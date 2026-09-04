#!/usr/bin/env python3
"""Config-load policy: bound the aggregate ``zstd_buffers number size``.

``zstd_buffers`` delegates to nginx core's ``ngx_conf_set_bufs_slot()``,
which rejects only a parse error or either argument being zero -- it never
looks at the PRODUCT. ``ngx_conf_merge_bufs_value()`` (invoked from
``ngx_http_zstd_merge_loc_conf()``) then either keeps an explicit value,
inherits the parent's, or applies this module's own default
(``2 x ZSTD_CStreamOutSize()``); none of those three paths re-validates the
pair either. A typo ("zstd_buffers 100000 100000;" instead of
"100 100k;") or a value inherited from an outer block could therefore
request an overflowing OR merely enormous per-response output-chain pool
that nginx would happily commit per concurrent response.

A first version of this policy only warned above 8 MB and refused only an
actual ``size_t`` overflow -- which meant ``zstd_buffers 2147483647 1024m``
(~2.3 EB per response) loaded successfully with nothing but a log line,
because ``size_t`` overflow needs operands nginx's own integer parsing
barely admits. That is not a bound; it is a warning that the config commits
2.3 exabytes. This version adds a real hard cap in between.

The policy under test -- four tiers on the representable (non-overflowing)
product, ascending severity
--------------------------------------------------------------------------
  1. ``<= NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES`` (8 MB)          -- silent.
  2. ``>  ADVISORY_BYTES``, ``<= NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES``
     (256 MB)                                                  -- ``[warn]``,
     never fails; a config that loads today keeps loading.
  3. ``>  HARD_CAP_BYTES``, no ``zstd_buffers_unsafe on;``      -- ``[emerg]``,
     config REFUSED.
  4. ``>  HARD_CAP_BYTES``, WITH ``zstd_buffers_unsafe on;``    -- ``[warn]``
     (not silent -- the operator still sees what they acknowledged),
     config PASSES.

``num * size`` overflowing ``size_t`` is refused unconditionally at every
tier, including with the acknowledgement flag set -- there is no
representable size for which "the operator meant this".

The hard-cap tier is deliberately NOT advisory-shaped like the CCtx budget
or the 8 MB tier below it: unlike a libzstd memory ESTIMATE (which depends
on library internals the operator never directly sees), ``number`` and
``size`` are two integers the operator typed out literally. At the 256 MB
scale, refusing by default and requiring an explicit
``zstd_buffers_unsafe on;`` is the correct default reading of "this is
almost certainly a mistake, but if you really mean it, say so."

The check runs once at merge time (``ngx_http_zstd_merge_loc_conf()``),
which is the single point that sees the value however it got there --
explicit, inherited via ``ngx_conf_merge_bufs_value()``, or this module's
own default (all three land in the same ``conf->bufs`` the filter reads
from, and ``conf->bufs_unsafe`` merges by the same inheritance rule). The
parse-time slot (``ngx_http_zstd_set_bufs_slot()``) additionally catches
an overflowing EXPLICIT value at the earliest point, but never repeats the
advisory/cap tiers -- so a bare explicit large value is reported exactly
once, not twice.

Why this test and not ``ci/t/02-conf-warn.t``: Test::Nginx's error-log
greps can assert a substring appeared, but cannot assert a config-load run
PASSED with a specific warning present, is REFUSED with a specific message,
and PASSES again once acknowledged -- all as one matrix with an explicit
exit-code check per cell. A signal death (e.g. a bad cast crashing
"nginx -t") would still satisfy a plain string grep; this harness
explicitly separates that case out.

Arms
----
1. default zstd_buffers (module default, 2 x stream_out_size)     -> PASS,
   silent.
2. advisory cap - 1 byte (``zstd_buffers 1 8388607``)               -> PASS,
   silent.
3. advisory cap + 1 byte (``zstd_buffers 1 8388609``)               -> PASS,
   warn.
4. hard cap - 1 byte (``zstd_buffers 1 268435455``)                 -> PASS,
   warn (still tier 2 -- the boundary is inclusive of "advisory, not
   refused").
5. hard cap exact (``zstd_buffers 1 268435456``)                    -> PASS,
   warn (same reason as arm 4 -- the cap itself is not yet a breach).
6. hard cap + 1 byte, NO acknowledgement (``zstd_buffers 1
   268435457``)                                                     -> REFUSED,
   naming the cap and the acknowledgement spelling.
7. hard cap + 1 byte, WITH ``zstd_buffers_unsafe on;``              -> PASS,
   warn (not silent).
8. the reported gap's exact reproduction (``zstd_buffers 2147483647
   1024m`` -- ~2.3 EB per response), NO acknowledgement              -> REFUSED.
   This is the realistic-typo-shaped operand pair the first version of
   this policy let straight through with only a log line; it must now be
   the hard-refused case, not the overflow case.
9. same reproduction, WITH acknowledgement                          -> PASS,
   warn.
10. product overflow (``zstd_buffers <huge> <huge>``), acknowledgement
    flag ALSO set                                                    -> REFUSED,
    naming both operands. Proves the acknowledgement never reaches the
    overflow tier -- there is no spelling that accepts an unrepresentable
    product.
11. inherited from an outer (http) block: both ``zstd_buffers`` and
    ``zstd_buffers_unsafe on;`` written at http level, a bare ``location``
    underneath                                                        -> PASS,
    warn (proves the acknowledgement flag inherits the same way the
    aggregate bound does, not just the location that wrote it).
12. explicit large value in the 8-256 MB band fires exactly ONCE, not
    twice (parse-time slot must not duplicate the merge-time advisory).

Arms 1, 2, 4, 5 are the controls that keep this test from being vacuous: a
build that warns or refuses unconditionally on any zstd_buffers value
fails them. Arm 8 is the regression control for the exact gap this policy
exists to close.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

# NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES in src/ngx_http_zstd_filter_module.c.
# (NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES, 8 MB, is exercised by the boundary
# arms below but not compared against directly in this file.)
HARD_CAP_BYTES = 256 * 1024 * 1024

# Matched only on a line carrying "[warn]" (see WARN_RE usage below) so a
# [emerg] hard-cap refusal -- which restates the same "requests N x M
# bytes = ~T bytes" figure in its own message -- is never miscounted as a
# warning.
WARN_RE = re.compile(
    r'\[warn\].*"zstd_buffers" \((?P<ctx>[^)]+)\) requests (?P<num>\d+) x '
    r"(?P<size>\d+) bytes = ~(?P<total>\d+) bytes"
)
OVERFLOW_RE = re.compile(
    r'"zstd_buffers" \([^)]+\) requests (\d+) buffers of (\d+) bytes each; '
    r"that product overflows"
)
HARD_CAP_ACK_RE = re.compile(r"acknowledges it")
HARD_CAP_REFUSE_RE = re.compile(r"above the \d+ MB hard cap")


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18140)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def config_test(nginx, module, port, http_directives, srv_directives):
    """Run ``nginx -t``; return (returncode, combined output)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()

        load = f"load_module {module};\n" if module else ""
        (root / "conf" / "nginx.conf").write_text(
            f"{load}"
            "events {}\n"
            "http {\n"
            f"    {http_directives}\n"
            f"    server {{\n"
            f"        listen 127.0.0.1:{port};\n"
            "        zstd on;\n"
            f"        {srv_directives}\n"
            "    }\n"
            "}\n"
        )

        proc = subprocess.run(
            [str(nginx), "-p", str(root), "-c", "conf/nginx.conf", "-t"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr


def check_not_a_signal(name, rc, out):
    if rc < 0:
        return [f"{name}: nginx -t died on signal {-rc}; output: {out.strip()!r}"]
    if rc > 128:
        return [
            (
                f"{name}: nginx -t exited {rc} (128+{rc - 128}), a signal "
                f"death, not a diagnostic; output: {out.strip()!r}"
            )
        ]
    return []


def run_arm(nginx, module, port, name, http_directives, srv_directives, spec):
    """One matrix cell. ``spec`` carries the expectations. Returns
    (failures, printable summary)."""
    want_pass = spec["want_pass"]
    want_warning = spec.get("want_warning", False)
    want_overflow_error = spec.get("want_overflow_error", False)
    want_hard_cap_refuse = spec.get("want_hard_cap_refuse", False)
    want_hard_cap_ack = spec.get("want_hard_cap_ack", False)
    min_total = spec.get("min_total")
    max_warn_count = spec.get("max_warn_count", 1)

    rc, out = config_test(nginx, module, port, http_directives, srv_directives)
    failures = check_not_a_signal(name, rc, out)

    if want_pass and rc != 0:
        failures.append(
            f"{name}: expected nginx -t to PASS but it exited {rc}. The "
            f"bufs bound policy must never turn a working config into a "
            f"config-load failure at this tier; output: {out.strip()!r}"
        )
    if not want_pass and rc == 0:
        failures.append(
            f"{name}: expected nginx -t to be REFUSED but it exited 0; "
            f"output: {out.strip()!r}"
        )

    warns = WARN_RE.findall(out)

    if want_warning and not warns:
        failures.append(
            f"{name}: expected the [warn] naming the aggregate buffer "
            f"total, but it was not emitted; output: {out.strip()!r}"
        )
    if not want_warning and warns:
        failures.append(
            f"{name}: a warning was emitted but must NOT be at this tier. "
            f"Either a threshold is wrong or a boundary is off-by-one; "
            f"output: {out.strip()!r}"
        )
    if warns and len(warns) > max_warn_count:
        failures.append(
            f"{name}: warning fired {len(warns)} times (want at most "
            f"{max_warn_count}) -- the parse-time slot and the merge-time "
            f"check are double-reporting the same explicit value; output: "
            f"{out.strip()!r}"
        )

    if warns and "[warn]" not in out:
        failures.append(
            f"{name}: matched warning text but not at [warn] level; "
            f"output: {out.strip()!r}"
        )

    total = None
    if warns:
        total = int(warns[0][3])
        if min_total is not None and total < min_total:
            failures.append(
                f"{name}: reports {total} bytes, below the expected "
                f"{min_total}. Computed from the wrong operands."
            )
        if "per response" not in out.lower():
            failures.append(
                f"{name}: does not state the total is PER RESPONSE; "
                f"output: {out.strip()!r}"
            )
        if "zstd_max_cctx_memory" not in out:
            failures.append(
                f"{name}: does not cross-reference the CCtx memory "
                f'advisory ("zstd_max_cctx_memory"); output: '
                f"{out.strip()!r}"
            )

    if want_overflow_error:
        m = OVERFLOW_RE.search(out)
        if m is None:
            failures.append(
                f"{name}: expected the overflow diagnostic naming both "
                f"operands, but it was not found; output: {out.strip()!r}"
            )
        elif "[emerg]" not in out:
            failures.append(
                f"{name}: overflow diagnostic present but not at [emerg] "
                f"level; output: {out.strip()!r}"
            )

    if want_hard_cap_refuse:
        if HARD_CAP_REFUSE_RE.search(out) is None:
            failures.append(
                f"{name}: expected the hard-cap refusal naming the cap, "
                f"but it was not found; output: {out.strip()!r}"
            )
        elif "[emerg]" not in out:
            failures.append(
                f"{name}: hard-cap diagnostic present but not at [emerg] "
                f"level; output: {out.strip()!r}"
            )
        if "zstd_buffers_unsafe" not in out:
            failures.append(
                f"{name}: hard-cap refusal does not name the "
                f'acknowledgement spelling ("zstd_buffers_unsafe"); '
                f"output: {out.strip()!r}"
            )

    if want_hard_cap_ack and HARD_CAP_ACK_RE.search(out) is None:
        failures.append(
            f"{name}: expected the hard-cap ACKNOWLEDGED wording "
            f"(the acknowledgement must still be visible, not "
            f"silent), but it was not found; output: {out.strip()!r}"
        )

    if (
        total is not None
        and total > HARD_CAP_BYTES
        and not (want_hard_cap_refuse or want_hard_cap_ack)
    ):
        failures.append(
            f"{name}: total {total} bytes exceeds the {HARD_CAP_BYTES}-byte "
            f"hard cap but this arm did not mark either the refuse or the "
            f"acknowledge expectation -- the matrix spec is wrong for this "
            f"arm."
        )

    summary = (
        f"  {name:<52} exit {rc} (want {'0' if want_pass else 'non-zero'}), "
        f"warnings {len(warns)}"
        + (f", total {total} bytes" if total is not None else "")
    )
    return failures, summary


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary).resolve()
    if not nginx.exists():
        print(f"FAIL: nginx binary not found: {nginx}", file=sys.stderr)
        return 1

    module = detect_module(args.filter_module, nginx)
    if module is not None:
        module = module.resolve()
        if not module.exists():
            print(f"FAIL: filter module not found: {module}", file=sys.stderr)
            return 1

    huge = 9223372036854775807  # ngx_int_t / int64_t max on a 64-bit build.
    ack = "zstd_buffers_unsafe on;"

    matrix = [
        (
            "1 default bufs (silent tier)",
            "",
            "",
            {"want_pass": True, "want_warning": False},
        ),
        (
            "2 advisory cap-1 (8388607, silent)",
            "",
            "zstd_buffers 1 8388607;",
            {"want_pass": True, "want_warning": False},
        ),
        (
            "3 advisory cap+1 (8388609, warn)",
            "",
            "zstd_buffers 1 8388609;",
            {"want_pass": True, "want_warning": True, "min_total": 8388609},
        ),
        (
            "4 hard cap-1 (268435455, still warn)",
            "",
            "zstd_buffers 1 268435455;",
            {"want_pass": True, "want_warning": True, "min_total": 268435455},
        ),
        (
            "5 hard cap exact (268435456, still warn)",
            "",
            "zstd_buffers 1 268435456;",
            {"want_pass": True, "want_warning": True, "min_total": 268435456},
        ),
        (
            "6 hard cap+1, NO ack -> REFUSED",
            "",
            "zstd_buffers 1 268435457;",
            {
                "want_pass": False,
                "want_warning": False,
                "want_hard_cap_refuse": True,
            },
        ),
        (
            "7 hard cap+1, WITH ack -> PASS+warn",
            "",
            f"zstd_buffers 1 268435457;\n        {ack}",
            {
                "want_pass": True,
                "want_warning": True,
                "want_hard_cap_ack": True,
                "min_total": 268435457,
            },
        ),
        (
            "8 reported gap repro, NO ack -> REFUSED",
            "",
            "zstd_buffers 2147483647 1024m;",
            {
                "want_pass": False,
                "want_warning": False,
                "want_hard_cap_refuse": True,
            },
        ),
        (
            "9 reported gap repro, WITH ack -> PASS+warn",
            "",
            f"zstd_buffers 2147483647 1024m;\n        {ack}",
            {
                "want_pass": True,
                "want_warning": True,
                "want_hard_cap_ack": True,
                "min_total": 2305843008139952128,
            },
        ),
        (
            "10 product overflow, ack ALSO set -> still REFUSED",
            "",
            f"zstd_buffers {huge} {huge};\n        {ack}",
            {
                "want_pass": False,
                "want_warning": False,
                "want_overflow_error": True,
            },
        ),
        (
            "11 inherited hard-cap breach + ack from http block",
            f"{ack}\n    zstd_buffers 1 268435457;",
            "",
            {
                "want_pass": True,
                "want_warning": True,
                "want_hard_cap_ack": True,
                "min_total": 268435457,
            },
        ),
        (
            "12 explicit 16 MB value warns once, not twice",
            "",
            "zstd_buffers 1 16777217;",
            {
                "want_pass": True,
                "want_warning": True,
                "min_total": 16777217,
                "max_warn_count": 1,
            },
        ),
    ]

    failures = []
    print("zstd_buffers aggregate bound policy matrix:")
    for i, (name, http_directives, srv_directives, spec) in enumerate(matrix):
        f, summary = run_arm(
            nginx, module, args.port + i, name, http_directives, srv_directives, spec
        )
        failures += f
        print(summary)

    if failures:
        print("\nFAIL: zstd_buffers bound policy", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"\nOK: zstd_buffers bound policy ({len(matrix)}/{len(matrix)} arms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
