#!/usr/bin/env python3
"""Config-load policy: the implicit per-request CCtx memory advisory.

``zstd_max_cctx_memory`` merges to ``0`` when the operator never sets it,
and the config-load estimator used to be skipped entirely in that case.
A later ``zstd_comp_level 22`` or ``zstd_long on`` could therefore commit
hundreds of MB of compressor working set per concurrent response --
multiplied by the ``NGX_HTTP_ZSTD_CCTX_SLOTS`` (4) contexts each worker
retains, and again by ``worker_processes`` -- even though the module
already knew the number at config load.

The policy under test
---------------------
Compression enabled and **no** explicit ``zstd_max_cctx_memory``
anywhere in the inheritance chain:

  * run libzstd's estimator on the merged profile;
  * if the estimate exceeds ``NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES``
    (32 MB), emit an ``[warn]`` naming the estimate and the retained
    worker bound;
  * **warn, never fail** -- turning ``nginx -t`` from pass to fail on a
    configuration that works today would break deployments on upgrade.

An explicit ``zstd_max_cctx_memory 0`` is the operator's
acknowledgement and silences the advisory. (``ngx_conf_set_size_slot()``
parses sizes only, so ``0`` -- not the keyword ``off`` -- is the
spelling; the directive is capped at ``INT_MAX``, hence ``1024m`` rather
than ``1g`` in arm 5.) An explicit non-zero value
keeps the pre-existing hard-failure semantics untouched.

Why this test and not ``ci/t/00-filter.t``: Test::Nginx's ``--- must_die``
and error-log greps cannot express "must PASS *and* must have emitted
exactly this warning", which is the whole contract here -- a policy that
failed the config would satisfy any must_die-shaped assertion while being
precisely the breaking change this design rejected.

Arms
----
1. default profile (``zstd on`` only)            -> PASS, NO advisory.
2. ``zstd_comp_level 22``                        -> PASS, advisory.
3. ``zstd_long on``                              -> PASS, advisory.
4. ``zstd_window_log 27``                        -> PASS, advisory.
5. ``zstd_comp_level 22`` + explicit 1024m budget -> PASS, NO advisory
   (the explicit-budget path owns this config; the advisory must not
   double-report).
6. ``zstd_comp_level 22`` + ``zstd_max_cctx_memory 0``
                                                 -> PASS, NO advisory
   (the acknowledgement is honoured).
7. ``zstd_comp_level 22`` + explicit 64m budget  -> REFUSED (the hard
   check is unchanged; the advisory did not soften it).
8. dictionary + default level                    -> PASS, NO advisory
   (a dictionary does not move the working set into advisory range).

Arms 1, 5, 6 and 8 are the controls that stop this test going vacuous:
each asserts the advisory is **absent**, so a build that warned
unconditionally -- the obvious wrong implementation -- fails them.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

# NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES in
# src/ngx_http_zstd_filter_module.c. Kept in sync by arms 1 and 2:
# level 3 estimates ~3.5 MB (below) and level 22 ~769 MB (above), so a
# threshold moved outside the (28.7 MB, 52.7 MB) gap between levels 11
# and 12 does not silently pass this test.
ADVISORY_BYTES = 32 * 1024 * 1024

# NGX_HTTP_ZSTD_CCTX_SLOTS.
CCTX_SLOTS = 4

# The advisory is identified by this phrase; matching on it rather than
# on "[warn]" keeps the unrelated zstd_bypass_vary warning from
# satisfying an arm.
ADVISORY_RE = re.compile(r"need ~(\d+) bytes of per-request compressor memory")


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18130)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def config_test(nginx, module, port, directives, want_dict=False):
    """Run ``nginx -t``; return (returncode, combined output)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()

        extra = ""
        if want_dict:
            # A small raw dictionary is enough: the point of the arm is
            # that loading one does not push the estimate over the
            # advisory threshold, not the dictionary's content.
            dic = root / "dict.bin"
            dic.write_bytes(b"the quick brown fox jumps over the lazy dog" * 64)
            # zstd_dict_file additionally requires the operator to
            # acknowledge the non-negotiated Content-Encoding; that gate
            # is unrelated to this test but must be satisfied to reach
            # the memory policy at all.
            extra = f"zstd_dict_file {dic};\n    zstd_dict_file_unsafe on;\n    "

        load = f"load_module {module};\n" if module else ""
        (root / "conf" / "nginx.conf").write_text(
            f"{load}"
            "events {}\n"
            "http {\n"
            f"    {extra}"
            f"    server {{\n"
            f"        listen 127.0.0.1:{port};\n"
            "        zstd on;\n"
            f"        {directives}\n"
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


def run_arm(
    nginx,
    module,
    port,
    name,
    directives,
    want_pass,
    want_advisory,
    want_dict=False,
    min_estimate=None,
):
    """One matrix cell. Returns (failures, printable summary)."""
    rc, out = config_test(nginx, module, port, directives, want_dict=want_dict)
    failures = check_not_a_signal(name, rc, out)

    if want_pass and rc != 0:
        failures.append(
            f"{name}: expected nginx -t to PASS but it exited {rc}. The "
            f"advisory policy must never turn a working config into a "
            f"config-load failure; output: {out.strip()!r}"
        )
    if not want_pass and rc == 0:
        failures.append(
            f"{name}: expected nginx -t to be REFUSED but it exited 0; "
            f"output: {out.strip()!r}"
        )

    m = ADVISORY_RE.search(out)
    saw_warn = m is not None and "[warn]" in out

    if want_advisory and not saw_warn:
        failures.append(
            f"{name}: expected the [warn] advisory naming the estimate, "
            f"but it was not emitted. The operator gets no signal that "
            f"this profile commits a large per-request working set; "
            f"output: {out.strip()!r}"
        )
    if not want_advisory and saw_warn:
        failures.append(
            f"{name}: the advisory was emitted but must NOT be. Either "
            f"the threshold is wrong or an explicit budget / "
            f"acknowledgement is not being honoured; output: "
            f"{out.strip()!r}"
        )

    est = None
    if saw_warn:
        est = int(m.group(1))
        if min_estimate is not None and est < min_estimate:
            failures.append(
                f"{name}: advisory reports {est} bytes, below the expected "
                f"{min_estimate}. The estimate was computed against the "
                f"wrong parameters."
            )
        if est <= ADVISORY_BYTES:
            failures.append(
                f"{name}: advisory fired at {est} bytes, which is <= the "
                f"{ADVISORY_BYTES}-byte threshold. The condition is not "
                f"the documented one."
            )
        # The message must give the operator the retained worker bound,
        # not just the per-context figure -- the per-worker number is
        # what actually shows up in RSS.
        if str(est * CCTX_SLOTS) not in out:
            failures.append(
                f"{name}: advisory does not state the retained worker "
                f"bound ({est} x {CCTX_SLOTS} = {est * CCTX_SLOTS} "
                f"bytes); output: {out.strip()!r}"
            )
        if "zstd_max_cctx_memory 0" not in out:
            failures.append(
                f"{name}: advisory does not tell the operator how to "
                f'acknowledge it ("zstd_max_cctx_memory 0"); output: '
                f"{out.strip()!r}"
            )

    summary = (
        f"  {name:<38} exit {rc} (want {'0' if want_pass else 'non-zero'}), "
        f"advisory {'yes' if saw_warn else 'no':<3} "
        f"(want {'yes' if want_advisory else 'no'})"
        + (f", estimate {est} bytes" if est is not None else "")
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

    # (name, directives, want_pass, want_advisory, want_dict, min_estimate)
    #
    # min_estimate pins the magnitude where the profile implies one, so a
    # correctly-firing advisory computed against the wrong parameters is
    # still caught. LDM and window_log 27 both imply a 128 MB window.
    matrix = [
        ("1 default profile", "", True, False, False, None),
        (
            "2 zstd_comp_level 22",
            "zstd_comp_level 22;",
            True,
            True,
            False,
            512 * 1024 * 1024,
        ),
        ("3 zstd_long on", "zstd_long on;", True, True, False, 128 * 1024 * 1024),
        (
            "4 zstd_window_log 27",
            "zstd_window_log 27;",
            True,
            True,
            False,
            128 * 1024 * 1024,
        ),
        (
            "5 level 22 + budget 1024m",
            "zstd_comp_level 22; zstd_max_cctx_memory 1024m;",
            True,
            False,
            False,
            None,
        ),
        (
            "6 level 22 + budget 0 (ack)",
            "zstd_comp_level 22; zstd_max_cctx_memory 0;",
            True,
            False,
            False,
            None,
        ),
        (
            "7 level 22 + budget 64m",
            "zstd_comp_level 22; zstd_max_cctx_memory 64m;",
            False,
            False,
            False,
            None,
        ),
        ("8 dictionary, default level", "", True, False, True, None),
    ]

    failures = []
    print("zstd CCtx memory advisory policy matrix:")
    for i, (name, directives, wp, wa, wd, mn) in enumerate(matrix):
        f, summary = run_arm(
            nginx,
            module,
            args.port + i,
            name,
            directives,
            wp,
            wa,
            want_dict=wd,
            min_estimate=mn,
        )
        failures += f
        print(summary)

    if failures:
        print("\nFAIL: CCtx memory advisory policy", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"\nOK: CCtx memory advisory policy ({len(matrix)}/{len(matrix)} arms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
