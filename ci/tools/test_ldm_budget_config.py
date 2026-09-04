#!/usr/bin/env python3
"""Config-load regression: ``zstd_long`` + ``zstd_max_cctx_memory``.

``ZSTD_estimateCStreamSize_usingCCtxParams()`` divides by
``params.ldmParams.hashRateLog``. libzstd derives the LDM sub-parameters
lazily during compression setup, so a ``ZSTD_CCtx_params`` that has only
had ``ZSTD_c_enableLongDistanceMatching`` set still carries
``hashRateLog == 0``. The config-load budget check called the estimator
on exactly such a params object, so ``nginx -t`` died with **SIGFPE**
(exit 136) for any configuration combining ``zstd_long on`` with
``zstd_max_cctx_memory``. Setting ``zstd_window_log`` did not avoid it --
the divisor is unrelated to the window.

Why this test is not folded into ``ci/t/00-filter.t``: that harness's
``--- must_die`` cannot tell a crash from a diagnostic. A SIGFPE and a
clean ``[emerg]`` both "die", so a ``must_die`` block would have passed
against the crashing build and proved nothing. This test asserts on the
**exit status and its sign** -- a negative ``returncode`` (or 128+N) is a
signal and always a failure, whatever the message says.

Arms
----
1. ``zstd_long on`` + ``zstd_max_cctx_memory 256m``  -> must PASS.
   The regression arm. Pre-fix: SIGFPE.
2. ``zstd_long on`` + ``zstd_max_cctx_memory 64m``   -> must be REFUSED
   with a diagnostic naming the budget. This is the arm that keeps the
   fix honest: it proves the estimate is still *enforced* under LDM
   rather than skipped, so the operator does not silently lose the bound
   they asked for. It also pins the magnitude -- the seeded estimate must
   land in the >=128 MB range that LDM's 128 MB default window implies,
   which is what distinguishes a correctly seeded estimate from one
   computed against the level's much smaller default window.
3. ``zstd_long on`` + ``zstd_window_log 20`` + ``64m`` -> must PASS.
   A capped window brings the same profile back under the same budget,
   proving arm 2's refusal is a real measurement and not a blanket
   "LDM always fails".
4. ``zstd_max_cctx_memory 256m`` alone (no LDM)      -> must PASS.
5. ``zstd_long on`` alone (no budget)                -> must PASS.

Arms 4 and 5 are the controls: both passed on the crashing build too, so
they are what stops this test from going vacuous if the estimator block
is ever short-circuited or compiled out entirely.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

# LDM raises libzstd's default windowLog to 27 (128 MB). A correctly
# seeded estimate for level 3 + LDM with no zstd_window_log is therefore
# ~144 MB (measured 144328225 against libzstd 1.5.7; a real streaming
# ZSTD_CCtx over 256 MB of input reported ZSTD_sizeof_CCtx() 144262689).
# An estimate computed against the level's default window instead would
# be ~3.6 MB, two orders of magnitude low, and would wrongly fit in the
# 64 MB budget of arm 2.
MIN_EXPECTED_LDM_ESTIMATE = 128 * 1024 * 1024


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--port", type=int, default=18099)
    return p.parse_args()


def detect_module(explicit, nginx: pathlib.Path):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / "ngx_http_zstd_filter_module.so"
    return sib if sib.exists() else None


def config_test(nginx: pathlib.Path, module, port: int, directives: str):
    """Run ``nginx -t`` on a minimal config; return (returncode, output)."""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "conf").mkdir()
        (root / "logs").mkdir()

        load = f"load_module {module};\n" if module else ""
        (root / "conf" / "nginx.conf").write_text(
            f"{load}"
            "events {}\n"
            "http {\n"
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


def check_not_a_signal(name: str, rc: int, out: str) -> list:
    """The core assertion: nginx -t must never terminate on a signal."""
    if rc < 0:
        return [
            (
                f"{name}: nginx -t died on signal {-rc} "
                f"(SIGFPE is 8); output: {out.strip()!r}"
            )
        ]
    if rc > 128:
        return [
            (
                f"{name}: nginx -t exited {rc} (128+{rc - 128}), which is "
                f"a signal death, not a diagnostic; output: "
                f"{out.strip()!r}"
            )
        ]
    return []


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

    failures = []

    # --- Arm 1: the regression. Pre-fix this was SIGFPE / exit 136. -----
    rc, out = config_test(
        nginx, module, args.port, "zstd_long on; zstd_max_cctx_memory 256m;"
    )
    failures += check_not_a_signal("arm1 ldm+256m", rc, out)
    if rc != 0:
        failures.append(
            f"arm1 ldm+256m: expected nginx -t to succeed (level 3 + LDM "
            f"needs ~144 MB, which fits in 256m) but it exited {rc}; "
            f"output: {out.strip()!r}"
        )
    print(f"  arm1 zstd_long + 256m           -> exit {rc} (want 0)")

    # --- Arm 2: the budget is still ENFORCED under LDM. ----------------
    rc, out = config_test(
        nginx, module, args.port, "zstd_long on; zstd_max_cctx_memory 64m;"
    )
    failures += check_not_a_signal("arm2 ldm+64m", rc, out)
    if rc == 0:
        failures.append(
            "arm2 ldm+64m: nginx -t SUCCEEDED, but level 3 + LDM needs "
            "~144 MB, which exceeds the 64m budget. The operator asked "
            "for a bound and silently did not get one -- the estimator "
            "is either skipping LDM profiles or sizing against the "
            "wrong window."
        )
    else:
        if "zstd_max_cctx_memory" not in out:
            failures.append(
                f"arm2 ldm+64m: refused, but the diagnostic does not name "
                f'"zstd_max_cctx_memory", so the operator cannot tell why: '
                f"{out.strip()!r}"
            )
        m = re.search(r"need ~(\d+) bytes", out)
        if not m:
            failures.append(
                f"arm2 ldm+64m: diagnostic does not report the estimated "
                f"byte count: {out.strip()!r}"
            )
        elif int(m.group(1)) < MIN_EXPECTED_LDM_ESTIMATE:
            failures.append(
                f"arm2 ldm+64m: estimate {m.group(1)} bytes is below "
                f"{MIN_EXPECTED_LDM_ESTIMATE}. LDM raises the default "
                f"windowLog to 27 (128 MB), so a correctly seeded estimate "
                f"cannot be this small -- the LDM sub-parameters were not "
                f"seeded and the estimate was computed against the level's "
                f"default window."
            )
        else:
            print(f"  arm2 estimate reported          -> {m.group(1)} bytes")
    print(f"  arm2 zstd_long + 64m            -> exit {rc} (want non-zero)")

    # --- Arm 3: a capped window fits the same budget. ------------------
    rc, out = config_test(
        nginx,
        module,
        args.port,
        "zstd_long on; zstd_window_log 20; zstd_max_cctx_memory 64m;",
    )
    failures += check_not_a_signal("arm3 ldm+wl20+64m", rc, out)
    if rc != 0:
        failures.append(
            f"arm3 ldm+wl20+64m: expected success (a 2^20 window under LDM "
            f"needs ~2.7 MB, well inside 64m) but nginx -t exited {rc}. "
            f"Arm 2's refusal is therefore a blanket rejection of LDM, not "
            f"a measurement; output: {out.strip()!r}"
        )
    print(f"  arm3 zstd_long + wl20 + 64m     -> exit {rc} (want 0)")

    # --- Arm 4 (control): budget alone, no LDM. -----------------------
    rc, out = config_test(nginx, module, args.port, "zstd_max_cctx_memory 256m;")
    failures += check_not_a_signal("arm4 256m only", rc, out)
    if rc != 0:
        failures.append(
            f"arm4 256m only (control): exited {rc}; output: {out.strip()!r}"
        )
    print(f"  arm4 256m alone (control)       -> exit {rc} (want 0)")

    # --- Arm 5 (control): LDM alone, no budget. -----------------------
    rc, out = config_test(nginx, module, args.port, "zstd_long on;")
    failures += check_not_a_signal("arm5 ldm only", rc, out)
    if rc != 0:
        failures.append(
            f"arm5 ldm only (control): exited {rc}; output: {out.strip()!r}"
        )
    print(f"  arm5 zstd_long alone (control)  -> exit {rc} (want 0)")

    if failures:
        print("\nFAIL: zstd_long + zstd_max_cctx_memory config test", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("\nOK: zstd_long + zstd_max_cctx_memory config validation (5/5 arms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
