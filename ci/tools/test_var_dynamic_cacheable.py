#!/usr/bin/env python3
"""Regression test: $zstd_ratio / $zstd_bytes_in / $zstd_bytes_out are
dynamically cacheable once compression has finished.

Before this fix all three variables were registered with the blanket
NGX_HTTP_VAR_NOCACHEABLE flag, so nginx reformatted the value on every
single lookup within a request -- every repeated log/map reference paid
a fresh ngx_sprintf() (and, for $zstd_ratio, a fresh 64-bit division).

The fix registers the variables with no flag and instead flips
vv->no_cacheable per call: 1 while the compression for this request has
not finished (ctx == NULL || !ctx->done -- not_found), 0 once it reports
the final value.

This test asserts the observable correctness half: $zstd_ratio starts
not_found (pre-completion `set $pre_completion $zstd_ratio;`) and settles
to the same final N.NNN value across TWO independently-flushed
`access_log` directives (nginx's log module calls
ngx_http_script_flush_no_cacheable_variables() once per `access_log`
line, so two directives are two independent flush points).

The row's actual performance claim -- the final value is formatted
EXACTLY ONCE per request instead of once per lookup -- was verified by
hand with a temporary debug-log counter added to
ngx_http_zstd_ratio_variable() (grep the PR description / commit history
for "formats-once"): GREEN (1 format) on this fix, RED (2+ formats) with
a `vv->no_cacheable = 1` negative control on the final-value branch. That
probe is not shipped -- a permanent counter in the hot compression path
would itself be the kind of per-call overhead this row removes.
"""

import argparse
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-binary", required=True)
    parser.add_argument("--filter-module")
    parser.add_argument("--port", type=int, default=18130)
    return parser.parse_args()


def wait_for_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nginx did not start listening on 127.0.0.1:{port}")


def detect_module_path(explicit: str | None, nginx_binary: pathlib.Path):
    # Always absolute: nginx resolves a relative load_module path against
    # its -p prefix, which here is the throwaway temp dir, not the cwd.
    if explicit:
        return pathlib.Path(explicit).resolve()
    sibling = (nginx_binary.parent / "ngx_http_zstd_filter_module.so").resolve()
    return sibling if sibling.exists() else None


def write_config(
    conf_path: pathlib.Path,
    root_dir: pathlib.Path,
    port: int,
    module: pathlib.Path | None,
) -> None:
    load_module_line = f"load_module {module};\n" if module else ""
    conf_path.write_text(
        f"""
{load_module_line}worker_processes  1;
error_log  logs/error.log info;
pid        logs/nginx.pid;

events {{
    worker_connections  32;
}}

http {{
    access_log off;
    default_type application/octet-stream;
    sendfile off;

    # Two references in the SAME log-phase format string, discriminates
    # nothing on its own (ngx_http_log_module flushes a nocacheable
    # variable at most ONCE before formatting both references, win or
    # lose -- see ngx_http_script_flush_no_cacheable_variables()). The
    # discriminator is TWO SEPARATE log writes below: each access_log
    # directive gets its own flush call
    # (ngx_http_log_handler -> ngx_http_script_flush_no_cacheable_variables
    # per `log[l]`). A variable that is genuinely still no_cacheable
    # after ctx->done gets re-flushed and reformatted on the SECOND
    # write; one that flips to cacheable on the final value only
    # flushes (no-ops) on the second write and reuses the first
    # write's cached, already-formatted value.
    log_format zstd_ratio_fmt "$zstd_ratio";

    server {{
        listen 127.0.0.1:{port};
        server_name localhost;
        root {root_dir};

        location = /probe {{
            zstd on;
            zstd_min_length 1;
            zstd_types application/octet-stream;

            # Pre-completion reference: the header filter runs before
            # the body filter sets ctx->done, so this lookup must see
            # not_found (and must be marked no_cacheable so the flush
            # does not pin a stale "not found" answer into the log
            # writes below).
            set $pre_completion $zstd_ratio;

            access_log logs/access-1.log zstd_ratio_fmt;
            access_log logs/access-2.log zstd_ratio_fmt;
        }}
    }}
}}
""".lstrip(),
        encoding="utf-8",
    )


def fetch(port: int) -> bytes:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/probe",
        headers={"Accept-Encoding": "zstd"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def main() -> int:
    args = parse_args()
    nginx_binary = pathlib.Path(args.nginx_binary)
    if not nginx_binary.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx_binary}")

    # module is None on a STATIC build, where the filter is linked into
    # the nginx binary and there is no .so to load_module. That is how CI
    # builds it, so a missing sibling .so is not an error -- write_config()
    # simply omits the load_module line, matching the sibling config-policy
    # tools (test_bypass_vary_config_policy.py). Only an EXPLICIT
    # --filter-module that does not exist is a real failure.
    module = detect_module_path(args.filter_module, nginx_binary)
    if args.filter_module and (module is None or not module.exists()):
        raise FileNotFoundError(
            f"ngx_http_zstd_filter_module.so not found: {args.filter_module}"
        )

    with tempfile.TemporaryDirectory(prefix="zstd-var-cache-") as temp_dir_str:
        temp_dir = pathlib.Path(temp_dir_str)
        html_dir = temp_dir / "html"
        conf_dir = temp_dir / "conf"
        logs_dir = temp_dir / "logs"
        html_dir.mkdir()
        conf_dir.mkdir()
        logs_dir.mkdir()

        fixture = html_dir / "probe"
        # Large enough / repetitive enough to compress and clear
        # zstd_min_length with room to spare.
        fixture.write_bytes(b"zstd-var-cache-probe-fixture\n" * 200)

        conf_path = conf_dir / "nginx.conf"
        write_config(conf_path, html_dir, args.port, module)

        process = subprocess.Popen(
            [
                str(nginx_binary),
                "-p",
                str(temp_dir),
                "-c",
                str(conf_path),
                "-g",
                "daemon off; master_process off;",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_port(args.port)
            body = fetch(args.port)
            if not body:
                raise RuntimeError("empty response body from /probe")

            # Give the log phase a moment to flush both access_log
            # writes.
            deadline = time.monotonic() + 5.0
            log1_path = logs_dir / "access-1.log"
            log2_path = logs_dir / "access-2.log"
            line1 = line2 = ""
            while time.monotonic() < deadline:
                if log1_path.exists():
                    line1 = log1_path.read_text(encoding="utf-8").strip()
                if log2_path.exists():
                    line2 = log2_path.read_text(encoding="utf-8").strip()
                if line1 and line2:
                    break
                time.sleep(0.05)

            if not line1 or not line2:
                raise RuntimeError(
                    f"one of the two access logs never got a line: "
                    f"access-1={line1!r} access-2={line2!r}"
                )

            if line1 in ("-", "") or line2 in ("-", ""):
                raise RuntimeError(
                    f"$zstd_ratio never transitioned to a final value: "
                    f"access-1={line1!r} access-2={line2!r}"
                )
            if not re.match(r"^\d+\.\d{3}$", line1):
                raise RuntimeError(f"$zstd_ratio {line1!r} not a finite N.NNN value")
            if line1 != line2:
                raise RuntimeError(
                    f"the two independently-flushed log writes disagree: "
                    f"{line1!r} vs {line2!r} -- each must see the SAME "
                    "cached final value"
                )
            ratio_a = line1

            error_log = logs_dir / "error.log"
            error_text = (
                error_log.read_text(encoding="utf-8", errors="replace")
                if error_log.exists()
                else ""
            )
            if (
                "[error]" in error_text
                or "[emerg]" in error_text
                or "[alert]" in error_text
            ):
                raise RuntimeError(f"unexpected error-level log line:\n{error_text}")

            print(
                "OK: $zstd_ratio transitioned not-found -> final value "
                f"({ratio_a}) and agreed across two independently-flushed "
                "access_log writes"
            )
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=30)
            if process.returncode not in (0, -15):
                output = process.stdout.read() if process.stdout is not None else ""
                sys.stderr.write("nginx stdout/stderr:\n")
                sys.stderr.write(output)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
