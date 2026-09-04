#!/usr/bin/env python3
import argparse
import concurrent.futures
import http.server
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import ClassVar

FIXTURE_SENTINEL = "END-OF-ZSTD-TRUNCATION-FIXTURE-9f4c3d1b"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an end-to-end zstd encoding smoke test against nginx."
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the smoke test.",
    )
    parser.add_argument(
        "--filter-module",
        help=(
            "Optional path to ngx_http_zstd_filter_module.so. "
            "If omitted, the helper auto-detects a sibling module next to the nginx binary."
        ),
    )
    parser.add_argument(
        "--static-module",
        help=(
            "Optional path to ngx_http_zstd_static_module.so. "
            "If omitted, the helper auto-detects a sibling module next to the nginx binary."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18080,
        help="Local TCP port for the temporary nginx instance.",
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        help="Local TCP port for the temporary Cache-Control upstream.",
    )
    parser.add_argument(
        "--zstd-bin",
        default=shutil.which("zstd") or "zstd",
        help="Path to the zstd CLI used for decompression.",
    )
    parser.add_argument(
        "--gzip-vary",
        choices=("on", "off"),
        default="off",
        help="Whether to enable gzip_vary in the temporary nginx config.",
    )
    parser.add_argument(
        "--expect-vary",
        action="store_true",
        help=(
            "Require the response to include Vary: Accept-Encoding. "
            "Useful when gzip_vary is enabled."
        ),
    )
    parser.add_argument(
        "--fixture-lines",
        type=int,
        default=8192,
        help="Number of repeated lines to generate in the JavaScript fixture.",
    )
    parser.add_argument(
        "--request-count",
        type=int,
        default=1,
        help="How many sequential requests to verify against the same nginx worker.",
    )
    parser.add_argument(
        "--concurrent-requests",
        type=int,
        default=1,
        help="How many concurrent requests to verify against the same nginx worker.",
    )
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


def build_fixture(path: pathlib.Path, lines: int) -> bytes:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("// zstd truncation regression fixture\n")
        handle.write("const payload = [\n")
        for index in range(lines):
            handle.write(
                f'  "line-{index:05d}: zstd-regression-payload-abcdefghijklmnopqrstuvwxyz0123456789",\n'
            )
        handle.write("];\n")
        handle.write(
            "globalThis.__zstd_fixture_checksum = `${payload.length}:${payload[0]}:${payload[payload.length - 1]}`;\n"
        )
        handle.write(f'globalThis.__zstd_fixture_end = "{FIXTURE_SENTINEL}";\n')
        handle.write("console.log(globalThis.__zstd_fixture_checksum);\n")
        handle.write("console.log(globalThis.__zstd_fixture_end);\n")
    data = path.read_bytes()
    if len(data) <= 131072:
        raise RuntimeError(
            f"fixture too small to catch truncation bugs: {len(data)} bytes"
        )
    return data


def detect_module_path(
    explicit_path: str | None,
    nginx_binary: pathlib.Path,
    module_name: str,
) -> pathlib.Path | None:
    if explicit_path:
        return pathlib.Path(explicit_path)

    sibling = nginx_binary.parent / module_name
    if sibling.exists():
        return sibling

    return None


def write_config(
    conf_path: pathlib.Path,
    root_dir: pathlib.Path,
    port: int,
    backend_port: int,
    gzip_vary: str,
    modules: list[pathlib.Path],
) -> None:
    load_modules = "".join(f"load_module {module};\n" for module in modules)
    conf_path.write_text(
        f"""
{load_modules}worker_processes  1;
error_log  logs/error.log info;
pid        logs/nginx.pid;

events {{
    worker_connections  128;
}}

http {{
    access_log logs/access.log;
    # $zstd_ratio is a log-phase variable; capture it to its own file so
    # the harness can assert it is a finite N.NNN value (regression for
    # 064895c, the compression-ratio integer-overflow fix).
    log_format zstd_ratio_fmt "$zstd_ratio";
    default_type application/octet-stream;
    sendfile off;
    gzip_vary {gzip_vary};
    keepalive_timeout 5;
    server {{
        listen 127.0.0.1:{port};
        server_name localhost;
        root {root_dir};
        location = /test.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            access_log logs/zstd_ratio.log zstd_ratio_fmt;
        }}
        location = /cache-control-public.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-public.js;
        }}
        location = /cache-control-quoted-no-transform.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-quoted-no-transform.js;
        }}
        location = /cache-control-quoted-comma.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-quoted-comma.js;
        }}
        location = /cache-control-no-transform-comma.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-no-transform-comma.js;
        }}
        location = /cache-control-no-transform-ows.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-no-transform-ows.js;
        }}
        location = /cache-control-no-transform-arg.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-no-transform-arg.js;
        }}
        location = /cache-control-no-transform-repeat.js {{
            types {{
                application/javascript js;
            }}
            default_type application/javascript;
            zstd on;
            zstd_min_length 1;
            zstd_types application/javascript;
            proxy_pass http://127.0.0.1:{backend_port}/cache-control-no-transform-repeat.js;
        }}
    }}
}}
""".lstrip(),
        encoding="utf-8",
    )


class CacheControlHandler(http.server.BaseHTTPRequestHandler):
    payload = b""
    cache_control: ClassVar[dict[str, list[str]]] = {
        "/cache-control-public.js": ["public"],
        "/cache-control-quoted-no-transform.js": ['public, extension="no-transform"'],
        "/cache-control-quoted-comma.js": ['public, extension="a,no-transform,b"'],
        "/cache-control-no-transform-comma.js": ["public, no-transform"],
        "/cache-control-no-transform-ows.js": [" public ; max-age=60 , No-Transform "],
        "/cache-control-no-transform-repeat.js": ["public", "no-transform"],
        "/cache-control-no-transform-arg.js": ["public, no-transform=1"],
    }

    def do_GET(self) -> None:
        values = self.cache_control.get(self.path)
        if values is None:
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(self.payload)))
        for value in values:
            self.send_header("Cache-Control", value)
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def fetch_response(port: int) -> tuple[bytes, str, str]:
    return fetch_path(port, "/test.js")


def fetch_path(port: int, path: str) -> tuple[bytes, str, str]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-ci-smoke-test/1.0"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        compressed = response.read()
        content_encoding = response.headers.get("Content-Encoding", "")
        vary = response.headers.get("Vary", "")
    return compressed, content_encoding, vary


def validate_cache_control_no_transform(port: int, expected: bytes) -> None:
    public_body, public_encoding, _ = fetch_path(port, "/cache-control-public.js")
    if public_encoding.lower() != "zstd":
        raise RuntimeError(
            "Cache-Control public negative control did not compress: "
            f"Content-Encoding={public_encoding!r}"
        )
    quoted_body, quoted_encoding, _ = fetch_path(
        port, "/cache-control-quoted-no-transform.js"
    )
    if quoted_encoding.lower() != "zstd":
        raise RuntimeError(
            "Cache-Control quoted no-transform parameter was treated as a "
            f"directive: Content-Encoding={quoted_encoding!r}"
        )
    if quoted_body == expected:
        raise RuntimeError(
            "Cache-Control quoted no-transform negative control was not transformed"
        )

    quoted_comma_body, quoted_comma_encoding, _ = fetch_path(
        port, "/cache-control-quoted-comma.js"
    )
    if quoted_comma_encoding.lower() != "zstd":
        raise RuntimeError(
            "Cache-Control quoted comma extension was split into a directive: "
            f"Content-Encoding={quoted_comma_encoding!r}"
        )
    if quoted_comma_body == expected:
        raise RuntimeError(
            "Cache-Control quoted comma negative control was not transformed"
        )

    for path in (
        "/cache-control-no-transform-comma.js",
        "/cache-control-no-transform-ows.js",
        "/cache-control-no-transform-repeat.js",
        # Malformed but intent-clear: the directive defines no argument
        # (RFC 9111 5.2.2.6), so an origin writing no-transform=1 gets
        # honored, not transformed -- the walker compares the directive
        # name, cut at '='.
        "/cache-control-no-transform-arg.js",
    ):
        body, encoding, _ = fetch_path(port, path)
        if encoding:
            raise RuntimeError(
                f"{path}: expected no Content-Encoding for no-transform, got {encoding!r}"
            )
        if body != expected:
            raise RuntimeError(f"{path}: identity response body changed")

    if public_body == expected:
        raise RuntimeError("Cache-Control public negative control was not transformed")


def decompress_payload(zstd_bin: str, compressed: bytes) -> bytes:
    result = subprocess.run(
        [zstd_bin, "-d", "-q", "-c"],
        input=compressed,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"zstd decompression failed: {stderr.strip()}")
    return result.stdout


def read_if_exists(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def validate_response(
    port: int,
    zstd_bin: str,
    expected: bytes,
    expect_vary: bool,
    request_label: str,
) -> None:
    compressed, encoding, vary = fetch_response(port)
    if encoding.lower() != "zstd":
        raise RuntimeError(f"expected Content-Encoding=zstd, got {encoding!r}")
    if expect_vary:
        vary_values = {
            value.strip().lower() for value in vary.split(",") if value.strip()
        }
        if "accept-encoding" not in vary_values:
            raise RuntimeError(
                f"expected Vary to include Accept-Encoding, got {vary!r}"
            )
    decoded = decompress_payload(zstd_bin, compressed)
    if decoded != expected:
        raise RuntimeError(
            "decompressed response does not match source fixture; "
            f"{request_label}, expected {len(expected)} bytes, got {len(decoded)} bytes"
        )
    if FIXTURE_SENTINEL.encode("utf-8") not in decoded:
        raise RuntimeError("fixture sentinel missing from decoded response")


RATIO_RE = re.compile(r"^\d+\.\d{3}$")


def validate_ratio_log(
    log_path: pathlib.Path, request_count: int, timeout: float = 10.0
) -> None:
    """Assert every logged $zstd_ratio is a finite N.NNN value.

    Regression for 064895c ("integer overflow in compression ratio
    calculation"): before the fix bytes_in*1000 could overflow and yield a
    garbage or zero ratio. The CI JavaScript fixture is highly compressible,
    so a correct ratio must parse AND be > 1.0 (output smaller than input).

    $zstd_ratio is written in nginx's *log phase*, which runs after the
    response body has already been flushed to the client. validate_response
    therefore returns before nginx has necessarily written the access_log
    line — a race that widens under the (much slower) ASAN/UBSAN binary and
    used to fail intermittently with "the ratio code path did not run". Poll
    for at least request_count non-empty lines before asserting, so a slow
    log-phase write is waited out rather than mistaken for a missing one.
    """
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    while True:
        content = read_if_exists(log_path)
        lines = [line for line in content.splitlines() if line.strip()]
        if len(lines) >= request_count or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    if not lines:
        raise RuntimeError(
            f"$zstd_ratio log {log_path} is empty — the variable was not "
            "populated (the ratio code path did not run)"
        )
    for line in lines:
        value = line.strip()
        if not RATIO_RE.match(value):
            raise RuntimeError(
                f"$zstd_ratio {value!r} is not a finite N.NNN value "
                "(integer-overflow / garbage regression, cf. 064895c)"
            )
        if float(value) <= 1.0:
            raise RuntimeError(
                f"$zstd_ratio {value!r} <= 1.0 for a highly compressible "
                "fixture — ratio computed wrong"
            )


def main() -> int:
    args = parse_args()
    nginx_binary = pathlib.Path(args.nginx_binary)
    if not nginx_binary.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx_binary}")
    if shutil.which(args.zstd_bin) is None and not pathlib.Path(args.zstd_bin).exists():
        raise FileNotFoundError(f"zstd CLI not found: {args.zstd_bin}")
    if args.request_count < 1:
        raise ValueError(f"request-count must be >= 1, got {args.request_count}")
    if args.concurrent_requests < 1:
        raise ValueError(
            f"concurrent-requests must be >= 1, got {args.concurrent_requests}"
        )
    backend_port = args.backend_port or args.port + 1

    filter_module = detect_module_path(
        args.filter_module,
        nginx_binary,
        "ngx_http_zstd_filter_module.so",
    )
    static_module = detect_module_path(
        args.static_module,
        nginx_binary,
        "ngx_http_zstd_static_module.so",
    )
    modules = [
        module for module in (filter_module, static_module) if module is not None
    ]

    for module in modules:
        if not module.exists():
            raise FileNotFoundError(f"zstd module not found: {module}")

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-ci-smoke-") as temp_dir_str:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(temp_dir_str, 0o755)
        temp_dir = pathlib.Path(temp_dir_str)
        html_dir = temp_dir / "html"
        conf_dir = temp_dir / "conf"
        logs_dir = temp_dir / "logs"
        html_dir.mkdir()
        conf_dir.mkdir()
        logs_dir.mkdir()

        fixture_path = html_dir / "test.js"
        expected = build_fixture(fixture_path, args.fixture_lines)
        conf_path = conf_dir / "nginx.conf"
        write_config(
            conf_path, html_dir, args.port, backend_port, args.gzip_vary, modules
        )

        CacheControlHandler.payload = expected
        backend = http.server.ThreadingHTTPServer(
            ("127.0.0.1", backend_port), CacheControlHandler
        )
        backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        backend_thread.start()

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
            for request_index in range(args.request_count):
                validate_response(
                    args.port,
                    args.zstd_bin,
                    expected,
                    args.expect_vary,
                    f"request {request_index + 1}/{args.request_count}",
                )

            if args.concurrent_requests > 1:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=args.concurrent_requests
                ) as executor:
                    futures = [
                        executor.submit(
                            validate_response,
                            args.port,
                            args.zstd_bin,
                            expected,
                            args.expect_vary,
                            f"concurrent request {request_index + 1}/{args.concurrent_requests}",
                        )
                        for request_index in range(args.concurrent_requests)
                    ]
                    for future in futures:
                        future.result()

            validate_cache_control_no_transform(args.port, expected)

            validate_ratio_log(
                pathlib.Path(temp_dir) / "logs" / "zstd_ratio.log",
                args.request_count,
            )

            print(
                "OK: verified zstd response integrity"
                f" for {len(expected)}-byte JavaScript fixture"
                + (
                    f" across {args.request_count} sequential requests"
                    if args.request_count > 1
                    else ""
                )
                + (
                    f" and {args.concurrent_requests} concurrent requests"
                    if args.concurrent_requests > 1
                    else ""
                )
                + (" with Vary: Accept-Encoding" if args.expect_vary else "")
            )
            return 0
        finally:
            backend.shutdown()
            backend.server_close()
            process.terminate()
            try:
                # 30s, not 5: gcov-instrumented nginx flushing .gcda
                # at exit on a loaded runner can outlive a tight reap
                # budget; teardown runs after the verdict, so patience
                # costs nothing when healthy.
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=30)

            output = process.stdout.read() if process.stdout is not None else ""
            error_log = read_if_exists(logs_dir / "error.log")
            if process.returncode not in (0, -15):
                sys.stderr.write("nginx stdout/stderr:\n")
                sys.stderr.write(output)
                sys.stderr.write("\nnginx error log:\n")
                sys.stderr.write(error_log)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
