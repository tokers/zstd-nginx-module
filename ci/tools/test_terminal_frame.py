#!/usr/bin/env python3
import argparse
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

MODULE_PATH = pathlib.Path(__file__).with_name("test_encoding.py")
SPEC = importlib.util.spec_from_file_location("test_encoding", MODULE_PATH)
test_encoding = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(test_encoding)


TERMINAL_SENTINEL = "END-OF-ZSTD-TERMINAL-FRAME-REGRESSION-54d9b7aa"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a targeted regression test for the empty-output ZSTD_e_end "
            "terminal-frame path fixed in a209f96."
        )
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx binary to start for the regression test.",
    )
    parser.add_argument(
        "--filter-module",
        help="Optional path to ngx_http_zstd_filter_module.so.",
    )
    parser.add_argument(
        "--static-module",
        help="Optional path to ngx_http_zstd_static_module.so.",
    )
    parser.add_argument(
        "--zstd-bin",
        default=test_encoding.shutil.which("zstd") or "zstd",
        help="Path to the zstd CLI used for decompression.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18084,
        help="Local TCP port for the temporary nginx instance.",
    )
    parser.add_argument(
        "--request-count",
        type=int,
        default=12,
        help="How many sequential tiny-payload requests to verify.",
    )
    return parser.parse_args()


def build_terminal_fixture(path: pathlib.Path) -> bytes:
    payload = (
        "// terminal-frame regression fixture\n"
        'const payload = "aaaaaaaaaaaaaaaa";\n'
        "console.log(payload);\n"
        f'console.log("{TERMINAL_SENTINEL}");\n'
    )
    path.write_text(payload, encoding="utf-8", newline="\n")
    return payload.encode("utf-8")


def fetch_response(port: int) -> tuple[bytes, str]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/test.js",
        headers={
            "Accept-Encoding": "zstd",
            "User-Agent": "zstd-terminal-frame-regression/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        compressed = response.read()
        content_encoding = response.headers.get("Content-Encoding", "")
    return compressed, content_encoding


def validate_response(
    port: int, zstd_bin: str, expected: bytes, request_label: str
) -> None:
    compressed, encoding = fetch_response(port)
    if encoding.lower() != "zstd":
        raise RuntimeError(f"expected Content-Encoding=zstd, got {encoding!r}")

    decoded = test_encoding.decompress_payload(zstd_bin, compressed)
    if decoded != expected:
        raise RuntimeError(
            "decompressed tiny response does not match source fixture; "
            f"{request_label}, expected {len(expected)} bytes, got {len(decoded)} bytes"
        )
    if TERMINAL_SENTINEL.encode("utf-8") not in decoded:
        raise RuntimeError("terminal-frame sentinel missing from decoded response")


def main() -> int:
    args = parse_args()
    nginx_binary = pathlib.Path(args.nginx_binary)
    if not nginx_binary.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx_binary}")
    if (
        test_encoding.shutil.which(args.zstd_bin) is None
        and not pathlib.Path(args.zstd_bin).exists()
    ):
        raise FileNotFoundError(f"zstd CLI not found: {args.zstd_bin}")
    if args.request_count < 1:
        raise ValueError(f"request-count must be >= 1, got {args.request_count}")

    filter_module = test_encoding.detect_module_path(
        args.filter_module,
        nginx_binary,
        "ngx_http_zstd_filter_module.so",
    )
    static_module = test_encoding.detect_module_path(
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
    with tempfile.TemporaryDirectory(prefix="zstd-terminal-frame-") as temp_dir_str:
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
        expected = build_terminal_fixture(fixture_path)
        conf_path = conf_dir / "nginx.conf"
        test_encoding.write_config(
            conf_path, html_dir, args.port, args.port + 1, "off", modules
        )

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
            test_encoding.wait_for_port(args.port)
            for request_index in range(args.request_count):
                validate_response(
                    args.port,
                    args.zstd_bin,
                    expected,
                    f"request {request_index + 1}/{args.request_count}",
                )

            print(
                "OK: verified empty-output terminal-frame regression "
                f"across {args.request_count} tiny sequential requests"
            )
            return 0
        finally:
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
            error_log = test_encoding.read_if_exists(logs_dir / "error.log")
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
