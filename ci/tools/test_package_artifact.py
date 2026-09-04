#!/usr/bin/env python3
import argparse
import dataclasses
import pathlib
import shutil
import subprocess
import sys
import tempfile

MODULE_DIR = pathlib.Path(__file__).resolve().parent
TEST_ENCODING = MODULE_DIR / "test_encoding.py"
TEST_TERMINAL_FRAME = MODULE_DIR / "test_terminal_frame.py"


@dataclasses.dataclass(frozen=True)
class PackageLayout:
    package_root: pathlib.Path
    flavor: str
    modules_dir: pathlib.Path
    filter_module: pathlib.Path
    static_module: pathlib.Path
    load_snippet: pathlib.Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a built nginx/angie http-zstd package artifact by checking "
            "its installed files and re-running the zstd smoke tests against the "
            "packaged module .so files."
        )
    )
    parser.add_argument(
        "--nginx-binary",
        required=True,
        help="Path to the nginx or angie binary used to run the smoke tests.",
    )
    parser.add_argument(
        "--package-root",
        help="Path to an already extracted package root (contains usr/lib/... and usr/share/...).",
    )
    parser.add_argument(
        "--deb-path",
        help="Path to a .deb package to extract and validate.",
    )
    parser.add_argument(
        "--zstd-bin",
        default=shutil.which("zstd") or "zstd",
        help="Path to the zstd CLI used by the child smoke tests.",
    )
    parser.add_argument(
        "--request-count",
        type=int,
        default=8,
        help="Sequential request count for the large-response smoke test.",
    )
    parser.add_argument(
        "--concurrent-requests",
        type=int,
        default=8,
        help="Concurrent request count for the large-response smoke test.",
    )
    parser.add_argument(
        "--terminal-request-count",
        type=int,
        default=12,
        help="Sequential request count for the terminal-frame regression smoke.",
    )
    return parser.parse_args()


def extract_deb(deb_path: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    subprocess.run(
        ["dpkg-deb", "-x", str(deb_path), str(destination)],
        check=True,
        capture_output=True,
        text=True,
    )
    return destination


def detect_package_layout(package_root: pathlib.Path) -> PackageLayout:
    candidates = (
        (
            "angie",
            package_root / "usr/lib/angie/modules",
            package_root / "usr/share/angie/modules-available/mod-http-zstd.conf",
        ),
        (
            "nginx",
            package_root / "usr/lib/nginx/modules",
            package_root / "usr/share/nginx/modules-available/mod-http-zstd.conf",
        ),
    )

    for flavor, modules_dir, load_snippet in candidates:
        filter_module = modules_dir / "ngx_http_zstd_filter_module.so"
        static_module = modules_dir / "ngx_http_zstd_static_module.so"
        if filter_module.exists() and static_module.exists() and load_snippet.exists():
            return PackageLayout(
                package_root=package_root,
                flavor=flavor,
                modules_dir=modules_dir,
                filter_module=filter_module,
                static_module=static_module,
                load_snippet=load_snippet,
            )

    raise FileNotFoundError(
        "could not find packaged zstd modules under usr/lib/{angie,nginx}/modules "
        "with matching mod-http-zstd.conf load snippet"
    )


def verify_load_snippet(layout: PackageLayout) -> None:
    snippet = layout.load_snippet.read_text(encoding="utf-8", errors="replace")
    for module in (layout.filter_module.name, layout.static_module.name):
        if module not in snippet:
            raise RuntimeError(
                f"load snippet {layout.load_snippet} does not reference {module}"
            )


def run_child(command: list[str]) -> None:
    subprocess.run(command, check=True)


def run_smoke_tests(
    layout: PackageLayout,
    nginx_binary: pathlib.Path,
    zstd_bin: str,
    request_count: int,
    concurrent_requests: int,
    terminal_request_count: int,
) -> None:
    run_child(
        [
            sys.executable,
            str(TEST_ENCODING),
            "--nginx-binary",
            str(nginx_binary),
            "--filter-module",
            str(layout.filter_module),
            "--static-module",
            str(layout.static_module),
            "--zstd-bin",
            zstd_bin,
            "--request-count",
            str(request_count),
            "--concurrent-requests",
            str(concurrent_requests),
        ]
    )
    run_child(
        [
            sys.executable,
            str(TEST_TERMINAL_FRAME),
            "--nginx-binary",
            str(nginx_binary),
            "--filter-module",
            str(layout.filter_module),
            "--static-module",
            str(layout.static_module),
            "--zstd-bin",
            zstd_bin,
            "--request-count",
            str(terminal_request_count),
        ]
    )


def main() -> int:
    args = parse_args()
    if bool(args.package_root) == bool(args.deb_path):
        raise ValueError("provide exactly one of --package-root or --deb-path")

    nginx_binary = pathlib.Path(args.nginx_binary)
    if not nginx_binary.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx_binary}")

    managed_tempdir: tempfile.TemporaryDirectory[str] | None = None
    try:
        if args.package_root:
            package_root = pathlib.Path(args.package_root)
        else:
            deb_path = pathlib.Path(args.deb_path)
            if not deb_path.exists():
                raise FileNotFoundError(f"package not found: {deb_path}")
            managed_tempdir = tempfile.TemporaryDirectory(prefix="http-zstd-deb-")
            package_root = extract_deb(deb_path, pathlib.Path(managed_tempdir.name))

        layout = detect_package_layout(package_root)
        verify_load_snippet(layout)
        run_smoke_tests(
            layout,
            nginx_binary,
            args.zstd_bin,
            args.request_count,
            args.concurrent_requests,
            args.terminal_request_count,
        )

        print(
            "OK: verified packaged http-zstd artifact "
            f"for {layout.flavor} using {layout.load_snippet.name} and packaged modules"
        )
        return 0
    finally:
        if managed_tempdir is not None:
            managed_tempdir.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
