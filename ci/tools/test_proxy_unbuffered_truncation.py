#!/usr/bin/env python3
"""Regression test for bug B: silent truncation / aborted response when
zstd compresses a proxied response with ``proxy_buffering off``.

Background
----------
Production (deb.myguard.nl, ``proxy_buffering off`` in the WordPress
vhost) served truncated / empty zstd responses. Root cause: under
``proxy_buffering off`` the upstream forces a flush around body data on
a compress call that feeds libzstd nothing (or sub-block-size input it
buffers internally); the filter then forwarded a *zero-size* buffer,
which nginx's ``ngx_http_write_filter`` rejects with
``zero size buf in writer`` and aborts the request. The body filter's
compress-directive selection ignored ``ctx->flush`` and the empty-buffer
emit guard had a ``!(rc == 0 && ctx->flush)`` exception that let the
empty buffer through.

Why the existing suite missed it
--------------------------------
``t/00-filter.t`` chunked cases use ``--- ignore_response`` (assert a
log line, never decode the body). ``test_terminal_frame.py`` uses a
tiny body that never crosses an output buffer. None used
``proxy_buffering off``. This test closes that gap: it reproduces the
exact production transport (proxy_pass -> chunked, no Content-Length,
``proxy_buffering off``) and **decodes + byte-compares the full body**
across the buffer-boundary size matrix.

It MUST fail on a module without the fix (truncated/aborted -> decoded
bytes differ or curl fails) and pass with it.

Hard test-rig discipline (learned the hard way during the bug-B hunt)
--------------------------------------------------------------------
* Decode and byte-compare the *whole* body and assert exact length —
  never trust an HTTP 200 or a non-empty body alone.
* Assert the response for size N actually has length N: guards against
  a stale / wrong-body false-green.
* Threaded backend: a single-threaded http.server is OOM/stall-killed
  under the boundary matrix and produces mass false failures.
* Verify the backend answers correctly *before* starting nginx.
* Fresh output file per request; ``curl -f`` so an HTTP error is a
  failure, not a silently reused stale file.

Self-contained: stdlib + the ``zstd`` CLI only (no PHP-FPM/fcgiwrap),
so it runs anywhere the rest of the Python suite does.
"""

from __future__ import annotations

import argparse
import http.server
import os
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

# Sizes straddle ZSTD_CStreamInSize (~131072 = 128 KiB), the historical
# boundary for this module's truncation bug class. 1 and 1024 are below
# one zstd block (output buffered internally -> the exact forced-flush
# zero-output path); the rest force multi-buffer streaming.
SIZES = [1, 1024, 131071, 131072, 131073, 200000, 1048576]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Regression test for the proxy_buffering-off zstd truncation bug (bug B)."
        )
    )
    p.add_argument(
        "--nginx-binary", required=True, help="nginx (or angie) binary to launch."
    )
    p.add_argument(
        "--filter-module",
        help="Path to ngx_http_zstd_filter_module.so "
        "(auto-detected next to the binary if omitted).",
    )
    p.add_argument(
        "--static-module",
        help="Path to ngx_http_zstd_static_module.so "
        "(auto-detected next to the binary if omitted).",
    )
    p.add_argument(
        "--zstd-bin", default="zstd", help="zstd CLI used for decompression."
    )
    p.add_argument("--port", type=int, default=18086, help="Front-end nginx port.")
    p.add_argument(
        "--backend-port", type=int, default=18087, help="Mock chunked upstream port."
    )
    p.add_argument(
        "--repeat",
        type=int,
        default=5,
        help="Times to re-request each size (the bug is "
        "intermittent at the exact boundary).",
    )
    return p.parse_args()


def detect_module(
    explicit: str | None, nginx: pathlib.Path, name: str
) -> pathlib.Path | None:
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serve /b/<n> as exactly <n> deterministic bytes, **chunked, no
    Content-Length**, written in small records so the response is a
    genuine streamed chunked body (the production shape)."""

    protocol_version = "HTTP/1.1"
    fixture_dir: pathlib.Path = pathlib.Path()

    def log_message(self, *a):
        pass

    def do_GET(self):
        name = self.path.rsplit("/", 1)[-1].split("?")[0]
        path = self.fixture_dir / name
        if not path.is_file():
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        mv = memoryview(data)
        step = 16384
        for i in range(0, len(mv), step):
            chunk = bytes(mv[i : i + step])
            self.wfile.write(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # Single-threaded server is OOM/stall-killed by the matrix and
    # yields mass false failures — must be threaded.
    allow_reuse_address = True
    daemon_threads = True


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def http_get(port: int, path: str, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-bugb-regression/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.headers.get("Content-Encoding", "").lower() != "zstd":
            raise RuntimeError(
                f"{path}: expected Content-Encoding=zstd, got "
                f"{resp.headers.get('Content-Encoding')!r}"
            )
        return resp.read()


def zstd_decompress(zstd_bin: str, blob: bytes) -> bytes:
    if blob[:4] != b"\x28\xb5\x2f\xfd":
        raise RuntimeError(
            f"missing zstd magic; first 16B hex={blob[:16].hex()} "
            f"(truncated/aborted response)"
        )
    r = subprocess.run(
        [zstd_bin, "-d", "-q", "-c"], input=blob, capture_output=True, check=False
    )
    if r.returncode != 0:
        raise RuntimeError(
            "zstd -d failed (premature end / corrupt frame): "
            + r.stderr.decode("utf-8", "replace").strip()
        )
    return r.stdout


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx}")

    filt = detect_module(args.filter_module, nginx, "ngx_http_zstd_filter_module.so")
    stat = detect_module(args.static_module, nginx, "ngx_http_zstd_static_module.so")
    modules = [m for m in (filt, stat) if m is not None]
    for m in modules:
        if not m.exists():
            raise FileNotFoundError(f"module not found: {m}")

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-bugb-") as td:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        fixtures = root / "fix"
        logs = root / "logs"
        fixtures.mkdir()
        logs.mkdir()

        # Deterministic, low-compressibility fixtures (like real CSS:
        # ~1:1, so the compressed stream genuinely crosses buffers).
        # Distinct per size so a wrong-body response is detectable.
        for n in SIZES:
            buf = bytearray(n)
            x = (n * 2654435761) & 0xFFFFFFFF
            for i in range(n):
                x = (x * 1103515245 + 12345) & 0xFFFFFFFF
                buf[i] = (x >> 16) & 0xFF
            (fixtures / str(n)).write_bytes(bytes(buf))

        _Handler.fixture_dir = fixtures
        backend = _ThreadingHTTPServer(("127.0.0.1", args.backend_port), _Handler)
        bt = threading.Thread(target=backend.serve_forever, daemon=True)
        bt.start()
        try:
            wait_port(args.backend_port)
            # Verify the backend itself is correct BEFORE trusting any
            # end-to-end result (rig-discipline rule).
            for n in (1, 131072, 1048576):
                raw = urllib.request.urlopen(
                    f"http://127.0.0.1:{args.backend_port}/b/{n}", timeout=10
                ).read()
                if len(raw) != n:
                    raise RuntimeError(
                        f"backend self-check failed: /b/{n} returned "
                        f"{len(raw)} bytes, expected {n}"
                    )

            load = "".join(f"load_module {m};\n" for m in modules)
            conf = root / "nginx.conf"
            conf.write_text(
                f"""{load}worker_processes 1;
error_log {logs}/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd on;
    zstd_comp_level 3;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    server {{
        listen 127.0.0.1:{args.port};
        location /b/ {{
            # The exact production trigger: unbuffered proxying of a
            # chunked, no-Content-Length upstream through the zstd
            # body filter.
            proxy_pass http://127.0.0.1:{args.backend_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }}
    }}
}}
""",
                encoding="utf-8",
            )

            proc = subprocess.Popen(
                [
                    str(nginx),
                    "-p",
                    str(root),
                    "-c",
                    str(conf),
                    "-g",
                    "daemon off; master_process off;",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_port(args.port)
                failures: list[str] = []
                for n in SIZES:
                    expected = (fixtures / str(n)).read_bytes()
                    for attempt in range(1, args.repeat + 1):
                        label = f"size={n} attempt={attempt}/{args.repeat}"
                        try:
                            blob = http_get(args.port, f"/b/{n}")
                            decoded = zstd_decompress(args.zstd_bin, blob)
                        except Exception as exc:  # noqa: BLE001
                            failures.append(f"{label}: {exc}")
                            continue
                        if len(decoded) != n:
                            failures.append(
                                f"{label}: decoded {len(decoded)} bytes, "
                                f"expected {n} (TRUNCATION)"
                            )
                        elif decoded != expected:
                            failures.append(
                                f"{label}: decoded body differs from "
                                f"origin at equal length (CORRUPTION)"
                            )

                if failures:
                    sys.stderr.write(
                        f"bug-B regression FAILED ({len(failures)} failing checks):\n"
                    )
                    for f in failures[:20]:
                        sys.stderr.write(f"  - {f}\n")
                    elog = logs / "error.log"
                    if elog.exists():
                        zsb = [
                            ln
                            for ln in elog.read_text("utf-8", "replace").splitlines()
                            if "zero size buf in writer" in ln
                        ]
                        if zsb:
                            sys.stderr.write(
                                f"  nginx logged {len(zsb)} "
                                f"'zero size buf in writer' "
                                f"(the bug-B signature)\n"
                            )
                    return 1

                total = len(SIZES) * args.repeat
                print(
                    f"OK: {total} proxy_buffering-off zstd responses "
                    f"across {len(SIZES)} boundary sizes round-tripped "
                    f"byte-exact (no truncation, no zero-size-buf abort)"
                )
                return 0
            finally:
                proc.terminate()
                try:
                    # 30s, not 5: gcov-instrumented nginx flushing
                    # .gcda at exit on a loaded runner can outlive a
                    # tight reap budget; teardown runs after the
                    # verdict, so patience costs nothing when healthy.
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=30)
        finally:
            backend.shutdown()
            backend.server_close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
