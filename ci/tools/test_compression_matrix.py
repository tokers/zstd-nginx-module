#!/usr/bin/env python3
"""Broad correctness matrix for the zstd filter.

The module's truncation / zero-size-buffer / terminal-frame bug class
(a209f96, 2af5889, PR#23/#49, bug A #36, bug B) keeps recurring in
*different* circumstances, and each prior regression test pinned only
the one slice that had just broken. This test crosses the axes the bug
class has actually hit and asserts the right outcome in **every cell**:

  * transport      : proxy (buffering on), proxy (buffering off), static
  * payload        : incompressible, highly-compressible, real-CSS-like
  * size           : 1, 1024, CStreamInSize-1/=/+1, 200000, 1 MiB
  * Accept-Encoding: "zstd"            -> must be zstd, byte-exact
                      "gzip, br, zstd" -> some C-E set, body decodes to
                                          origin (zstd OR a co-filter
                                          wins; either is correct as
                                          long as it round-trips)
                      "gzip"           -> must NOT be zstd; body intact
                      ""  (identity)   -> no C-E; body intact

Every cell verifies the client can reconstruct the exact origin bytes
(decode per the returned Content-Encoding, then byte-compare) — never
"got 200" or "got non-empty". A truncation/abort shows up as a short
body, a decode error, or a connection failure.

Rig discipline (learned the hard way):
  * threaded backend (single-thread is OOM/stall-killed under load)
  * backend self-check before trusting any end-to-end result
  * distinct bytes per (payload,size) so a wrong-body is detectable
  * fresh request each cell; HTTP error => failure, not silent reuse

Self-contained: stdlib + the ``zstd`` and ``gzip`` CLIs (+ ``brotli``
if present; brotli cells are skipped when it is not). No PHP-FPM.
"""

from __future__ import annotations

import argparse
import gzip as _gzip
import http.server
import itertools
import os
import pathlib
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import ClassVar

CSTREAM_IN = 131072  # ZSTD_CStreamInSize on libzstd 1.5.x — the
# historical boundary for this bug class.
SIZES = [1, 1024, CSTREAM_IN - 1, CSTREAM_IN, CSTREAM_IN + 1, 200000, 1024 * 1024]
PAYLOADS = ("incompressible", "compressible", "css")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Broad zstd filter correctness matrix.")
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18096)
    p.add_argument("--backend-port", type=int, default=18097)
    p.add_argument(
        "--repeat",
        type=int,
        default=2,
        help="Re-request each cell N times (intermittent bugs surface on repeats).",
    )
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def make_payload(kind: str, n: int) -> bytes:
    if kind == "incompressible":
        buf = bytearray(n)
        x = (n * 2654435761) & 0xFFFFFFFF
        for i in range(n):
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            buf[i] = (x >> 16) & 0xFF
        return bytes(buf)
    if kind == "compressible":
        # Highly compressible: zstd buffers internally and produces
        # zero output on early/forced-flush calls — the exact bug-B
        # path. A short unique prefix keeps (kind,size) bodies distinct.
        head = f"CELL-{kind}-{n}-".encode()
        return (head + b"A" * max(0, n - len(head)))[:n]
    # "css": realistic mid-ratio text, distinct per size.
    unit = (
        f"/* cell {n} */.c{n}{{color:#abcdef;margin:0 auto;padding:1px}}\n"
    ).encode()
    return (unit * (n // len(unit) + 1))[:n]


class _Handler(http.server.BaseHTTPRequestHandler):
    """GET /p/<kind>/<n> -> exactly <n> bytes of <kind>, **chunked,
    no Content-Length**, streamed in small records."""

    protocol_version = "HTTP/1.1"
    # ClassVar: deliberately shared by every handler instance -- the server
    # populates it once before serving, and each request only reads it.
    fixtures: ClassVar[dict] = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if len(parts) != 3 or parts[0] != "p":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        key = (parts[1], int(parts[2]))
        data = self.fixtures.get(key)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/css")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        mv = memoryview(data)
        for i in range(0, len(mv), 16384):
            c = bytes(mv[i : i + 16384])
            self.wfile.write(b"%X\r\n" % len(c) + c + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")


class _Srv(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def wait_port(port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing on 127.0.0.1:{port}")


def fetch(port: int, path: str, accept_encoding: str):
    hdrs = {"User-Agent": "zstd-matrix/1.0"}
    if accept_encoding:
        hdrs["Accept-Encoding"] = accept_encoding
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=hdrs)
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read(), (resp.headers.get("Content-Encoding") or "").lower()


def decode(zstd_bin: str, blob: bytes, enc: str) -> bytes:
    if enc == "zstd":
        if blob[:4] != b"\x28\xb5\x2f\xfd":
            raise RuntimeError(f"zstd C-E but no zstd magic (hex={blob[:8].hex()})")
        r = subprocess.run(
            [zstd_bin, "-dq", "-c"], input=blob, capture_output=True, check=False
        )
        if r.returncode != 0:
            raise RuntimeError(
                "zstd -d failed (premature end): " + r.stderr.decode("utf-8", "replace")
            )
        return r.stdout
    if enc == "gzip":
        return _gzip.decompress(blob)
    if enc == "br":
        br = shutil.which("brotli")
        if not br:
            raise RuntimeError("br C-E but no brotli CLI to verify")
        r = subprocess.run([br, "-dc"], input=blob, capture_output=True, check=False)
        if r.returncode != 0:
            raise RuntimeError("brotli -d failed")
        return r.stdout
    if enc in ("", "identity"):
        return blob
    raise RuntimeError(f"unexpected Content-Encoding {enc!r}")


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)
    mods = [
        m
        for m in (
            detect(args.filter_module, nginx, "ngx_http_zstd_filter_module.so"),
            detect(args.static_module, nginx, "ngx_http_zstd_static_module.so"),
        )
        if m
    ]
    have_brotli = shutil.which("brotli") is not None

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-matrix-") as td:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        sroot = root / "static"
        logs = root / "logs"
        sroot.mkdir()
        logs.mkdir()

        fixtures: dict = {}
        for kind, n in itertools.product(PAYLOADS, SIZES):
            data = make_payload(kind, n)
            fixtures[(kind, n)] = data
            (sroot / f"{kind}-{n}").write_bytes(data)
        _Handler.fixtures = fixtures

        backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        try:
            wait_port(args.backend_port)
            # backend self-check (rig discipline)
            for kind, n in (
                ("incompressible", 1),
                ("compressible", CSTREAM_IN),
                ("css", 1024 * 1024),
            ):
                raw = urllib.request.urlopen(
                    f"http://127.0.0.1:{args.backend_port}/p/{kind}/{n}", timeout=10
                ).read()
                if raw != fixtures[(kind, n)]:
                    raise RuntimeError(f"backend self-check failed for {kind}/{n}")

            load = "".join(f"load_module {m};\n" for m in mods)
            conf = root / "nginx.conf"
            conf.write_text(
                f"""{load}worker_processes 1;
error_log {logs}/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 256; }}
http {{
    access_log off;
    default_type text/css;
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1;
    zstd_types text/css;
    gzip on;
    gzip_comp_level 5;
    gzip_min_length 1;
    gzip_types text/css;
    server {{
        listen 127.0.0.1:{args.port};
        # transport: proxy, buffering ON (default)
        location /bufon/ {{
            proxy_pass http://127.0.0.1:{args.backend_port}/p/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
        # transport: proxy, buffering OFF (the bug-B production shape)
        location /bufoff/ {{
            proxy_pass http://127.0.0.1:{args.backend_port}/p/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }}
        # transport: static file (sendfile path)
        location /static/ {{
            alias {sroot}/;
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
                ae_axis = ["zstd", "gzip", ""]
                if have_brotli:
                    ae_axis.append("gzip, br, zstd")
                else:
                    ae_axis.append("gzip, zstd")  # zstd should win

                transports = {
                    "bufon": lambda k, n: f"/bufon/{k}/{n}",
                    "bufoff": lambda k, n: f"/bufoff/{k}/{n}",
                    "static": lambda k, n: f"/static/{k}-{n}",
                }

                failures: list[str] = []
                cells = 0
                for tname, mkpath in transports.items():
                    for kind in PAYLOADS:
                        for n in SIZES:
                            origin = fixtures[(kind, n)]
                            for ae in ae_axis:
                                for attempt in range(args.repeat):
                                    cells += 1
                                    lbl = (
                                        f"{tname} {kind} n={n} AE={ae!r} #{attempt + 1}"
                                    )
                                    try:
                                        body, enc = fetch(
                                            args.port, mkpath(kind, n), ae
                                        )
                                    except Exception as e:  # noqa
                                        failures.append(f"{lbl}: request failed: {e}")
                                        continue
                                    # Correctness rules:
                                    # AE 'zstd' -> must be zstd.
                                    # AE 'gzip' -> must NOT be zstd.
                                    # any      -> body decodes to origin.
                                    if ae == "zstd" and enc != "zstd":
                                        failures.append(
                                            f"{lbl}: expected zstd, got C-E={enc!r}"
                                        )
                                        continue
                                    if ae == "gzip" and enc == "zstd":
                                        failures.append(
                                            f"{lbl}: zstd served to gzip-only client"
                                        )
                                        continue
                                    try:
                                        dec = decode(args.zstd_bin, body, enc)
                                    except Exception as e:  # noqa
                                        failures.append(
                                            f"{lbl}: decode failed (C-E={enc!r}): {e}"
                                        )
                                        continue
                                    if dec != origin:
                                        failures.append(
                                            f"{lbl}: body mismatch "
                                            f"(C-E={enc!r} got "
                                            f"{len(dec)}B want {n}B)"
                                        )

                if failures:
                    sys.stderr.write(f"MATRIX FAILED: {len(failures)}/{cells} cells:\n")
                    for f in failures[:30]:
                        sys.stderr.write(f"  - {f}\n")
                    if len(failures) > 30:
                        sys.stderr.write(f"  ... +{len(failures) - 30} more\n")
                    el = logs / "error.log"
                    if el.exists():
                        z = [
                            ln
                            for ln in el.read_text("utf-8", "replace").splitlines()
                            if "zero size buf in writer" in ln
                        ]
                        if z:
                            sys.stderr.write(
                                f"  nginx logged {len(z)} 'zero size buf in writer'\n"
                            )
                    return 1

                print(
                    f"OK: {cells} matrix cells "
                    f"({len(transports)} transports x "
                    f"{len(PAYLOADS)} payloads x {len(SIZES)} sizes "
                    f"x {len(ae_axis)} AE x {args.repeat}) "
                    f"all round-tripped byte-exact / correct "
                    f"fallback"
                    + ("" if have_brotli else " [brotli CLI absent: br-axis skipped]")
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
