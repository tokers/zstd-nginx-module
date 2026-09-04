#!/usr/bin/env python3
"""Regression test: response correctness across nginx reload under load.

Bug class
---------
Commit 2c538e0 ("fix: register CDict cleanup handler to prevent leak on
reload") and the broader CDict / config-cycle lifetime history: a
``zstd_dict_file`` ``ZSTD_CDict`` is owned by the configuration cycle.
On ``nginx -s reload`` the old cycle is retired while in-flight
requests on old workers are still compressing with the old cycle's
CDict. A mishandled lifetime here can leak (covered by the existing
``tools/test_reload_leak.sh``) **or** corrupt / truncate responses
that straddle the reload — which nothing currently asserts.

This test keeps a steady request stream running, issues repeated
``SIGHUP`` reloads while requests are in flight, and verifies **every**
response (old-cycle, straddling, and new-cycle) still decompresses
byte-exact to its origin, the master stays up, and the error log stays
clean (no ``[alert]``/``[emerg]``/``zero size buf``/sanitizer).

Rig discipline (same hard rules as the other regression tests):
* threaded backend; backend self-check before trusting results
* distinct per-request bodies so a wrong/stale body is detectable
* decode-and-diff the full body; HTTP error is a failure
* a real ``zstd_dict_file`` so the CDict lifetime path is exercised
* overall timeout so a hang/livelock is a hard FAIL

Self-contained: stdlib + the ``zstd`` CLI only.
"""

from __future__ import annotations

import argparse
import http.server
import os
import pathlib
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

CSTREAM_IN = 131072
SIZES = [4096, 65000, CSTREAM_IN - 1, CSTREAM_IN + 1, 200000]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Response correctness across reload under load "
        "(2c538e0 CDict-cycle class)."
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18100)
    p.add_argument("--backend-port", type=int, default=18101)
    p.add_argument("--reloads", type=int, default=6)
    p.add_argument(
        "--workers", type=int, default=4, help="Concurrent client workers driving load."
    )
    p.add_argument(
        "--duration",
        type=float,
        default=18.0,
        help="Seconds of sustained load (reloads spread across it).",
    )
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def payload_for(rid: int) -> bytes:
    size = SIZES[rid % len(SIZES)]
    head = f"RELOAD-REQ-{rid:09d}-".encode()
    head = head + b"." * (48 - len(head))
    buf = bytearray(head)
    x = (rid * 2246822519 + 7) & 0xFFFFFFFF
    while len(buf) < size:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf.append((x >> 16) & 0xFF)
    return bytes(buf[:size])


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        seg = self.path.split("?")[0].rsplit("/", 1)[-1]
        try:
            rid = int(seg)
        except ValueError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = payload_for(rid)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
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
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def one(port: int, rid: int, zstd_bin: str, dict_path: pathlib.Path) -> None:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/r/{rid}",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-reload/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        if (resp.headers.get("Content-Encoding") or "").lower() != "zstd":
            raise RuntimeError(
                f"rid={rid}: not zstd (C-E={resp.headers.get('Content-Encoding')!r})"
            )
        blob = resp.read()
    if blob[:4] != b"\x28\xb5\x2f\xfd":
        raise RuntimeError(f"rid={rid}: no zstd magic")
    # nginx.conf below sets zstd_dict_file, so every response is compressed
    # against that dictionary (ZSTD_CCtx_refCDict in the filter module) --
    # the decoder needs the same dictionary via -D, or libzstd correctly
    # rejects the frame as "Data corruption detected" even though nothing is
    # actually corrupt. Omitting -D here previously made this test fail on
    # every run regardless of reload timing (any response, any size).
    r = subprocess.run(
        [zstd_bin, "-dq", "-c", "-D", str(dict_path)],
        input=blob,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"rid={rid}: zstd -d failed: " + r.stderr.decode("utf-8", "replace")
        )
    if r.stdout != payload_for(rid):
        raise RuntimeError(
            f"rid={rid}: body mismatch across reload "
            f"(got {len(r.stdout)}B want {len(payload_for(rid))}B)"
        )


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

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-reload-") as td:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        logs = root / "logs"
        logs.mkdir()
        # A non-trivial dictionary so ZSTD_createCDict actually
        # allocates and the per-cycle CDict lifetime is exercised.
        dict_path = root / "zstd.dict"
        dseed = bytearray()
        x = 0x9E3779B1
        while len(dseed) < 16384:
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            dseed.append((x >> 16) & 0xFF)
        dict_path.write_bytes(bytes(dseed))

        backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        try:
            wait_port(args.backend_port)
            for rid in (0, 2, 4):
                if urllib.request.urlopen(
                    f"http://127.0.0.1:{args.backend_port}/r/{rid}", timeout=10
                ).read() != payload_for(rid):
                    raise RuntimeError(f"backend self-check failed rid={rid}")

            load = "".join(f"load_module {m};\n" for m in mods)
            pid_file = root / "nginx.pid"
            conf = root / "nginx.conf"
            conf.write_text(
                f"""{load}worker_processes 2;
error_log {logs}/error.log warn;
pid {pid_file};
events {{ worker_connections 256; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd_dict_file_unsafe on;
    zstd_dict_file {dict_path};
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    server {{
        listen 127.0.0.1:{args.port};
        location /r/ {{
            proxy_pass http://127.0.0.1:{args.backend_port}/r/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
""",
                encoding="utf-8",
            )

            # Master process mode (reload needs a master to signal).
            proc = subprocess.Popen(
                [str(nginx), "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_port(args.port)
                stop = threading.Event()
                failures: list[str] = []
                counter = {"n": 0}
                clock = threading.Lock()

                def worker():
                    while not stop.is_set():
                        with clock:
                            rid = counter["n"]
                            counter["n"] += 1
                        try:
                            one(args.port, rid, args.zstd_bin, dict_path)
                        except Exception as e:  # noqa: BLE001
                            failures.append(str(e))

                threads = [
                    threading.Thread(target=worker, daemon=True)
                    for _ in range(args.workers)
                ]
                for t in threads:
                    t.start()

                # Spread SIGHUP reloads across the load window.
                deadline = time.time() + args.duration
                interval = args.duration / (args.reloads + 1)
                master_pid = int(pid_file.read_text().strip())
                done_reloads = 0
                while time.time() < deadline and not failures:
                    time.sleep(interval)
                    if done_reloads < args.reloads:
                        os.kill(master_pid, signal.SIGHUP)
                        done_reloads += 1
                stop.set()
                for t in threads:
                    t.join(timeout=10)

                # Final clean shutdown so all cycle cleanups run
                # (incl. the CDict cleanup handler from 2c538e0).
                os.kill(master_pid, signal.SIGQUIT)
                try:
                    # 30s, not 10/5: gcov-instrumented nginx flushing
                    # .gcda at exit on a loaded runner can outlive a
                    # tight reap budget; teardown runs after the
                    # verdict, so patience costs nothing when healthy.
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=30)

                el = logs / "error.log"
                logtext = el.read_text("utf-8", "replace") if el.exists() else ""
                bad = [
                    ln
                    for ln in logtext.splitlines()
                    if (
                        "[alert]" in ln
                        or "[emerg]" in ln
                        or "zero size buf in writer" in ln
                        or "AddressSanitizer" in ln
                        or "LeakSanitizer" in ln
                        or "runtime error:" in ln
                    )
                ]

                if failures or bad:
                    sys.stderr.write(
                        f"RELOAD-UNDER-LOAD FAILED: "
                        f"{len(failures)} response failures, "
                        f"{len(bad)} log issues, "
                        f"{counter['n']} reqs, "
                        f"{done_reloads} reloads:\n"
                    )
                    for f in failures[:15]:
                        sys.stderr.write(f"  resp: {f}\n")
                    for b in bad[:10]:
                        sys.stderr.write(f"  log:  {b}\n")
                    return 1

                print(
                    f"OK: {counter['n']} requests across "
                    f"{done_reloads} SIGHUP reloads under "
                    f"{args.workers}-way load — every response "
                    f"decoded byte-exact, master survived, error log "
                    f"clean (CDict cycle lifetime intact)"
                )
                return 0
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
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
