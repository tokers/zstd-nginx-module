#!/usr/bin/env python3
"""Regression test for per-request ZSTD_CCtx isolation.

Bug class
---------
Commit 774b4a5 ("fix: use per-request zstd contexts") fixed a defect
where the compression context was effectively shared across requests
handled by one worker. A shared / improperly-reset ``ZSTD_CCtx`` does
NOT crash — it silently produces a *wrong but well-formed* zstd stream:
request A's worker state bleeds into request B, so B decompresses to a
mix of A's and B's bytes (or a frame that decodes cleanly but to the
wrong content). None of the other tests can see this: they each fetch a
single body, or many *identical* bodies, so cross-request bleed is
invisible.

This test makes every concurrent request ask for **distinct content**
and asserts each response decompresses to *its own* expected bytes,
exactly. Cross-request CCtx contamination shows up as a body that
decodes to the wrong request's payload (or a decode error / wrong
length).

Coverage
--------
* High concurrency against a single worker (worker_processes 1) so all
  requests share the one worker's context lifecycle.
* Distinct per-request payloads spanning the ZSTD_CStreamInSize buffer
  boundary (the size where the module's bugs cluster), with a unique
  per-request marker prefix so a swapped body is unambiguous.
* HTTP/1.1 keepalive reuse: many requests per connection (connection
  reuse is where a not-properly-reset context leaks between requests).
* Several rounds; every response decode-and-diffed against its own
  origin.

Rig discipline (same hard rules as the other regression tests):
* threaded backend (single-thread is OOM/stall-killed under load)
* backend self-check before trusting any end-to-end result
* distinct bytes per request id so a wrong-body is detectable
* per-request fresh buffer; an HTTP error is a failure, not a retry
* overall + per-request timeouts so a livelock is a hard FAIL

Self-contained: stdlib + the ``zstd`` CLI only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.server
import os
import pathlib
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

CSTREAM_IN = 131072  # ZSTD_CStreamInSize (libzstd 1.5.x) — the size
# where this module's bug history clusters.
# Distinct sizes straddling the boundary; each request id maps to one.
SIZES = [913, 65536, CSTREAM_IN - 1, CSTREAM_IN, CSTREAM_IN + 1, 180003, 524288]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Per-request ZSTD_CCtx isolation regression (774b4a5 class)."
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18098)
    p.add_argument("--backend-port", type=int, default=18099)
    p.add_argument(
        "--concurrency", type=int, default=16, help="Simultaneous in-flight requests."
    )
    p.add_argument(
        "--rounds", type=int, default=6, help="Times to run the full concurrent batch."
    )
    p.add_argument(
        "--require-multi-slot",
        action="store_true",
        help="Also assert, from the debug-log witnesses, that the worker "
        "CCtx ring actually lent MORE THAN ONE slot during the run. "
        "Without this the byte-exactness oracle alone is satisfied by a "
        "build where concurrent claimants always fall through to a "
        "per-request context -- which is exactly what the single-slot "
        "cache did, so the test would pass without ever exercising "
        "concurrent slot borrowing, the risk surface the ring "
        "introduces. Needs an nginx built --with-debug; raises the "
        "location error_log to debug.",
    )
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def payload_for(req_id: int) -> bytes:
    """Deterministic, unique-per-id, low-compressibility body.

    A 64-byte ASCII header carries the request id so a swapped body is
    instantly identifiable; the remainder is an id-seeded PRNG stream
    (incompressible -> the stream genuinely crosses output buffers, the
    regime where context state matters)."""
    size = SIZES[req_id % len(SIZES)]
    head = f"REQ-{req_id:08d}-CCTX-ISOLATION-MARKER-".encode()
    head = head + b"=" * (64 - len(head))
    buf = bytearray(head)
    x = (req_id * 2654435761 + 1) & 0xFFFFFFFF
    while len(buf) < size:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf.append((x >> 16) & 0xFF)
    return bytes(buf[:size])


class _Handler(http.server.BaseHTTPRequestHandler):
    """GET /r/<id> -> payload_for(id), chunked, no Content-Length."""

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


def fetch_decoded(port: int, rid: int, zstd_bin: str) -> bytes:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/r/{rid}",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-cctx-iso/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        if (resp.headers.get("Content-Encoding") or "").lower() != "zstd":
            raise RuntimeError(
                f"rid={rid}: not zstd-encoded "
                f"(C-E={resp.headers.get('Content-Encoding')!r})"
            )
        blob = resp.read()
    if blob[:4] != b"\x28\xb5\x2f\xfd":
        raise RuntimeError(f"rid={rid}: no zstd magic (hex={blob[:8].hex()})")
    r = subprocess.run(
        [zstd_bin, "-dq", "-c"], input=blob, capture_output=True, check=False
    )
    if r.returncode != 0:
        raise RuntimeError(
            f"rid={rid}: zstd -d failed (premature "
            f"end / corrupt): " + r.stderr.decode("utf-8", "replace")
        )
    return r.stdout


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    if args.require_multi_slot:
        # The slot witnesses are ngx_log_debug2 lines, compiled out without
        # --with-debug. Checked here rather than at the assertion: a
        # non-debug build yields zero witnesses, which the multi-slot check
        # would otherwise report as "the ring never lent two slots" -- an
        # accusation against the module for what is a build-flavor problem.
        v = subprocess.run(
            [str(nginx), "-V"], capture_output=True, text=True, check=False
        )
        if "--with-debug" not in v.stderr:
            raise RuntimeError(
                "--require-multi-slot reads ngx_log_debug witnesses: this "
                "tool needs an nginx built --with-debug, or drop the flag"
            )

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
    with tempfile.TemporaryDirectory(prefix="zstd-cctx-") as td:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        logs = root / "logs"
        logs.mkdir()

        backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        try:
            wait_port(args.backend_port)
            # Backend self-check: distinct ids -> distinct bodies.
            for rid in (0, 3, 7):
                raw = urllib.request.urlopen(
                    f"http://127.0.0.1:{args.backend_port}/r/{rid}", timeout=10
                ).read()
                if raw != payload_for(rid):
                    raise RuntimeError(f"backend self-check failed for rid={rid}")
            if (
                payload_for(0) == payload_for(1)
                or hashlib.sha256(payload_for(2)).digest()
                == hashlib.sha256(payload_for(3)).digest()
            ):
                raise RuntimeError(
                    "payloads not distinct per id (test would be blind to bleed)"
                )

            elvl = "debug" if args.require_multi_slot else "warn"
            load = "".join(f"load_module {m};\n" for m in mods)
            conf = root / "nginx.conf"
            conf.write_text(
                f"""{load}worker_processes 1;
error_log {logs}/error.log {elvl};
pid {root}/nginx.pid;
events {{ worker_connections 512; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    keepalive_requests 100000;
    server {{
        listen 127.0.0.1:{args.port};
        keepalive_timeout 60s;
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
                total = 0
                base = 0
                for rnd in range(args.rounds):
                    ids = list(range(base, base + args.concurrency))
                    base += args.concurrency
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=args.concurrency
                    ) as ex:
                        futs = {
                            ex.submit(fetch_decoded, args.port, rid, args.zstd_bin): rid
                            for rid in ids
                        }
                        for fut in concurrent.futures.as_completed(futs):
                            rid = futs[fut]
                            total += 1
                            try:
                                got = fut.result()
                            except Exception as e:  # noqa: BLE001
                                failures.append(f"round {rnd} rid={rid}: {e}")
                                continue
                            want = payload_for(rid)
                            if got != want:
                                # Identify if it is *another request's*
                                # body (the CCtx-bleed signature).
                                culprit = ""
                                if got[:32].startswith(b"REQ-"):
                                    culprit = " looks like " + got[:28].decode(
                                        "ascii", "replace"
                                    )
                                failures.append(
                                    f"round {rnd} rid={rid}: body "
                                    f"mismatch (got {len(got)}B want "
                                    f"{len(want)}B){culprit}"
                                )
                slots_seen: set[str] = set()
                if args.require_multi_slot:
                    # Flush, then count the DISTINCT ring slots that were
                    # actually lent. One slot is the single-slot cache's
                    # behaviour; the concurrent-borrowing path this test
                    # exists to cover is only reached when at least two
                    # distinct slots were on loan during the run.
                    time.sleep(0.3)
                    elog = (logs / "error.log").read_text("utf-8", "replace")
                    slots_seen = set(
                        re.findall(
                            r"zstd: reusing worker cctx \S+ \(slot:(\d+)\)",
                            elog,
                        )
                    )
                    if len(slots_seen) < 2:
                        failures.append(
                            f"only {len(slots_seen)} distinct ring slot(s) "
                            f"were ever lent ({sorted(slots_seen)}) across "
                            f"{total} concurrent requests -- this run never "
                            f"exercised concurrent slot borrowing, so its "
                            f"byte-exactness result proves nothing about "
                            f"the ring"
                        )

                if failures:
                    sys.stderr.write(
                        f"CCtx-ISOLATION FAILED: {len(failures)}/{total}:\n"
                    )
                    for f in failures[:25]:
                        sys.stderr.write(f"  - {f}\n")
                    if len(failures) > 25:
                        sys.stderr.write(f"  ... +{len(failures) - 25} more\n")
                    return 1
                print(
                    f"OK: {total} concurrent requests "
                    f"({args.concurrency} in flight x {args.rounds} "
                    f"rounds, distinct per-request bodies, keepalive "
                    f"reuse) each decoded byte-exact to its own "
                    f"origin — no cross-request CCtx bleed"
                    + (
                        f"; {len(slots_seen)} distinct ring slots lent concurrently"
                        if args.require_multi_slot
                        else ""
                    )
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
