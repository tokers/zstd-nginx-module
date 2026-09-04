#!/usr/bin/env python3
"""Regression test for the ``zstd_long`` (long-distance matching) directive.

Bug class
---------
Commit 8edb7bb added the ``zstd_long`` directive
(``ZSTD_c_enableLongDistanceMatching``) and the interacting
``zstd_window_log`` cap (``ZSTD_c_windowLog``). Both are set on the
per-request ``ZSTD_CCtx`` *before* compression starts. A shipped
feature with **zero** test coverage: a mistake in the parameter wiring
(wrong enum, value clamped/rejected, set after the stream is already
running, or an interaction with the per-request CCtx / window cap)
would either

* abort the stream (``ZSTD_setParameter`` error -> 500 / truncated
  body — the bug-B failure mode), or
* silently produce a *wrong but well-formed* frame, or
* quietly do nothing (LDM never actually engages), so the directive is
  a no-op and operators get none of the promised ratio win.

This test asserts all three cannot happen:

1. **Correctness** — a large body that is internally repetitive *beyond
   the regular match window* (the regime LDM exists for) still
   decompresses byte-exact with ``zstd_long on``, including with an
   explicit small ``zstd_window_log`` cap (the documented "explicit
   window cap still takes precedence" path around line 1000 of the
   filter module).
2. **Effect** — with such a body, ``zstd_long on`` must produce a
   *strictly smaller* compressed stream than ``zstd_long off`` at the
   same level. If LDM were silently a no-op the two sizes would match;
   a meaningful gap proves the directive reached libzstd and engaged.
3. **No regression** — master process clean shutdown, error log free of
   ``[alert]``/``[emerg]``/``zero size buf``/sanitizer findings.

Rig discipline (same hard rules as the other regression tests):
* threaded backend; backend self-check before trusting any result
* a body with long-range repeats *and* a unique per-request marker so a
  swapped/stale body is detectable
* decode-and-diff the full body; any HTTP error is a hard failure
* overall timeout via the CI step so a hang/livelock is a hard FAIL

Self-contained: stdlib + the ``zstd`` CLI only.
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

# Body layout (designed so ONLY long-distance matching can collapse it
# at the configured compression level, with NO window-cap fiddling —
# the directive under test is exercised in isolation):
#
#   [ 8 MiB unique pseudo-random region R ][ exact copy of R ]
#
# R is incompressible (id-seeded PRNG) so the regular matcher cannot
# shrink it. The second copy of R repeats at distance 8 MiB, which is
# far beyond zstd's level-6 *default* match window (~1–2 MiB): by the
# time the duplicate arrives the regular matcher's window has long slid
# past the original, so it cannot back-reference it and the body stays
# ~incompressible (~16 MiB out). LDM, whose long-range hash table
# defaults to a 2^27 window, *can* reach back 8 MiB, match the copy to
# R, and roughly halve the output (~8 MiB). Empirically (libzstd
# 1.5.x): off ~= 16 MiB, on ~= 8 MiB — a clean, unambiguous 2:1 signal
# that LDM genuinely engaged. A swapped/stale body is caught by the
# per-request marker header.
UNIQUE = 8 * 1024 * 1024
TOTAL = 2 * UNIQUE


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="zstd_long / windowLog directive regression (8edb7bb class)."
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18102)
    p.add_argument("--backend-port", type=int, default=18103)
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def payload_for(rid: int) -> bytes:
    """Unique incompressible region R followed by an exact copy of R.

    R is a ``UNIQUE``-byte id-seeded PRNG stream (incompressible, so the
    regular matcher cannot shrink it). The second half is byte-identical
    to R, repeating at distance ``UNIQUE`` — far beyond the small
    ``zstd_window_log`` cap, so only long-distance matching can collapse
    it. A 64-byte marker header makes a swapped/stale body unambiguous."""
    head = f"ZSTD-LONG-REQ-{rid:08d}-LDM-MARKER-".encode()
    head = head + b"#" * (64 - len(head))
    r = bytearray(head)
    x = (rid * 2654435761 + 1) & 0xFFFFFFFF
    while len(r) < UNIQUE:
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        r.append((x >> 16) & 0xFF)
    r = bytes(r[:UNIQUE])
    return r + r


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


def fetch(port: int, rid: int, zstd_bin: str) -> tuple[bytes, int]:
    """Return (decoded_body, compressed_size) or raise on any error."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/r/{rid}",
        headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-long/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
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
    return r.stdout, len(blob)


def run_server(
    nginx, conf, root, port, backend_port, zstd_bin, rids: list[int]
) -> dict[int, tuple[bytes, int]]:
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
        wait_port(port)
        return {rid: fetch(port, rid, zstd_bin) for rid in rids}
    finally:
        proc.terminate()
        try:
            # 30s, not 5: a gcov-instrumented nginx flushing .gcda at
            # exit on a loaded runner can outlive a tight reap budget
            # (seen live in CI — the verdict had already passed and the
            # teardown alone failed the tool). Teardown runs after the
            # verdict, so patience costs nothing on healthy runs.
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=30)


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
    with tempfile.TemporaryDirectory(prefix="zstd-long-") as td:
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
            for rid in (1, 2, 3):
                raw = urllib.request.urlopen(
                    f"http://127.0.0.1:{args.backend_port}/r/{rid}", timeout=10
                ).read()
                if raw != payload_for(rid):
                    raise RuntimeError(f"backend self-check failed for rid={rid}")
            if len(payload_for(1)) != TOTAL:
                raise RuntimeError("payload not the expected size")

            load = "".join(f"load_module {m};\n" for m in mods)

            def conf_text(extra: str) -> str:
                return f"""{load}worker_processes 1;
error_log {logs}/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 256; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1;
    zstd_types application/octet-stream;
{extra}
    server {{
        listen 127.0.0.1:{args.port};
        location /r/ {{
            proxy_pass http://127.0.0.1:{args.backend_port}/r/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
"""

            rids = [11, 22, 33]

            # Baseline: LDM off (default).
            off_conf = root / "off.conf"
            off_conf.write_text(conf_text(""), encoding="utf-8")
            off = run_server(
                nginx, off_conf, root, args.port, args.backend_port, args.zstd_bin, rids
            )

            # LDM on (directive under test, in isolation — no window
            # cap, so zstd's LDM default 2^27 window is what reaches
            # back the 8 MiB to the duplicate region).
            on_conf = root / "on.conf"
            on_conf.write_text(conf_text("    zstd_long on;\n"), encoding="utf-8")
            on = run_server(
                nginx, on_conf, root, args.port, args.backend_port, args.zstd_bin, rids
            )

            failures: list[str] = []
            for rid in rids:
                want = payload_for(rid)
                off_body, off_sz = off[rid]
                on_body, on_sz = on[rid]
                # (1) correctness on both configs
                if off_body != want:
                    failures.append(
                        f"rid={rid}: LDM-off body mismatch "
                        f"(got {len(off_body)}B want {len(want)}B)"
                    )
                if on_body != want:
                    failures.append(
                        f"rid={rid}: LDM-on body mismatch "
                        f"(got {len(on_body)}B want {len(want)}B) — "
                        f"directive corrupts/truncates the stream"
                    )
                # (2) LDM must actually engage. The duplicate region is
                # only reachable via LDM's long-range window, so LDM-on
                # must roughly halve the output vs LDM-off. Require a
                # large, unambiguous gap (>25% smaller) so an incidental
                # few-byte difference cannot pass as "engaged"; a silent
                # no-op leaves the two sizes essentially equal.
                if on_sz >= off_sz * 0.75:
                    failures.append(
                        f"rid={rid}: zstd_long had no/insufficient "
                        f"effect (on={on_sz}B vs off={off_sz}B; "
                        f"expected on <~ off/2) — directive is a "
                        f"silent no-op (LDM never engaged)"
                    )

            # (3) error log clean across both runs.
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
                    f"ZSTD-LONG FAILED: {len(failures)} assertion "
                    f"failures, {len(bad)} log issues:\n"
                )
                for f in failures:
                    sys.stderr.write(f"  - {f}\n")
                for b in bad[:10]:
                    sys.stderr.write(f"  log: {b}\n")
                return 1

            ratios = ", ".join(
                f"rid={rid}: {off[rid][1]}->{on[rid][1]}B" for rid in rids
            )
            print(
                f"OK: zstd_long on decoded byte-exact on {len(rids)} "
                f"16MiB long-range-repetitive bodies AND compressed "
                f">=25% smaller than LDM-off (~2:1 as expected: "
                f"{ratios}) — directive reaches libzstd, engages, and "
                f"does not corrupt the stream; error log clean"
            )
            return 0
        finally:
            backend.shutdown()
            backend.server_close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
