#!/usr/bin/env python3
"""Couples a dcz (RFC 9842) request to the CCtx memory budget and the ring key.

A dcz request does not compress at ``zstd_window_log``: it derives its own
window from the negotiated dictionary, up to 2^23. Two consequences had no
test at all before this one, and both are asserted here against the bytes on
the wire and against the module's own reuse witnesses:

1. RING PARTITION. The worker CCtx ring keys each slot on the memory-affecting
   profile (level, long mode, window log) because ``ZSTD_sizeof_CCtx()`` never
   shrinks on reset. Keying a dcz request on the *unset* directive let it
   borrow a slot vetted for a small window and permanently raise that slot's
   retained workspace; every later plain request matching the same key then
   reused a context whose floor was the dcz figure. A dcz request and a plain
   request on the SAME location must therefore land in DIFFERENT slots.

   Asserted from the ``zstd: reusing worker cctx ... (slot:N) ... window_log:W``
   debug witnesses, which print the slot index and the profile the slot was
   built for -- the key is reversible precisely so tests can read it back.
   This is a real oracle rather than a byte comparison: both requests decode
   correctly either way, so only the slot identity distinguishes the fixed
   code from the broken code.

2. BUDGET CLAMP. ``zstd_max_cctx_memory`` is vetted at config load against
   ``zstd_window_log`` only, so the dcz window walked straight through it
   (measured, libzstd 1.5.7 level 3: 3 663 393 B at the default window vs
   9 954 849 B at wlog 23). With a budget set, the declared window in the dcz
   frame header must not exceed the budget-derived cap.

3. DEFAULT UNCHANGED. The clamp is opt-in. With neither ``zstd_window_log``
   nor ``zstd_max_cctx_memory`` set, the dcz window must still be the
   dictionary-derived one -- the regression guard for that scoping decision,
   without which the "fix" would quietly change wire bytes for everyone.

Needs an nginx built --with-debug: the ring witnesses are debug log lines.
"""

import argparse
import base64
import hashlib
import http.server
import os
import pathlib
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

DCZ_MAGIC = bytes([0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00])
DCZ_HEADER_LEN = 40  # 8-byte skippable magic + 32-byte dict hash
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# The dcz window is ceil_log2(dict + content). 4 MB dictionary + 4 MB body is
# 2^23 exactly, so with no ceiling the derived window saturates at
# NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG -- the worst case the budget escape was
# measured at, and comfortably above anything a budget can permit.
DICT_SIZE = 4 * 1024 * 1024
BODY_SIZE = 4 * 1024 * 1024

COMP_LEVEL = 3

# What the dictionary + body demand with no ceiling configured: the RFC 9842
# cap itself.
UNCLAMPED_WLOG = 23

# Measured, libzstd 1.5.7, ZSTD_estimateCStreamSize_usingCCtxParams at level 3:
#
#     window log   estimate
#     (unset)       3 663 393
#     20            2 614 817
#     21            3 663 393
#     22            5 760 545
#     23            9 954 849
#
# The budget must clear the DEFAULT-window estimate or the pre-existing
# nginx -t gate rejects the configuration before any of this runs -- that gate
# vets conf->window_log, and it is not what this test is about. 4 000 000 B
# clears 3 663 393 B, so the config loads, and the largest window log that
# still fits it is 21 -- two steps below the 23 the dictionary asks for, which
# is what makes the assertion able to fail rather than pass by construction.
BUDGET = 4_000_000
BUDGET_EXPECTED_WLOG = 21

REUSE_RE = re.compile(
    r"zstd: reusing worker cctx \S+ \(slot:(\d+)\) "
    r"level:(-?\d+) long:(\d+) window_log:(\d+)"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--port", type=int, default=18160)
    p.add_argument("--backend-port", type=int, default=18162)
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def make_dict() -> bytes:
    """A raw dcz dictionary. RFC 9842 type=raw: any bytes are legal, and the
    module references them with ZSTD_CCtx_refPrefix, so no training needed."""
    out = bytearray()
    i = 0
    while len(out) < DICT_SIZE:
        out += b'{"tok":%08d,"kind":"dcz-budget-ring-fixture"}\n' % i
        i += 1
    return bytes(out[:DICT_SIZE])


def make_body() -> bytes:
    """Body that shares structure with the dictionary, so dcz genuinely wins
    and the response is a dcz frame rather than a fallback."""
    out = bytearray()
    i = 0
    while len(out) < BODY_SIZE:
        out += b'{"tok":%08d,"kind":"dcz-budget-ring-fixture"}\n' % (i + 7)
        i += 1
    return bytes(out[:BODY_SIZE])


class _Handler(http.server.BaseHTTPRequestHandler):
    """Chunked origin.

    A static file gives nginx a Content-Length, which becomes libzstd's
    pledged source size, and libzstd then emits a Single_Segment frame with
    NO Window_Descriptor -- the declared window is unreadable and the whole
    oracle collapses. Proxying a chunked body is what keeps the window
    observable, the same reason test_window_cap.py does it.
    """

    protocol_version = "HTTP/1.1"
    payload = b""

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        mv = memoryview(self.payload)
        for i in range(0, len(mv), 16384):
            c = bytes(mv[i : i + 16384])
            self.wfile.write(b"%X\r\n" % len(c) + c + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")


class _Srv(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def wait_port(port: int, timeout: float = 15.0) -> None:
    import socket

    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def frame_window(body: bytes, expect_dcz: bool) -> int:
    """Declared window size from the zstd frame header (RFC 8878 3.1.1.1)."""
    if expect_dcz:
        if body[:8] != DCZ_MAGIC:
            raise RuntimeError(f"not a dcz body (hex={body[:8].hex()})")
        blob = body[DCZ_HEADER_LEN:]
    else:
        blob = body
    if blob[:4] != ZSTD_MAGIC:
        raise RuntimeError(f"no zstd magic (hex={blob[:8].hex()})")
    fhd = blob[4]
    if fhd & 0x20:
        raise RuntimeError(
            "frame is Single_Segment: it carries no Window_Descriptor, so "
            "the window cannot be read -- the fixture must stay chunked"
        )
    wd = blob[5]
    exp, mantissa = wd >> 3, wd & 7
    base = 1 << (10 + exp)
    return base + (base // 8) * mantissa


def fetch(port: int, path: str, dcz: bool, dict_bytes: bytes):
    headers = {"Accept-Encoding": "zstd", "User-Agent": "zstd-dcz-budget/1.0"}
    if dcz:
        digest = hashlib.sha256(dict_bytes).digest()
        b64 = base64.b64encode(digest).decode("ascii")
        headers["Accept-Encoding"] = "zstd, dcz"
        headers["Available-Dictionary"] = f":{b64}:"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return (resp.headers.get("Content-Encoding") or "identity").strip(), resp.read()


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary).resolve()
    mods = [
        m
        for m in (
            detect(args.filter_module, nginx, "ngx_http_zstd_filter_module.so"),
            detect(args.static_module, nginx, "ngx_http_zstd_static_module.so"),
        )
        if m
    ]

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"ok   - {name}")
        else:
            print(f"FAIL - {name}: {detail}")
            failures.append(name)

    dict_bytes = make_dict()
    body = make_body()

    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-dczbudget-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        (root / "html").mkdir()
        for d in ("client_body_temp", "proxy_temp"):
            (root / d).mkdir()
        dict_path = root / "dcz.dict"
        dict_path.write_bytes(dict_bytes)
        # Served from disk; nginx sends it chunked-free but with a
        # Content-Length. pledged_size is then known, and the derived window
        # is ceil_log2(dict + content) either way.
        (root / "html" / "app.js").write_bytes(body)

        load = "".join(f"load_module {m};\n" for m in mods)
        conf = root / "nginx.conf"
        conf.write_text(
            f"""{load}worker_processes 1;
error_log {root}/logs/error.log debug;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/client_body_temp;
    proxy_temp_path {root}/proxy_temp;
    types {{ application/javascript js; }}
    default_type application/octet-stream;
    zstd on;
    zstd_comp_level {COMP_LEVEL};
    zstd_min_length 64;
    zstd_types application/javascript;
    zstd_dcz_dict_file {dict_path};
    zstd_dcz_assume_secure_transport on;

    # No zstd_window_log and no zstd_max_cctx_memory: the DEFAULT config,
    # where the dcz window must be exactly what it always was and the only
    # thing that changes is which ring slot it uses.
    server {{
        listen 127.0.0.1:{args.port};
        location / {{
            proxy_pass http://127.0.0.1:{args.backend_port}/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}

    # Same location shape, plus an explicit memory budget. This is the only
    # configuration in which the dcz window is allowed to move.
    server {{
        listen 127.0.0.1:{args.port + 1};
        zstd_max_cctx_memory {BUDGET};
        location / {{
            proxy_pass http://127.0.0.1:{args.backend_port}/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
""",
            encoding="utf-8",
            newline="\n",
        )

        _Handler.payload = body
        backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()

        proc = subprocess.Popen(
            [str(nginx), "-p", str(root) + "/", "-c", str(conf), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            wait_port(args.port)

            # --- 3. default config: dcz window unchanged -----------------
            ce, dcz_body = fetch(args.port, "/app.js", True, dict_bytes)
            check("default config negotiates dcz", ce == "dcz", f"C-E={ce!r}")
            if ce == "dcz":
                w = frame_window(dcz_body, True)
                check(
                    "default config: dcz window is the dictionary-derived one",
                    w == 1 << UNCLAMPED_WLOG,
                    f"declared window {w}, want {1 << UNCLAMPED_WLOG} "
                    f"(2^{UNCLAMPED_WLOG}) -- an opt-in clamp leaked into the "
                    "default configuration",
                )

            # A plain request on the SAME location, twice, so the second is a
            # reuse witness naming the slot the plain profile settled in.
            for _ in range(2):
                ce_p, _plain_body = fetch(args.port, "/app.js", False, dict_bytes)
            check(
                "same location also serves plain zstd", ce_p == "zstd", f"C-E={ce_p!r}"
            )

            # And the dcz request again, so it too produces a reuse witness.
            fetch(args.port, "/app.js", True, dict_bytes)

            # --- 2. budget clamp ----------------------------------------
            ce_b, budget_body = fetch(args.port + 1, "/app.js", True, dict_bytes)
            check("budgeted location negotiates dcz", ce_b == "dcz", f"C-E={ce_b!r}")
            if ce_b == "dcz":
                wb = frame_window(budget_body, True)
                check(
                    "zstd_max_cctx_memory clamps the dcz window",
                    wb == 1 << BUDGET_EXPECTED_WLOG,
                    f"declared window {wb} != budget-derived cap "
                    f"{1 << BUDGET_EXPECTED_WLOG} (2^{BUDGET_EXPECTED_WLOG}) "
                    f"for zstd_max_cctx_memory {BUDGET} -- the dcz path "
                    "either escaped the vetted budget (over-clamp) or "
                    "clamped tighter than the budget allows (under-clamp)",
                )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)

        # --- 1. ring partition ------------------------------------------
        log = (root / "logs" / "error.log").read_text(errors="replace")
        witnesses = REUSE_RE.findall(log)
        if not witnesses:
            check(
                "ring reuse witnesses present",
                False,
                "no 'reusing worker cctx' lines -- nginx is not built "
                "--with-debug, or the cache never engaged",
            )
        else:
            check("ring reuse witnesses present", True)
            # slot -> set of window_logs that slot was keyed for
            by_slot: dict[str, set[str]] = {}
            for slot, _lvl, _lng, wlog in witnesses:
                by_slot.setdefault(slot, set()).add(wlog)
            wlogs = {w for s in by_slot.values() for w in s}

            # The STRONG form, and the weak one is not good enough here.
            # "at least two slots exist and at least two window logs appear"
            # is an aggregate over the whole log: it cannot tell the fixed
            # behaviour (slot A keyed only on the dcz window, slot B keyed
            # only on the plain one) from a regression in which one slot was
            # keyed on the plain window and LATER re-keyed by a dcz request,
            # which is exactly the contamination under test. Two servers run
            # in this one worker, so both aggregate counts are inflated for
            # reasons unrelated to the property anyway.
            #
            # A slot is never re-parameterised, so every witness for a given
            # slot must report the SAME window log. More than one window log
            # on a single slot is the contamination itself, visible directly.
            mixed = {s: sorted(w) for s, w in by_slot.items() if len(w) > 1}
            check(
                "no ring slot is keyed on more than one window log",
                not mixed,
                f"slot(s) re-keyed mid-run: {mixed} -- a dcz request borrowed "
                "a slot vetted for another window and raised its retained "
                "workspace permanently",
            )

            # And the two profiles must actually be present, in slots of
            # their own: the dcz window (unclamped, on the default server)
            # and the plain "unset" 0. Without this a run in which dcz never
            # negotiated would satisfy the check above vacuously.
            dcz_slots = {s for s, w in by_slot.items() if str(UNCLAMPED_WLOG) in w}
            plain_slots = {s for s, w in by_slot.items() if "0" in w}
            check(
                "dcz and plain requests occupy DIFFERENT ring slots",
                bool(dcz_slots) and bool(plain_slots) and not (dcz_slots & plain_slots),
                f"witnesses {witnesses!r}: slots keyed on the dcz window "
                f"{UNCLAMPED_WLOG} = {sorted(dcz_slots)}, slots keyed on the "
                f"unset window 0 = {sorted(plain_slots)}; want both non-empty "
                "and disjoint. A dcz request keyed on the unset "
                "zstd_window_log shares the plain slot and raises its "
                "retained workspace permanently",
            )
            check(
                "the dcz slot is keyed on the dcz window, not the unset one",
                str(UNCLAMPED_WLOG) in wlogs,
                f"window_logs seen in the ring: {sorted(wlogs)}; expected one "
                f"slot keyed on {UNCLAMPED_WLOG}",
            )

    if failures:
        print(f"\nFAILED {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("\nOK: dcz budget + ring key")
    return 0


if __name__ == "__main__":
    sys.exit(main())
