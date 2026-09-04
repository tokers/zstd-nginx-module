#!/usr/bin/env python3
"""Effect test: ``zstd_dict_file`` + ``zstd_window_log`` bound the window.

TEST 38 in t/00-filter.t only proves a window-capped stream still decodes;
it never inspects the frame, so a silently ignored ``ZSTD_c_windowLog``
(e.g. a CDict path that resets parameters) would pass it. This test parses
the RFC 8878 frame header of a response compressed WITH a trained
dictionary and a ``zstd_window_log 15`` cap and asserts:

1. the frame is not Single_Segment (a chunked body must carry a
   Window_Descriptor);
2. the declared window is <= 2^15 bytes — the directive actually reached
   libzstd on the dictionary code path (audit C2/R1 regression);
3. the frame references the trained dictionary's real dictID, and only
   ``zstd -d -D <dict>`` can decode it byte-exact (plain ``zstd -d``
   must refuse) — the CDict engaged, we did not fall back to dictless
   compression.
"""

import argparse
import http.server
import os
import pathlib
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

BODY_SIZE = 1024 * 1024  # >> 2^15 so the cap is load-bearing
WINDOW_LOG = 15

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
DICT_MAGIC = b"\x37\xa4\x30\xec"


def parse_args():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--static-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18104)
    p.add_argument("--backend-port", type=int, default=18105)
    return p.parse_args()


def detect(explicit, nginx: pathlib.Path, name: str):
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def make_payload() -> bytes:
    """Compressible body: repeated structured records with a counter."""
    out = bytearray()
    i = 0
    while len(out) < BODY_SIZE:
        out += (
            b'{"record":%08d,"name":"window-cap-effect-test",'
            b'"path":"/var/lib/example/data/%04d/blob.bin",'
            b'"flags":["a","b","c"],"pad":"%s"}\n' % (i, i % 1000, b"x" * (i % 37))
        )
        i += 1
    return bytes(out[:BODY_SIZE])


def train_dict(zstd_bin: str, work: pathlib.Path) -> pathlib.Path:
    """Train a real dictionary (nonzero dictID) on payload-like samples."""
    samples = work / "samples"
    samples.mkdir()
    payload = make_payload()
    n, step = 64, len(make_payload()) // 64
    for k in range(n):
        (samples / f"s{k:03d}").write_bytes(payload[k * step : (k + 1) * step])
    dict_path = work / "test.dict"
    r = subprocess.run(
        [
            zstd_bin,
            "--train",
            *sorted(str(f) for f in samples.iterdir()),
            "-o",
            str(dict_path),
            "--maxdict=16384",
            "-q",
        ],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0 or not dict_path.exists():
        raise RuntimeError(
            "zstd --train failed: " + r.stderr.decode("utf-8", "replace")
        )
    raw = dict_path.read_bytes()
    if raw[:4] != DICT_MAGIC:
        raise RuntimeError("trained dict lacks dictionary magic")
    return dict_path


def dict_id(dict_path: pathlib.Path) -> int:
    return struct.unpack("<I", dict_path.read_bytes()[4:8])[0]


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    payload = b""

    def log_message(self, *a):
        pass

    def do_GET(self):
        # Chunked (no Content-Length) so the filter cannot take the
        # pledged-src-size / Single_Segment path.
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
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


def wait_port(port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def parse_frame_header(blob: bytes):
    """Return (single_segment, window_size_or_None, dict_id_or_0)."""
    if len(blob) < 10:
        raise RuntimeError(
            f"truncated response: {len(blob)} bytes is too "
            "short for a zstd frame header"
        )
    if blob[:4] != ZSTD_MAGIC:
        raise RuntimeError(f"no zstd magic (hex={blob[:8].hex()})")
    fhd = blob[4]
    did_flag = fhd & 0x03
    single_segment = bool(fhd & 0x20)
    pos = 5
    window = None
    if not single_segment:
        wd = blob[pos]
        pos += 1
        exp, mantissa = wd >> 3, wd & 7
        base = 1 << (10 + exp)
        window = base + (base // 8) * mantissa
    did_size = (0, 1, 2, 4)[did_flag]
    did = int.from_bytes(blob[pos : pos + did_size], "little") if did_size else 0
    return single_segment, window, did


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

    payload = make_payload()
    _Handler.payload = payload

    # Everything below must stay readable by the workers when run as
    # root (they drop to the compiled-in nginx user): a restrictive
    # inherited umask (e.g. 077) would strip group/other bits from
    # every fixture and subdir created here, 403ing the workers even
    # with the scratch root itself opened up.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-wincap-") as td:
        # mkdtemp gives 0700: run as root, workers drop to the
        # compiled-in nginx user and cannot enter it -> 403s
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        logs = root / "logs"
        logs.mkdir()
        # nginx -p prefix wants these to exist for temp paths
        for d in ("client_body_temp", "proxy_temp"):
            (root / d).mkdir()

        dict_path = train_dict(args.zstd_bin, root)
        did_expected = dict_id(dict_path)
        if did_expected == 0:
            raise RuntimeError("trained dict has dictID 0; cannot assert")

        load = "".join(f"load_module {m};\n" for m in mods)
        conf = root / "nginx.conf"
        conf.write_text(
            f"""{load}worker_processes 1;
error_log {logs}/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/client_body_temp;
    proxy_temp_path {root}/proxy_temp;
    default_type application/octet-stream;
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    zstd_dict_file {dict_path};
    zstd_dict_file_unsafe on;
    zstd_window_log {WINDOW_LOG};
    server {{
        listen 127.0.0.1:{args.port};
        location / {{
            proxy_pass http://127.0.0.1:{args.backend_port}/;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }}
    }}
}}
""",
            encoding="utf-8",
        )

        backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
        threading.Thread(target=backend.serve_forever, daemon=True).start()

        proc = subprocess.Popen(
            [str(nginx), "-p", str(root) + "/", "-c", str(conf), "-g", "daemon off;"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            wait_port(args.port)

            req = urllib.request.Request(
                f"http://127.0.0.1:{args.port}/blob",
                headers={"Accept-Encoding": "zstd", "User-Agent": "zstd-wincap/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                ce = (resp.headers.get("Content-Encoding") or "").lower()
                if ce != "zstd":
                    raise RuntimeError(f"not zstd-encoded (C-E={ce!r})")
                blob = resp.read()

            single, window, did = parse_frame_header(blob)

            if single:
                raise RuntimeError(
                    "frame is Single_Segment: no Window_Descriptor, the "
                    "window equals the full content size — cap not applied"
                )
            cap = 1 << WINDOW_LOG
            if window > cap:
                raise RuntimeError(
                    f"declared window {window} exceeds zstd_window_log "
                    f"cap {cap} — directive ignored on the dict path"
                )
            if did != did_expected:
                raise RuntimeError(
                    f"frame dictID {did} != trained dict {did_expected} — "
                    "CDict not engaged"
                )

            # Dictless decode must refuse (frame demands the dict) ...
            r = subprocess.run(
                [args.zstd_bin, "-dq", "-c"],
                input=blob,
                capture_output=True,
                check=False,
            )
            if r.returncode == 0:
                raise RuntimeError(
                    "decoded WITHOUT the dictionary — dict not actually load-bearing"
                )
            # ... and dict-aware decode must round-trip byte-exact.
            r = subprocess.run(
                [args.zstd_bin, "-dq", "-c", "-D", str(dict_path)],
                input=blob,
                capture_output=True,
                check=False,
            )
            if r.returncode != 0:
                raise RuntimeError(
                    "zstd -d -D failed: " + r.stderr.decode("utf-8", "replace")
                )
            if r.stdout != payload:
                raise RuntimeError("dict decode not byte-exact")

            print(
                f"✓ window {window} <= {cap} (log {WINDOW_LOG}), "
                f"dictID {did} engaged, {len(blob)} compressed bytes "
                f"round-trip {len(payload)} exactly"
            )
            return 0
        finally:
            proc.terminate()
            try:
                # 30s, not 10: gcov-instrumented nginx flushing .gcda
                # at exit on a loaded runner can outlive a tight reap
                # budget; teardown runs after the verdict, so patience
                # costs nothing when healthy.
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
            backend.shutdown()
            err = logs / "error.log"
            if err.exists():
                tail = err.read_text(errors="replace").strip()
                if "[error]" in tail or "[crit]" in tail:
                    print("error.log tail:\n" + tail[-2000:], file=sys.stderr)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - top-level guard: any failure in a
        # test tool is a test failure, and the message is the diagnosis.
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
