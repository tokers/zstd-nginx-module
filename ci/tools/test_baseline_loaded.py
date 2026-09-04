#!/usr/bin/env python3
"""Baseline: the zstd filter module is actually loaded and blocking.

Every other live-server driver in ci/tools/ (test_reload_under_load.py,
test_concurrent_cctx_isolation.py, ...) asserts a *property* of zstd
compression under some stressor -- reload, concurrency, a timing race.
None of them prove the module ran at all versus, say, a config that
silently no-ops zstd and serves identity responses that happen to also
pass every other assertion in isolation. ci/t/00-filter.t covers this in
the Test::Nginx layer already, but per PR2 step 22 the driver keeps its
own loaded-and-blocking control too: without it, a module that failed to
load reads as a run of green concurrency/reload cases, because none of
them individually depend on compression actually having happened -- they
mostly assert response *correctness*, which an unmodified passthrough of
a small enough body can also satisfy by accident (Content-Length equal,
bytes identical, decode step skipped by a permissive comparison).

Two configs, same backend, same request:
  * WITH `zstd on;` (module present, static --add-module build)      -> the
    filter module is expected to compress: Content-Encoding: zstd and
    zstd-magic body bytes.
  * WITHOUT any zstd directive at all (module compiled in, but no
    directive turns it on)                                            -> the
    response must NOT be zstd-encoded: this is the compiled-in-default
    case (see grind worker-contract's warning on default-flip
    reachability -- an opt-in module must default OFF).

The interesting failure mode this catches is not "module missing" (that
fails to configure/build at all) but "module present, and something
makes it decide not to act" -- a decision-flip bug in the accept/ok
predicates step 21 unit-tests, exercised here end-to-end through a real
request instead of directly.

Requires an nginx binary built --add-module (static) with the zstd
filter module, plus the `zstd` CLI for the magic-byte / decode check.
"""

from __future__ import annotations

import argparse
import http.server
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

BODY = b"BASELINE." * 4096  # 36KB, well above zstd_min_length, compressible
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Baseline: module loaded and blocking (PR2 step 22)."
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18110)
    p.add_argument("--off-port", type=int, default=18112)
    p.add_argument("--backend-port", type=int, default=18111)
    return p.parse_args()


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        # text/html: the module's compiled-in default `zstd_types` value
        # (src/ngx_http_zstd_filter_module.c ~line 235). Using anything
        # else would make the "no directive" case decline on the
        # content-type gate regardless of the `enable` default, which
        # would mask -- not exercise -- the enable-default mutation this
        # baseline exists to catch.
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)


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


def run_one(
    nginx: pathlib.Path, port: int, backend_port: int, zstd_directive: str
) -> tuple[bool, bool, bytes]:
    """Start nginx with (or without) the zstd directive, fetch once,
    return (advertised_zstd, payload_is_zstd, raw_body).

    The header and the payload are reported SEPARATELY on purpose. Collapsing
    them into one boolean makes the default-off case unable to distinguish
    "no Content-Encoding" from "advertised zstd but sent something else" --
    the second is a real bug and would read as a pass.
    """
    with tempfile.TemporaryDirectory(prefix="zstd-baseline-") as td:
        root = pathlib.Path(td)
        logs = root / "logs"
        logs.mkdir()
        pid_file = root / "nginx.pid"
        conf = root / "nginx.conf"
        conf.write_text(
            f"""master_process off;
error_log {logs}/error.log warn;
pid {pid_file};
events {{ worker_connections 32; }}
http {{
    access_log off;
    default_type application/octet-stream;
    {zstd_directive}
    server {{
        listen 127.0.0.1:{port};
        location / {{
            proxy_pass http://127.0.0.1:{backend_port}/;
        }}
    }}
}}
""",
            encoding="utf-8",
        )

        proc = subprocess.Popen(
            [str(nginx), "-p", str(root), "-c", str(conf), "-g", "daemon off;"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_port(port)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/", headers={"Accept-Encoding": "zstd"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                ce = (resp.headers.get("Content-Encoding") or "").lower()
                blob = resp.read()
            advertised = ce == "zstd"
            payload_is_zstd = blob[:4] == ZSTD_MAGIC
            return advertised, payload_is_zstd, blob
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    backend = _Srv(("127.0.0.1", args.backend_port), _Handler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    try:
        wait_port(args.backend_port)

        # Case 1: zstd explicitly enabled -> must compress.
        on_adv, on_payload, on_body = run_one(
            nginx,
            args.port,
            args.backend_port,
            "zstd on; zstd_comp_level 3; zstd_min_length 1;",
        )
        if not (on_adv and on_payload):
            print(
                "FAIL baseline: 'zstd on;' did not produce a "
                "zstd-encoded response -- the module is not blocking "
                "as expected",
                file=sys.stderr,
            )
            return 1
        r = subprocess.run(
            [args.zstd_bin, "-dq", "-c"],
            input=on_body,
            capture_output=True,
            check=False,
        )
        if r.returncode != 0 or r.stdout != BODY:
            print(
                "FAIL baseline: 'zstd on;' response does not decode "
                "byte-exact to the origin body",
                file=sys.stderr,
            )
            return 1
        print("ok   'zstd on;' compresses and decodes byte-exact")

        # Case 2: no zstd directive at all -> compiled-in default is OFF,
        # response must NOT be zstd-encoded (see grind worker-contract's
        # reachability warning: an opt-in module defaulting ON would make
        # this pass vacuously).
        # Deliberately its OWN port, distinct from both --port and
        # --backend-port: colliding with the backend's listening socket
        # here silently routes the client straight to the backend,
        # bypassing nginx (and the module) entirely -- the request would
        # still get a non-zstd response, but for the wrong reason, and
        # the check would pass even if `enable`'s default were flipped.
        # (Caught exactly this way during the mutation pass, see
        # ci/adoption-findings.md.)
        off_adv, off_payload, off_body = run_one(
            nginx, args.off_port, args.backend_port, ""
        )
        # Either half is a failure on its own. Advertising zstd without a zstd
        # payload is not "safely off", it is a lie to the client.
        if off_adv or off_payload:
            print(
                "FAIL baseline: response was zstd-encoded with NO "
                "zstd directive present -- compiled-in default is not "
                f"OFF (Content-Encoding: zstd={off_adv}, "
                f"zstd magic in body={off_payload})",
                file=sys.stderr,
            )
            return 1
        if off_body != BODY:
            print(
                "FAIL baseline: undirected response body does not "
                "match origin (proxy path itself broken, unrelated to "
                "zstd)",
                file=sys.stderr,
            )
            return 1
        print(
            "ok   no zstd directive -> compiled-in default is OFF, "
            "origin body served unmodified"
        )

        print("\n2/2 checks passed")
        return 0
    finally:
        backend.shutdown()


if __name__ == "__main__":
    sys.exit(main())
