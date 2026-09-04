#!/usr/bin/env python3
"""Regression test: sub_filter partial-match sync bufs must not reset the
zstd CCtx mid-stream.

Background
----------
The body filter used to infer "first body data for this request" from
``ctx->buffer_in.src == NULL``, but ``add_data`` reloads ``buffer_in.src``
from every incoming buffer. ``ngx_http_sub_filter`` emits a data-less sync
carrier (``pos == NULL``) whenever an in-memory input buffer is entirely
absorbed into a cross-buffer match candidate and produces no output that
call. Loading that carrier re-armed the old first-call check, so the next
invocation re-ran ``ZSTD_CCtx_reset()`` mid-stream and everything libzstd
had buffered but not yet flushed was silently discarded. The response
still ended as ONE well-formed frame (200 + valid zstd), just missing the
pre-reset content. Seen in production as truncated HTML on
sub_filter-rewritten pages fed by a slow chunked upstream. Fixed by an
explicit ``cctx_ready`` latch instead of inferring lifecycle state from a
data pointer.

Why ci/t/00-filter.t TEST 92 does not detect this
--------------------------------------------------
That test relies on Test::Nginx's ``tcp_reply_delay`` + an array-form
``tcp_reply`` to model three separate upstream chunks. Measured (see
memory/labs/http-zstd/issues.md, 2026-08-13): the harness sleeps ONCE
before the whole array, then writes every element back-to-back in a tight
loop with no pause between ``$client->send()`` calls. Locally the three
segments arrive COALESCED -- 2 body-filter invocations for 3 requests, not
the 3-per-request the test's three delayed segments assume -- so the
mid-stream carrier this bug needs never occurs; the test passes against
BOTH the pre-fix and the fixed module and pins the contract without
detecting a regression in it.

This test reproduces the same production trigger a different way: a raw
socket backend that ``send()``s each chunk as its own syscall with a
real sleep in between, through ``proxy_buffering off`` (which forwards
each upstream read immediately instead of coalescing them), so nginx's
event loop genuinely dispatches three separate reads. The body-filter
invocation count is read back from ``error_log debug`` -- counting
invocations, not assuming chunk boundaries, per the coalescing trap this
test exists to avoid repeating.

It MUST fail (decoded body missing the pre-reset content, or a decode
error) on a module with the old ``buffer_in.src == NULL`` first-call
check, and pass with the ``cctx_ready`` fix.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

FROM = "http://upstream.example"
TO = "https://very-long-replacement-host.example"

# seg2 lies strictly inside FROM: absorbed into the sub_filter match
# candidate with no output on its own call, producing the data-less sync
# carrier the bug needs.
SEG1 = b"EARLY-CONTENT that must survive the match holdback http://up"
SEG2 = b"stream.exa"
SEG3 = b"mple/path LATE-CONTENT after the match completes\n"

EXPECTED_BODY = (
    b"EARLY-CONTENT that must survive the match holdback "
    + TO.encode()
    + b"/path LATE-CONTENT after the match completes\n"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Regression test for the sub_filter mid-stream CCtx-reset "
            "truncation bug (uncoalesced backend reads)."
        )
    )
    p.add_argument("--nginx-binary", required=True)
    p.add_argument("--filter-module")
    p.add_argument("--zstd-bin", default="zstd")
    p.add_argument("--port", type=int, default=18096)
    p.add_argument("--backend-port", type=int, default=18097)
    p.add_argument(
        "--chunk-delay",
        type=float,
        default=0.15,
        help="Seconds slept between each backend send() call.",
    )
    p.add_argument("--repeat", type=int, default=3)
    p.add_argument(
        "--log-level",
        choices=("debug", "warn"),
        default="debug",
        help="Location error_log level. The invocation-count harness "
        "-integrity guard only runs at debug (it counts 'http zstd "
        "filter' lines). Use warn under sanitizer builds: UBSAN "
        "(-fno-sanitize-recover) fatally traps nginx core's own "
        "debug logging, so a sanitized nginx cannot log at debug at "
        "all -- see ci/tools/test_slow_drain.py's --log-level for the "
        "same trap. The body round-trip assertion still runs either "
        "way; only the coalescing self-check is skipped at warn.",
    )
    return p.parse_args()


def detect_module(explicit: str | None, nginx: pathlib.Path) -> pathlib.Path | None:
    """Resolve the filter .so: explicit path, or beside the binary.

    Returns None when neither is present, which is the normal case for a
    STATICALLY linked CI build -- the filter is already in the binary and
    emitting a `load_module` line for it would make nginx refuse to start.
    Same contract as ci/tools/test_slow_drain.py's detect_module().
    """
    if explicit:
        return pathlib.Path(explicit).resolve()
    # resolve(): nginx resolves a relative load_module path against its
    # PREFIX (-p, a temp dir here), not against the cwd, so a relative
    # path dlopen()s from inside the temp dir and fails.
    sib = (nginx.parent / "ngx_http_zstd_filter_module.so").resolve()
    return sib if sib.exists() else None


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


def chunk(data: bytes) -> bytes:
    return b"%x\r\n%s\r\n" % (len(data), data)


def serve_one(sock: socket.socket, delay: float) -> None:
    """Accept connections until one sends an actual request, read it, then
    stream the three chunks as three distinct send() calls with a real
    sleep between each -- the part Test::Nginx's tcp_reply array-send
    cannot do. wait_port()'s own bare probe connect (no data, immediate
    close) is skipped rather than consumed, so it never steals the one
    real request this call is meant to serve."""
    while True:
        conn, _ = sock.accept()
        conn.settimeout(10)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                b = conn.recv(4096)
                if not b:
                    break
                buf += b
        except OSError:
            buf = b""
        if not buf:
            conn.close()
            continue
        break
    try:
        header = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        conn.sendall(header + chunk(SEG1))
        conn.sendall(b"")  # no-op, keeps parity with syscall-per-segment intent
        time.sleep(delay)
        conn.sendall(chunk(SEG2))
        time.sleep(delay)
        conn.sendall(chunk(SEG3) + b"0\r\n\r\n")
    finally:
        conn.close()


_BACKEND_SOCK: socket.socket | None = None


def start_backend_listener(port: int) -> None:
    """Bind+listen once, up front, so wait_port's own probe connect cannot
    be mistaken for -- and consumed by -- a real request in serve_one()."""
    global _BACKEND_SOCK
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(8)
    _BACKEND_SOCK = sock


def accept_one_request(delay: float) -> threading.Thread:
    assert _BACKEND_SOCK is not None
    t = threading.Thread(target=serve_one, args=(_BACKEND_SOCK, delay), daemon=True)
    t.start()
    return t


def http_get_raw(port: int, path: str, timeout: float = 20.0) -> bytes:
    """GET the response and return the fully dechunked body. nginx
    re-chunks the compressed output (the upstream sent no
    Content-Length), so the wire body is HTTP chunked framing wrapping
    the zstd frame, not the zstd frame itself -- urllib's HTTPResponse
    does the dechunking so this stays a plain byte-exact comparison."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Accept-Encoding": "zstd", "Connection": "close"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"unexpected status: {resp.status}")
        if (resp.headers.get("Content-Encoding") or "").lower() != "zstd":
            raise RuntimeError(
                f"missing Content-Encoding: zstd, got "
                f"{resp.headers.get('Content-Encoding')!r}"
            )
        return resp.read()


def zstd_decompress(zstd_bin: str, blob: bytes) -> bytes:
    if blob[:4] != b"\x28\xb5\x2f\xfd":
        raise RuntimeError(f"missing zstd magic; first 16B hex={blob[:16].hex()}")
    r = subprocess.run(
        [zstd_bin, "-d", "-q", "-c"], input=blob, capture_output=True, check=False
    )
    if r.returncode != 0:
        raise RuntimeError(
            "zstd -d failed: " + r.stderr.decode("utf-8", "replace").strip()
        )
    return r.stdout


def count_filter_invocations(error_log: pathlib.Path) -> int:
    if not error_log.exists():
        return 0
    text = error_log.read_text("utf-8", "replace")
    return len(re.findall(r"http zstd filter", text))


def main() -> int:
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(f"nginx binary not found: {nginx}")
    module = detect_module(args.filter_module, nginx)
    if module is not None and not module.exists():
        raise FileNotFoundError(f"module not found: {module}")
    load = f"load_module {module};\n" if module else ""

    with tempfile.TemporaryDirectory(prefix="zstd-subfilter-") as td:
        root = pathlib.Path(td)
        logs = root / "logs"
        logs.mkdir()

        lvl = args.log_level
        conf = root / "nginx.conf"
        conf.write_text(
            f"""{load}worker_processes 1;
error_log {logs}/error.log {lvl};
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type text/plain;
    server {{
        listen 127.0.0.1:{args.port};
        location /filter {{
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            sub_filter '{FROM}' '{TO}';
            sub_filter_once off;
            sub_filter_types text/plain;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_pass http://127.0.0.1:{args.backend_port}/;
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
            try:
                wait_port(args.port)
            except RuntimeError:
                # nginx never listened -- almost always a config-load
                # rejection (a directive whose module is not compiled in,
                # a bad path). Its stderr is the only thing that says
                # WHICH, and it is on the pipe, so surface it instead of
                # letting the bare "nothing listening" hide the cause.
                proc.terminate()
                try:
                    out = proc.communicate(timeout=5)[0] or ""
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out = proc.communicate()[0] or ""
                if out.strip():
                    sys.stderr.write("nginx output:\n")
                    for line in out.strip().splitlines()[:20]:
                        sys.stderr.write(f"  {line}\n")
                raise
            failures: list[str] = []
            start_backend_listener(args.backend_port)

            for attempt in range(1, args.repeat + 1):
                label = f"attempt={attempt}/{args.repeat}"
                backend_thread = accept_one_request(args.chunk_delay)
                try:
                    try:
                        blob = http_get_raw(args.port, "/filter")
                        decoded = zstd_decompress(args.zstd_bin, blob)
                    except Exception as exc:  # noqa: BLE001
                        failures.append(f"{label}: {exc}")
                        continue
                    if decoded != EXPECTED_BODY:
                        failures.append(
                            f"{label}: decoded body mismatch "
                            f"(TRUNCATION/CORRUPTION): got {decoded!r}, "
                            f"expected {EXPECTED_BODY!r}"
                        )
                finally:
                    backend_thread.join(timeout=10)

            invocations = -1
            if args.log_level == "debug":
                invocations = count_filter_invocations(logs / "error.log")
                # This is the harness-integrity guard for this test:
                # fewer than 2 invocations per request means the three
                # backend sends coalesced into a single read after all
                # (the exact failure mode that makes TEST 92 inert) and
                # the run below proves nothing either way. Only checked
                # at --log-level debug (see that flag's help): a
                # sanitizer build cannot log at debug at all, so this
                # guard is skipped there and the body round-trip
                # assertion is the only oracle for that job.
                min_expected = 2 * args.repeat
                if invocations < min_expected:
                    sys.stderr.write(
                        f"HARNESS INTEGRITY FAILURE: only {invocations} "
                        f"'http zstd filter' invocations logged across "
                        f"{args.repeat} requests (need >= {min_expected}); "
                        f"the backend chunks coalesced into fewer reads "
                        f"than intended and this run cannot distinguish "
                        f"the bug from a false pass.\n"
                    )
                    return 2

            invocation_note = (
                f"{invocations} filter invocations observed"
                if args.log_level == "debug"
                else "invocation count not checked at --log-level warn"
            )

            if failures:
                sys.stderr.write(
                    f"sub_filter/CCtx-reset regression FAILED "
                    f"({len(failures)} failing checks), {invocation_note}:\n"
                )
                for f in failures[:20]:
                    sys.stderr.write(f"  - {f}\n")
                return 1

            print(
                f"OK: {args.repeat} sub_filter + proxy_buffering-off zstd "
                f"responses round-tripped byte-exact across uncoalesced "
                f"backend reads ({invocation_note})"
            )
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
