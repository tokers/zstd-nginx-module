#!/usr/bin/env python3
"""Deterministic drivers for the two timing-dependent filter paths.

Ported from the unified-module branch (#117), where the same tool
pins the recycling pause path. The trigger was the coverage floor:
the gcov job's 82% gate assumes two code paths that only ran when CI
load happened to produce the right races, and one run (PR #124,
nginx pin bump) lost every race at once — 8 lines vanished, 82.6%
fell to 81.9%, and an unrelated two-line env change failed the
floor. Comparing that run's lcov tracefile against the previous
green run identified exactly the lines; this tool makes both paths
run on purpose so the floor measures tests, not scheduler luck.

The two paths, and how they are forced:

1. **The nomem entry block** (busy-buffer recovery at the top of the
   body filter): needs ``zstd_buffers`` exhausted while the client
   cannot drain, then a writer-driven re-invocation. A local socket
   drains instantly, which is why no Test::Nginx block can reach it.
   Forced here with ``zstd_buffers 2 8k``, a ~1 MB incompressible
   body, ``sndbuf=16384`` on the listener, a small client-side
   SO_RCVBUF, and deliberately slow reads. Witness:
   "zstd get_buf: no free buffer, nomem set" — plus a byte-exact
   decode proving the pause/resume seams preserved the stream.

2. **The content-less flush completion** (empty out_buf, flush
   pending, encoder fully drained — the #116-era livelock guard):
   needs a flush to reach the filter while the encoder holds
   nothing. nginx's non-buffered upstream path sends exactly that —
   ``ngx_http_upstream_send_response`` emits a data-less
   NGX_HTTP_FLUSH special before relaying any body — but only a
   backend that sends its headers alone and its body strictly later
   makes the special arrive with an empty encoder. The mock backend
   here sleeps between headers and body to guarantee it. Witness:
   "content-less flush completed", once per proxied response.

Requires an nginx binary built ``--with-debug`` (the witnesses are
ngx_log_debug lines) with the zstd filter module, plus the ``zstd``
CLI for decoding.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import typing

DRAIN_SIZE = 1_000_000
READ_CHUNK = 16384
READ_DELAY = 0.02

PROXY_PART = 40_000
PROXY_REPEAT = 8
HEADER_BODY_GAP = 0.3
INTER_PART_GAP = 0.15

NOMEM_WITNESS = "no free buffer, nomem set"
FLUSH_WITNESS = "content-less flush completed"


class WitnessFloor(typing.NamedTuple):
    """One (log substring, human label, minimum occurrence count) row."""

    witness: str
    path_name: str
    floor: int


def parse_args() -> argparse.Namespace:
    """Parse the CLI arguments (binary, module path, ports, zstd CLI)."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--nginx-binary", required=True, help="nginx (or angie) binary to launch."
    )
    p.add_argument(
        "--filter-module",
        help="Path to ngx_http_zstd_filter_module.so "
        "(auto-detected next to the binary if omitted).",
    )
    p.add_argument(
        "--zstd-bin", default="zstd", help="zstd CLI used for decompression."
    )
    p.add_argument("--port", type=int, default=18095, help="Front-end nginx port.")
    p.add_argument(
        "--backend-port",
        type=int,
        default=18096,
        help="Mock slow-headers upstream port.",
    )
    p.add_argument(
        "--log-level",
        choices=("debug", "warn"),
        default="debug",
        help="Location error_log level. Witnesses are only "
        "asserted at debug. Use warn under sanitizer "
        "builds: UBSAN (-fno-sanitize-recover) fatally "
        "traps nginx core's own debug logging — every "
        '"%%V?%%V" line passes r->args={0,NULL} into '
        "ngx_sprintf_str's nonnull argument on "
        "query-less URIs (ngx_string.c:586) — so a "
        "sanitized nginx cannot log at debug at all. "
        "The forced paths still run; only their log "
        "proof is skipped.",
    )
    return p.parse_args()


def detect_module(
    explicit: str | None, nginx: pathlib.Path, name: str
) -> pathlib.Path | None:
    """Resolve a dynamic-module .so: explicit path, or beside the binary."""
    if explicit:
        return pathlib.Path(explicit)
    sib = nginx.parent / name
    return sib if sib.exists() else None


def fixture_bytes(n: int) -> bytes:
    """Deterministic pseudorandom (incompressible) fixture of n bytes."""
    buf = bytearray(n)
    x = (n * 2654435761) & 0xFFFFFFFF
    for i in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        buf[i] = (x >> 16) & 0xFF
    return bytes(buf)


def wait_port(port: int, timeout: float = 10.0) -> None:
    """Block until something accepts connections on 127.0.0.1:port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port}")


class SlowHeaderBackend(threading.Thread):
    """Sends 200 + headers immediately, then the body only after a
    pause — so nginx's non-buffered data-less FLUSH special always
    reaches the filter before a single body byte does."""

    def __init__(self, port: int, body: bytes) -> None:
        """Bind the listener up front so wait-for-port has a target."""
        super().__init__(daemon=True)
        self.port = port
        self.body = body
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(8)

    def run(self) -> None:
        """Accept loop: headers immediately, body in two paused halves."""
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(10)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    piece = conn.recv(4096)
                    if not piece:
                        break
                    buf += piece
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Connection: close\r\n\r\n"
                )
                time.sleep(HEADER_BODY_GAP)
                half = len(self.body) // 2
                conn.sendall(self.body[:half])
                time.sleep(INTER_PART_GAP)
                conn.sendall(self.body[half:])
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self) -> None:
        """Close the listener; the accept loop exits on the next OSError."""
        self.srv.close()


def http_get(port: int, path: str, slow: bool, timeout: float = 120.0) -> bytes:
    """GET path expecting Content-Encoding: zstd; slow=True throttles
    reads through a small SO_RCVBUF to create real backpressure."""
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    if slow:
        # Without a small SO_RCVBUF the kernel buffers the whole
        # compressed response client-side and nginx never feels the
        # backpressure this test exists to create.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    req = f"GET {path} HTTP/1.0\r\nHost: t\r\nAccept-Encoding: zstd\r\n\r\n"
    s.sendall(req.encode("latin1"))
    raw = b""
    while True:
        piece = s.recv(READ_CHUNK)
        if not piece:
            break
        raw += piece
        if slow:
            time.sleep(READ_DELAY)
    s.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = head.decode("latin1", "replace")
    status = headers.splitlines()[0] if headers else "<no response>"
    if " 200 " not in f"{status} ":
        raise RuntimeError(f"{path}: expected 200, got {status!r} ({len(body)}B body)")
    m = re.search(r"(?im)^content-encoding:\s*(\S+)", headers)
    got = m.group(1) if m else None
    if got != "zstd":
        raise RuntimeError(
            f"{path}: Content-Encoding {got!r}, "
            f"wanted 'zstd' (status {status!r}, "
            f"{len(body)}B body)"
        )
    return body


def main() -> int:
    """Launch nginx + mock backend, run both scenarios, check witnesses."""
    args = parse_args()
    nginx = pathlib.Path(args.nginx_binary)
    if not nginx.exists():
        raise FileNotFoundError(nginx)

    v = subprocess.run([str(nginx), "-V"], capture_output=True, text=True, check=False)
    if "zstd" not in v.stderr:
        raise RuntimeError("nginx -V shows no zstd module")
    if "--with-debug" not in v.stderr:
        raise RuntimeError(
            "the witnesses are ngx_log_debug lines: "
            "this tool needs an nginx built --with-debug"
        )

    filter_so = detect_module(
        args.filter_module, nginx, "ngx_http_zstd_filter_module.so"
    )
    load = f"load_module {filter_so};\n" if filter_so else ""

    def decode(blob: bytes) -> bytes:
        """Decompress with the zstd CLI; a nonzero exit means truncation."""
        r = subprocess.run(
            [args.zstd_bin, "-d", "-q", "-c"],
            input=blob,
            capture_output=True,
            check=False,
        )
        if r.returncode != 0:
            raise RuntimeError(
                "zstd decode failed (truncated/corrupt stream): "
                + r.stderr.decode("utf-8", "replace").strip()
            )
        return r.stdout

    drain_body = fixture_bytes(DRAIN_SIZE)
    proxy_body = fixture_bytes(2 * PROXY_PART)
    backend = SlowHeaderBackend(args.backend_port, proxy_body)
    backend.start()

    # mkdtemp gives 0700: when nginx runs as root (the ASAN job) the
    # workers drop privileges and cannot traverse into the fixture
    # tree — /drain/big then serves uncompressed instead of erroring.
    # Same lines the sibling tools carry, dropped once in the port and
    # caught by exactly that job.
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="zstd-drain-") as td:
        os.chmod(td, 0o755)
        root = pathlib.Path(td)
        (root / "logs").mkdir()
        html = root / "html" / "d"
        html.mkdir(parents=True)
        (html / "big").write_bytes(drain_body)

        # The location error_log level is a flag (see --log-level):
        # sanitizer builds fatally trap nginx core's own debug logging
        # (the "%V?%V" lines pass NULL for empty args — latent in core,
        # first hit by this tool because nothing else in CI ran a
        # sanitized binary at debug level), so the ASAN job runs at
        # warn and skips the witness assertions. The forced paths run
        # regardless of log level; the roundtrip oracles keep gating.
        lvl = args.log_level
        conf = root / "nginx.conf"
        conf.write_text(
            f"""worker_processes 1;
{load}error_log {root}/logs/error.log warn;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    default_type application/octet-stream;
    zstd on;
    zstd_min_length 1;
    zstd_types application/octet-stream;
    gzip_vary on;
    server {{
        listen 127.0.0.1:{args.port} sndbuf=16384;
        location /drain/ {{
            error_log {root}/logs/error.log {lvl};
            alias {html}/;
            zstd_buffers 2 8k;
        }}
        location /px {{
            error_log {root}/logs/error.log {lvl};
            proxy_pass http://127.0.0.1:{args.backend_port};
            proxy_buffering off;
        }}
    }}
}}
""",
            encoding="utf-8",
        )

        # nginx's own stdout/stderr to a file, not a PIPE: nothing
        # drains a pipe here (deadlock risk on a chatty ASan abort),
        # and on failure the tail is the diagnosis.
        nlog_path = root / "logs" / "nginx-stdout.log"
        # SIM115 suppressed above: the handle must outlive this block: it is Popen's
        # stdout for the whole server lifetime. A with-block would close it
        # while nginx is still writing.
        nlog = open(nlog_path, "w", encoding="utf-8")  # noqa: SIM115
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
            stdout=nlog,
            stderr=subprocess.STDOUT,
            text=True,
        )

        def alive_or_die(when: str) -> None:
            """Fail with nginx's captured output if the process exited —
            a bind conflict or sanitizer abort otherwise masquerades as
            responses from a stale listener on the same port."""
            if proc.poll() is not None:
                nlog.flush()
                tail = nlog_path.read_text("utf-8", "replace")[-2000:]
                raise RuntimeError(
                    f"nginx exited (rc={proc.returncode}) {when}; output tail:\n{tail}"
                )

        try:
            wait_port(args.port)
            alive_or_die("during startup")
            failures: list[str] = []

            # 1. slow-drain: force the buffer cap and the writer-driven
            #    re-entry through the nomem entry block
            try:
                t0 = time.time()
                body = http_get(args.port, "/drain/big", slow=True)
                took = time.time() - t0
                plain = decode(body)
                if plain != drain_body:
                    failures.append(
                        f"slow-drain: decoded {len(plain)}B, expected "
                        f"{len(drain_body)}B — the pause/resume seams "
                        f"corrupted or truncated the stream"
                    )
                else:
                    print(
                        f"  slow-drain: {len(body)}B compressed drained "
                        f"in {took:.1f}s, decoded byte-exact"
                    )
            except Exception as exc:  # noqa: BLE001
                failures.append(f"slow-drain: {exc}")

            alive_or_die("after the slow-drain scenario")

            # 2. proxied data-less flush: every response starts with the
            #    upstream FLUSH special hitting an empty encoder
            ok = 0
            for i in range(PROXY_REPEAT):
                try:
                    body = http_get(args.port, "/px", slow=False)
                    if decode(body) != proxy_body:
                        failures.append(f"proxy #{i}: decode mismatch")
                        break
                    ok += 1
                except Exception as exc:  # noqa: BLE001
                    failures.append(f"proxy #{i}: {exc}")
                    break
            if ok:
                print(
                    f"  proxy: {ok}/{PROXY_REPEAT} unbuffered responses "
                    f"decoded byte-exact"
                )

            elog = (root / "logs" / "error.log").read_text("utf-8", "replace")
            if args.log_level != "debug":
                print(
                    "  witnesses skipped (--log-level warn: sanitizer "
                    "builds cannot log at debug — paths still forced, "
                    "roundtrips still gate)"
                )
            # The upstream FLUSH special is unconditional per response,
            # so every successful proxied request owes one content-less
            # completion — a lower bound, not an exact pin, because
            # nginx may legally emit further data-less specials
            # mid-relay (and those only log content-less when they too
            # meet an empty encoder). The nomem count depends on drain
            # scheduling, so only its existence is pinned.
            witness_floors: tuple[WitnessFloor, ...] = ()
            if args.log_level == "debug":
                witness_floors = (
                    WitnessFloor(NOMEM_WITNESS, "buffer-cap/nomem", 1),
                    WitnessFloor(FLUSH_WITNESS, "content-less flush", PROXY_REPEAT),
                )
            for witness, path_name, floor in witness_floors:
                n = elog.count(witness)
                if n < floor:
                    failures.append(
                        f"witness short: {witness!r} x{n}, expected at "
                        f"least x{floor} — the {path_name} path did not "
                        f"run as forced (geometry drift, or the "
                        f"filter's debug lines changed)"
                    )
                else:
                    print(f"  witness: {witness!r} x{n}")

            if failures:
                sys.stderr.write(f"slow-drain FAILED ({len(failures)}):\n")
                for f in failures:
                    sys.stderr.write(f"  - {f}\n")
                # CI runs are not reproducible interactively: ship the
                # evidence with the verdict.
                nlog.flush()
                sys.stderr.write("--- nginx stdout/stderr tail:\n")
                sys.stderr.write(nlog_path.read_text("utf-8", "replace")[-2000:] + "\n")
                sys.stderr.write("--- error.log tail (non-debug):\n")
                sys.stderr.write(
                    "\n".join(ln for ln in elog.splitlines() if "[debug]" not in ln)[
                        -3000:
                    ]
                    + "\n"
                )
                return 1

            proof = (
                "witnessed"
                if args.log_level == "debug"
                else "roundtripped (witnesses skipped)"
            )
            print(
                f"OK: forced backpressure and data-less flushes both "
                f"{proof}, streams byte-exact"
            )
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=30)
            nlog.close()
            backend.stop()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
