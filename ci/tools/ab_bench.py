#!/usr/bin/env python3
"""Request-path A/B benchmark harness: drives a real nginx over the zstd
filter under `wrk` load, interleaved between two arms to cancel machine
drift, and reports throughput/latency/RSS per (arm, concurrency, body size).

This is the gating dependency for the CCtx-ring, per-profile-slot,
one-reset-per-request and first-buffer-sizing TODO rows, all of which say
"do NOT guess -- measure". It exists to answer "did this change help, on
what body sizes, at what concurrency" with a number, not a guess.

What it measures
-----------------
- requests/sec, p50 and p99 latency, and peak WORKER (not master) RSS, per
  (arm, concurrency, body-size class), under a real nginx + `wrk` load.
- Two arms (two nginx binaries, or one binary run under two labelled
  configs) run in INTERLEAVED rounds -- not sequentially -- because a
  sequential A-then-B run confounds the comparison with machine drift
  (thermal throttling, background load, cache warmth). The existing
  worker-CCtx-cache +79% measurement used exactly this: 3 interleaved
  rounds. Reported numbers are the per-arm MEDIAN across rounds, plus the
  delta.
- Body-size mix matters and is never collapsed into one number: the +79%
  win above was measured on 8 KB bodies and was ZERO on 64 KB, where
  compression itself dominates. Defaults to both sizes, reported
  separately, specifically so nobody can quote a blanket speedup that
  doesn't hold at every size.

Why bodies are proxied through a paced backend, not served static
-------------------------------------------------------------------
The worker-lifetime CCtx loan (acquire_cctx sets the busy flag; only
request CLEANUP clears it -- src/ngx_http_zstd_filter_module.c:1847 and
:2896) is held for the FULL lifetime of one compression, so two
compressions only contend when their lifetimes actually overlap on one
worker. A location serving a static, fully-buffered, known-length body
from page cache completes inside a single event-loop turn; `wrk`
connections then queue rather than overlap, and every concurrency in the
sweep reports the same meaningless 100% hit rate with worker RSS that
never moves -- indistinguishable, from the debug pass's own numbers,
from a real single-slot cache never actually contending. An earlier
version of this harness did exactly that and it was caught in review
before the numbers were trusted.

Every body is therefore served by PacedBackend: a mock upstream, proxied
with `proxy_buffering off`, that sends chunked-transfer headers
immediately and then the body in small pieces with a short sleep between
each. The filter's compression session for one response stays open
across many event-loop turns while other connections are being
accepted, so a second concurrent request can reach acquire_cctx while
the first still holds the loan -- the only way this workload can
demonstrate the contention the ring-sizing row is about.

The harness self-checks this rather than trusting it: the debug pass
requires the hit rate at the LOWEST swept concurrency to be measurably
higher than at the HIGHEST -- a relative fall, because "decays toward
1/N" is itself a relative claim -- plus an absolute floor on `created`
witnesses at the highest concurrency, and raises a RuntimeError (harness
error, non-zero exit) if either does not hold. A flat 100% hit rate at
every concurrency is never printed as a result -- it is either real
contention whose hit rate genuinely falls with concurrency, which the
self-check has independently confirmed, or the self-check itself fails
loudly instead.

What it deliberately does NOT do
---------------------------------
- It does NOT report a cache-engagement hit rate alongside release
  throughput. The reuse/create witnesses
  ("zstd: reusing worker cctx" / "zstd: created cctx") are ngx_log_debug
  lines that only exist in a --with-debug build's debug-level log, and
  emitting them under 128-connection load would distort the very
  throughput being measured. The harness therefore runs the RELEASE pass
  (throughput/latency/RSS, error_log at `warn`) and the DEBUG pass (witness
  counts and hit rate, error_log at `debug`, only if a --with-debug binary
  is supplied) as two structurally separate passes with separate result
  sections -- see BenchResult vs WitnessResult below -- so it is not
  possible to accidentally print one pass's numbers as if measured
  together with the other's. If only a release-mode binary is given, the
  hit rate is reported as unmeasured, never inferred.
- It does NOT trust a flat hit rate. See "Why bodies are proxied" above --
  the debug pass's own self-check must independently prove contention
  happened before its numbers are printed at all.
- It is not a pass/fail gate on the MODULE's performance. Exit non-zero
  only on a harness error (missing wrk/nginx, nginx failed to start, zero
  successful requests for an arm, or the contention self-check failing)
  -- same contract as ci/tools/benchmark.py. A "slow" result is a result,
  not a failure; a workload that cannot contend IS a harness failure,
  because it cannot back up any hit-rate number it would otherwise print.
- It is not wired into any CI workflow. This is a manual measurement tool
  the TODO rows above call out as their prerequisite; running it is a
  deliberate step a human (or a grind worker sizing the ring) takes, not
  something every PR pays for.

Usage
-----
    # A/B: two release binaries, default concurrency sweep (8, 32, 128)
    python3 ci/tools/ab_bench.py \\
        --arm-a .build/nginx-baseline/objs/nginx:baseline \\
        --arm-b .build/nginx-ring/objs/nginx:ring \\
        --json results.json

    # Single binary, release pass only (no A/B, still gives a baseline table)
    python3 ci/tools/ab_bench.py --arm-a .build/nginx-1.31.4/objs/nginx

    # Add the debug pass (separate, clearly-labelled section) for one arm
    python3 ci/tools/ab_bench.py \\
        --arm-a .build/nginx-1.31.4/objs/nginx:release \\
        --debug-binary .build/nginx-1.31.4/objs/nginx

    # Focus one RFC 9842 lookup cell: 16 configured dictionaries, miss path
    python3 ci/tools/ab_bench.py \\
        --arm-a .build/nginx-1.31.4/objs/nginx \\
        --workload dcz --dcz-dictionaries 16 --dcz-case miss

Exit non-zero only on harness error, never on a "slow" result.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parent.parent.parent

DEFAULT_CONCURRENCY = [8, 32, 128]
DEFAULT_ROUNDS = 3
DEFAULT_DURATION = "10s"
WARMUP_DURATION = "3s"

# nginx retries bind() several times on "Address already in use" before
# giving up and exiting -- measured at ~2.5s from spawn to exit on this
# build. require_own_nginx_ready() waits at least this long past a
# successful socket connect before trusting it, so a foreign listener
# already on the port (which answers instantly, well before our nginx
# would exit) cannot be mistaken for readiness. See that function's
# docstring for the reproduction that caught the original 0.2s window
# being too short.
NGINX_BIND_RETRY_GRACE_S = 4.0

# Body-size classes. 8 KB is where the worker-CCtx-cache win showed up
# (+79%); 64 KB is where it was measured as zero because the compression
# work itself dominates over context-creation overhead. Keeping both by
# default is deliberate -- see the module docstring.
BODY_SIZES: dict[str, int] = {
    "8kb": 8 * 1024,
    "64kb": 64 * 1024,
}

DCZ_DICTIONARY_COUNTS = (1, 4, 16)
DCZ_CASES = ("hit", "miss")

# The debug pass drives ONE body-size class (the smaller one, where the
# cache win is largest -- see the block above) rather than the full mix,
# since it exists only to produce witness lines, not a throughput
# comparison. Bound to BODY_SIZES itself, not a bare literal path, so a
# future rename can't silently point this at a 404 (nginx would answer
# 404, the debug pass would collect zero witnesses, and the hit rate
# would misleadingly read "n/a" rather than erroring loudly).
DEBUG_BODY = next(iter(BODY_SIZES))
assert DEBUG_BODY in BODY_SIZES

CREATE_WITNESS = "zstd: created cctx"
REUSE_WITNESS = "zstd: reusing worker cctx"

# The loan (ngx_http_zstd_worker_cctx_busy) is held from acquire_cctx
# until REQUEST CLEANUP, so two compressions only actually CONTEND when
# their lifetimes overlap on one worker. A location that serves a static,
# fully-buffered, known-length body from page cache completes inside one
# event-loop turn -- wrk connections then queue rather than overlap, and
# the harness would silently report a meaningless 100% hit rate at every
# concurrency (caught in review: flat 100% at 8/32/128 conn plus
# unmoving worker RSS is the signature of a workload that never
# contends, not of a healthy cache). Bodies are therefore served via
# PacedBackend + `proxy_buffering off` below: the backend sends headers
# immediately, then the body in small chunked pieces with a sleep
# between each, so the filter's compression session for one response
# stays open across many event-loop turns while other connections are
# being accepted -- long enough for a second concurrent request to
# reach acquire_cctx while the first still holds the loan.
PACE_CHUNK = 512
PACE_DELAY_S = 0.004

# Self-check thresholds for the debug pass -- see
# evaluate_contention_self_check(). Three prior versions of this check
# were tried and defeated by real (not hypothetical) counterexamples,
# each one caught by actually reproducing the failure rather than
# reasoning about it:
#   1. An ABSOLUTE `created > 1` floor -- too weak. Even a near-instant
#      single-chunk send through the proxy hop picks up a handful of
#      "created" witnesses from ordinary thread-scheduling jitter,
#      which let a workload that barely contends pass silently.
#   2. A RELATIVE rise in created-fraction (created / total) from the
#      lowest to the highest concurrency -- wrong because
#      created-fraction saturates near 1.0 once contention is heavy
#      (measured: 87.8% -> 96.9%, only a 1.10x rise) and compresses all
#      the signal into a narrow band exactly where resolution is
#      needed.
#   3. A RELATIVE fall in hit rate (`lo_hr >= hi_hr * RISE`) with only a
#      floor on `created` at the HIGH end -- defeated by a workload
#      where the cache never engages at all: hit rate 0.0 at every
#      concurrency satisfies `0.0 >= 0.0 * 1.5` (True), and a total-miss
#      run creates a context on every request, so `created` at the high
#      end is enormous and clears any created-count floor trivially.
#      Verified in the interpreter, not merely reasoned about; see
#      test_contention_self_check_negative_control() below, which is
#      the negative control this defect should have caught before it
#      shipped twice.
# The check that survived requires BOTH: an ABSOLUTE floor on the hit
# rate at the LOWEST concurrency (the cache must demonstrably engage at
# all when barely contended -- CONTENTION_MIN_LO_HIT_RATE), and a
# STRICT relative fall to the highest concurrency (CONTENTION_MIN_RELATIVE_RISE,
# compared with `>`, never `>=`, so equal values cannot pass).
# CONTENTION_MIN_CREATED remains a trivial sanity bound on sample size
# at the highest concurrency, not a second independent discriminator.
CONTENTION_MIN_CREATED = 20
CONTENTION_MIN_RELATIVE_RISE = 1.5
CONTENTION_MIN_LO_HIT_RATE = 0.05


@dataclasses.dataclass
class Arm:
    label: str
    binary: pathlib.Path
    filter_module: pathlib.Path | None = None
    static_module: pathlib.Path | None = None


@dataclasses.dataclass
class BenchSample:
    """One wrk run's result for one (arm, concurrency, body size)."""

    rps: float
    p50_ms: float
    p99_ms: float
    peak_rss_kb: int
    requests: int
    errors: int


@dataclasses.dataclass
class WitnessSample:
    """Cache-engagement counts from ONE debug-pass run. Never carries a
    throughput number -- the debug pass's own throughput is deliberately
    unreliable (see module docstring) and must never be read as
    comparable to a release-pass BenchSample.
    """

    created: int
    reused: int

    @property
    def hit_rate(self) -> float | None:
        total = self.created + self.reused
        if total == 0:
            return None
        return self.reused / total


@dataclasses.dataclass(frozen=True)
class Workload:
    """Request/config contract for one benchmark run."""

    mode: str
    headers: tuple[tuple[str, str], ...]
    expected_encoding: str
    config: str = ""
    dictionary_count: int = 0
    dcz_case: str | None = None


@dataclasses.dataclass(frozen=True)
class PerfAttachment:
    """perf stat output contract for nginx workers during measured runs."""

    output: pathlib.Path
    events: str


def _available_dictionary(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return f":{base64.b64encode(digest).decode('ascii')}:"


def _dcz_dictionary(index: int) -> bytes:
    marker = f"dictionary-{index:02d}".encode()
    unit = marker + body_bytes(8 * 1024)
    return unit[: 8 * 1024]


def prepare_workload(
    root: pathlib.Path,
    mode: str,
    dictionary_count: int,
    dcz_case: str,
) -> Workload:
    """Create deterministic dcz fixtures and the matching request contract."""
    if mode == "zstd":
        return Workload(
            mode="zstd",
            headers=(("Accept-Encoding", "zstd"),),
            expected_encoding="zstd",
        )
    if mode != "dcz":
        raise ValueError(f"unsupported workload: {mode!r}")
    if dictionary_count not in DCZ_DICTIONARY_COUNTS:
        raise ValueError(
            f"dcz dictionary count must be one of {DCZ_DICTIONARY_COUNTS}, "
            f"got {dictionary_count}"
        )
    if dcz_case not in DCZ_CASES:
        raise ValueError(f"dcz case must be one of {DCZ_CASES}, got {dcz_case!r}")

    dictionary_dir = root / "dictionaries"
    dictionary_dir.mkdir()
    configured: list[str] = []
    directives: list[str] = [
        "    zstd_dcz_assume_secure_transport on;",
    ]
    for index in range(dictionary_count):
        data = _dcz_dictionary(index)
        path = dictionary_dir / f"dict-{index:02d}.bin"
        path.write_bytes(data)
        configured.append(_available_dictionary(data))
        digest_hex = hashlib.sha256(data).hexdigest()
        directives.append(f"    zstd_dcz_dict_file {path} {digest_hex};")

    if dcz_case == "hit":
        # The lookup walks configuration order, so the last entry exercises
        # the full configured table just like a miss does.
        advertised = configured[-1]
        expected_encoding = "dcz"
    else:
        advertised = _available_dictionary(b"unconfigured dcz benchmark dictionary")
        if advertised in configured:
            raise RuntimeError(
                "dcz miss fixture unexpectedly matches a configured hash"
            )
        expected_encoding = "zstd"

    return Workload(
        mode="dcz",
        headers=(
            ("Accept-Encoding", "zstd, dcz"),
            ("Available-Dictionary", advertised),
            ("Sec-Fetch-Site", "same-origin"),
        ),
        expected_encoding=expected_encoding,
        config="\n".join(directives),
        dictionary_count=dictionary_count,
        dcz_case=dcz_case,
    )


def parse_arm(spec: str) -> tuple[str, str]:
    """ "path[:label]" -> (path, label). Label defaults to the basename."""
    if ":" in spec:
        path, label = spec.rsplit(":", 1)
        if path and label:
            return path, label
    return spec, pathlib.Path(spec).name


def detect_module(binary: pathlib.Path, name: str) -> pathlib.Path | None:
    sibling = binary.parent / name
    return sibling if sibling.exists() else None


def require_own_nginx_ready(
    proc: subprocess.Popen, port: int, root: pathlib.Path, what: str
) -> None:
    """Block until `port` is accepting connections AND our own nginx
    process is still alive -- accepting readiness from the socket alone
    is not enough. If something else already holds `port`, our nginx
    exits almost immediately with "Address already in use", but a bare
    socket connect happily reaches the FOREIGN listener and reports
    ready instantly, before our process has even been reaped: the
    harness would then benchmark somebody else's server and report a
    confident number for software it never started -- reproduced while
    testing this exact fix, with a foreign HTTP server already bound to
    the target port.

    A single `proc.poll()` right after the socket connects is NOT
    enough: it does not block, and nginx failing to bind is not
    guaranteed to have been reaped by the OS in that exact instant, so
    the race can still slip through. This polls both conditions
    together over a short window instead of trusting one snapshot of
    either.
    """
    deadline = time.time() + 10
    ready = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                ready = True
                break
        except OSError:
            time.sleep(0.05)
    # A socket connect succeeding is NOT proof our process is the one
    # answering: nginx retries bind() on "Address already in use"
    # several times before giving up (measured: ~2.5s of retries before
    # it actually exits), so a foreign listener already on the port
    # answers wait_for_port() immediately while our nginx is still
    # mid-retry, and a short grace window after "ready" is not long
    # enough to distinguish the two -- reproduced while testing this
    # exact fix. Once the socket is reachable, actively wait for our
    # process to EITHER exit (bind failure) or survive past nginx's own
    # bind-retry budget (genuine readiness), rather than trusting one
    # snapshot.
    if ready:
        try:
            proc.wait(timeout=NGINX_BIND_RETRY_GRACE_S)
        except subprocess.TimeoutExpired:
            pass  # still alive past the retry window -- genuinely ours
    exited = proc.poll() is not None
    if ready and not exited:
        return
    tail = ""
    log = root / "stdout.log"
    if log.exists():
        tail = log.read_text("utf-8", "replace")[-2000:]
    if exited:
        raise RuntimeError(
            f"{what}: our nginx process exited before/during the "
            f"readiness wait on port {port} (exit code "
            f"{proc.returncode}) -- if something else already held that "
            f"port, a socket connect alone would otherwise have reached "
            f"the FOREIGN listener and this run would have silently "
            f"benchmarked someone else's server. Log tail:\n{tail}"
        )
    raise RuntimeError(
        f"{what}: nginx never became ready on port {port}. Log tail:\n{tail}"
    )


def body_bytes(size: int) -> bytes:
    """Realistic ~6:1-compressible HTML-ish body of the given size --
    matches the fixture the existing +79% measurement used, not
    incompressible random bytes (which would exercise a different, less
    representative code path in the compressor).
    """
    unit = b"<div class='row'><span>item</span><a href='/x'>link text here</a></div>\n"
    reps = size // len(unit) + 1
    return (unit * reps)[:size]


class PacedBackend(threading.Thread):
    """Mock upstream: sends chunked-transfer headers immediately, then
    the body either unpaced (`pace=False`, the whole body in one write)
    or in PACE_CHUNK-sized pieces with a PACE_DELAY_S sleep between each
    (`pace=True`). One handler thread per accepted connection so it
    scales to the harness's own concurrency sweep without becoming the
    bottleneck itself when unpaced.

    Pacing is what makes compression sessions overlap for the DEBUG
    pass. Proxied through nginx with `proxy_buffering off`, the filter
    processes each chunk as it streams in rather than compressing one
    fully-buffered body in a single event-loop turn -- so the
    worker-lifetime CCtx loan (acquired at acquire_cctx, released only
    at request cleanup, per
    src/ngx_http_zstd_filter_module.c:1847/:2896) stays held for the
    whole paced duration instead of being taken and returned before the
    next request is even accepted. A static, fully-buffered,
    known-length body completes inside one event-loop turn and can
    never contend, however high the connection count -- that was the
    workload bug this class exists to fix.

    Pacing must NEVER be used for the RELEASE pass. PACE_CHUNK/PACE_DELAY_S
    caps this backend at 512B/4ms = 128 KB/s PER CONNECTION -- a hard
    ceiling both arms share equally. A caught defect: the release pass
    was originally paced unconditionally, and its numbers (8 KB body:
    ~115/~478/~1878 rps at 8/32/128 conn) matched the backend's own
    theoretical ceiling (conn_count / stream_time) almost exactly --
    the harness was measuring PacedBackend's sleep loop, never the zstd
    filter, and would have reported "no regression" for a genuinely
    slower build because the backend, not the filter, was always the
    bottleneck. The release pass now runs `pace=False`; only the debug
    pass (which exists for contention, not throughput -- see the module
    docstring) is ever paced.
    """

    def __init__(self, port: int, bodies: dict[str, bytes], pace: bool) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.bodies = bodies
        self.pace = pace
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.srv.bind(("127.0.0.1", port))
        except OSError as exc:
            # A bare OSError here (e.g. "Address already in use") would
            # otherwise propagate uncaught out of run_release_pass /
            # run_debug_pass -- main() only catches RuntimeError, so a
            # busy backend port would crash with a traceback instead of
            # the documented harness-error path every other startup
            # failure in this file follows.
            self.srv.close()
            raise RuntimeError(
                f"PacedBackend: could not bind 127.0.0.1:{port}: {exc}"
            ) from exc
        self.srv.listen(256)
        self._stopping = False

    def stop(self) -> None:
        self._stopping = True
        try:
            self.srv.close()
        except OSError:
            pass

    def run(self) -> None:
        while not self._stopping:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15)
            buf = b""
            while b"\r\n\r\n" not in buf:
                piece = conn.recv(4096)
                if not piece:
                    return
                buf += piece
            request_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            path = request_line.split(" ")[1] if " " in request_line else "/"
            name = path.strip("/").split("/")[-1] or "8kb"
            body = self.bodies.get(name, next(iter(self.bodies.values())))

            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: close\r\n\r\n"
            )
            if self.pace:
                for i in range(0, len(body), PACE_CHUNK):
                    piece = body[i : i + PACE_CHUNK]
                    conn.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                    time.sleep(PACE_DELAY_S)
            else:
                conn.sendall(f"{len(body):x}\r\n".encode() + body + b"\r\n")
            conn.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def write_conf(
    root: pathlib.Path,
    port: int,
    backend_port: int,
    arm: Arm,
    workers: int,
    log_level: str,
    comp_level: int,
    workload: Workload,
) -> pathlib.Path:
    load = ""
    filt = arm.filter_module or detect_module(
        arm.binary, "ngx_http_zstd_filter_module.so"
    )
    static = arm.static_module or detect_module(
        arm.binary, "ngx_http_zstd_static_module.so"
    )
    if filt:
        load += f"load_module {filt};\n"
    if static:
        load += f"load_module {static};\n"

    conf = root / "nginx.conf"
    conf.write_text(
        f"""daemon off;
master_process on;
worker_processes {workers};
{load}error_log {root}/error.log {log_level};
pid {root}/nginx.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    zstd on;
    # Pinned explicitly, not left at the compiled-in default: two arms
    # can be two different binaries with two different defaults, and an
    # unpinned level would mix a level change into the change under
    # measurement. ci/tools/test_compression_matrix.py pins it for the
    # same reason.
    zstd_comp_level {comp_level};
    zstd_min_length 1;
    zstd_types application/octet-stream;
{workload.config}
    server {{
        listen 127.0.0.1:{port};
        default_type application/octet-stream;
        location / {{
            # Paced, chunked, unbuffered upstream -- see PacedBackend.
            # A static in-page-cache body completes in one event-loop
            # turn and can never make two compressions overlap.
            proxy_pass http://127.0.0.1:{backend_port};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(arm: Arm, conf: pathlib.Path, root: pathlib.Path) -> subprocess.Popen:
    log = open(root / "stdout.log", "w", encoding="utf-8")  # noqa: SIM115
    return subprocess.Popen(
        [str(arm.binary), "-p", str(root), "-c", str(conf)],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def stop_nginx(proc: subprocess.Popen) -> None:
    """Gracefully stop nginx, then kill and reap its private process group."""
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def nginx_worker_pids(master_pid: int, expected: int) -> list[int]:
    """Wait for and return the exact worker child set of an nginx master."""
    children_path = pathlib.Path(f"/proc/{master_pid}/task/{master_pid}/children")
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            children = [int(pid) for pid in children_path.read_text().split()]
        except (FileNotFoundError, ProcessLookupError):
            children = []
        if len(children) == expected:
            return children
        time.sleep(0.05)
    raise RuntimeError(
        f"expected {expected} nginx worker pid(s), found {len(children)}"
    )


def start_worker_perf(
    master_pid: int, workers: int, attachment: PerfAttachment
) -> subprocess.Popen:
    """Attach perf only to nginx workers, excluding harness/backend work."""
    if workers != 1:
        raise RuntimeError("worker perf attachment requires --workers 1")
    pids = nginx_worker_pids(master_pid, workers)
    proc = subprocess.Popen(
        [
            "/usr/bin/perf",
            "stat",
            "-p",
            ",".join(str(pid) for pid in pids),
            "-e",
            attachment.events,
            "-o",
            str(attachment.output),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.1)
    if proc.poll() is not None:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"perf stat failed to attach to nginx workers: {stderr}")
    return proc


def stop_worker_perf(proc: subprocess.Popen) -> None:
    """Stop an attached perf process and require a usable exit."""
    if proc.poll() is not None:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(
            f"perf stat exited before the measured pass completed: {stderr}"
        )
    try:
        proc.send_signal(signal.SIGINT)
    except ProcessLookupError as exc:
        raise RuntimeError("perf stat exited before it could be stopped") from exc
    try:
        returncode = proc.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait(timeout=5)
        raise RuntimeError("perf stat did not stop after the measured pass") from exc
    if returncode not in (0, 128 + signal.SIGINT, -signal.SIGINT):
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"perf stat failed with exit code {returncode}: {stderr}")


def rss_monitor_start(master_pid: int, stop_path: pathlib.Path) -> subprocess.Popen:
    """A tiny standalone poller so RSS sampling continues during the wrk
    run without the harness process itself needing a thread juggling
    subprocess I/O. Writes the peak seen to `stop_path` on receipt of
    SIGTERM, then exits -- polled by the caller after wrk finishes.

    `worker_processes` is fixed for the whole run, so the worker pid set
    is resolved via `pgrep -P` ONCE, then reused for every 100ms /proc
    read -- not re-forked on every poll. Forking a shell plus `pgrep` 10
    times a second inside the measured window would add CPU noise on the
    same machine the throughput itself is being measured on, undermining
    the very number this monitor exists to collect. The pid set is only
    re-resolved if a previously-known pid stops existing (a worker died
    or reloaded mid-run), not on a fixed schedule.
    """
    script = f"""
import os, signal, sys, time
peak = 0
stop = False
def _stop(signum, frame):
    global stop
    stop = True
signal.signal(signal.SIGTERM, _stop)

def resolve_pids():
    try:
        out = os.popen("pgrep -P {master_pid}").read()
        return [int(x) for x in out.split() if x.strip()]
    except Exception:
        return []

pids = resolve_pids()
while not stop:
    total = 0
    stale = False
    for pid in pids:
        try:
            with open(f"/proc/{{pid}}/status") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
                        break
        except (FileNotFoundError, ProcessLookupError):
            stale = True
    peak = max(peak, total)
    if stale or not pids:
        pids = resolve_pids()
    time.sleep(0.1)
with open({str(stop_path)!r}, "w") as fh:
    fh.write(str(peak))
"""
    return subprocess.Popen([sys.executable, "-c", script])


def _to_ms(value: float, unit: str) -> float:
    return {"us": value / 1000, "ms": value, "s": value * 1000}[unit]


def parse_wrk_percentiles(text: str) -> tuple[float, float]:
    """Extract p50 / p99 from `wrk --latency` output's distribution table."""
    p50 = p99 = 0.0
    for line in text.splitlines():
        m = re.match(r"\s*(50|99)%\s+([\d.]+)(us|ms|s)", line)
        if not m:
            continue
        pct, val, unit = m.groups()
        ms = _to_ms(float(val), unit)
        if pct == "50":
            p50 = ms
        else:
            p99 = ms
    return p50, p99


def parse_wrk_duration_s(duration: str) -> float:
    """Parse a wrk `-d` duration string ("10s", "2m", "1h", or a bare
    number of seconds) into seconds. Raises ValueError on anything else
    -- callers treat that as a harness error, not a silent fallback,
    since a duration wrk itself would reject is worth failing loudly on
    before ever spawning the subprocess.
    """
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(s|m|h)?", duration.strip())
    if not m:
        raise ValueError(f"unparsable wrk duration: {duration!r}")
    value = float(m.group(1))
    unit = m.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def verify_workload(port: int, workload: Workload) -> str:
    """Fail before measurement unless the configured request path engages."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", "/8kb", headers=dict(workload.headers))
        response = conn.getresponse()
        response.read()
    finally:
        conn.close()
    encoding = response.getheader("Content-Encoding", "")
    if response.status != 200 or encoding != workload.expected_encoding:
        raise RuntimeError(
            f"{workload.mode} workload preflight failed: status={response.status}, "
            f"Content-Encoding={encoding!r}, expected "
            f"{workload.expected_encoding!r}"
        )
    return encoding


def run_wrk(
    url: str,
    connections: int,
    duration: str,
    threads: int,
    headers: tuple[tuple[str, str], ...],
) -> tuple[float, float, float, int, int]:
    wrk_bin = shutil.which("wrk")
    assert wrk_bin
    # The subprocess timeout must be derived from the user-supplied
    # duration, not a fixed constant -- a fixed 120s timeout raises an
    # uncaught subprocess.TimeoutExpired (main() only catches
    # RuntimeError) the moment someone passes --duration longer than
    # that, aborting the harness with a traceback instead of the
    # documented harness-error path. The margin covers wrk's own
    # connect/warmup/report overhead on top of the measured window.
    timeout_s = parse_wrk_duration_s(duration) + 30
    command = [
        wrk_bin,
        "-t",
        str(threads),
        "-c",
        str(connections),
        "-d",
        duration,
        "--latency",
    ]
    for name, value in headers:
        command.extend(("-H", f"{name}: {value}"))
    command.append(url)
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_s,
    )
    out = proc.stdout
    rps_m = re.search(r"Requests/sec:\s*([\d.]+)", out)
    req_m = re.search(r"(\d+) requests in", out)
    err_m = re.search(r"Non-2xx or 3xx responses:\s*(\d+)", out)
    rps = float(rps_m.group(1)) if rps_m else 0.0
    requests = int(req_m.group(1)) if req_m else 0
    errors = int(err_m.group(1)) if err_m else 0
    p50, p99 = parse_wrk_percentiles(out)
    if rps_m is None:
        raise RuntimeError(f"wrk produced no parseable output:\n{out}\n{proc.stderr}")
    return rps, p50, p99, requests, errors


def bench_one(
    arm: Arm,
    master_pid: int,
    root: pathlib.Path,
    port: int,
    body: str,
    conc: int,
    duration: str,
    workload: Workload,
) -> BenchSample:
    # The config sets `daemon off; master_process on;`, so the Popen
    # object's own pid already IS the master -- no need to re-derive it
    # via `pgrep -f`, which depended on `pgrep` being installed and on
    # arm.binary/root containing no regex metacharacters; a miss there
    # silently left the RSS monitor never started and the table reported
    # a false peakRSS(MB) of 0.0 instead of failing loudly.
    stop_file = root / f"rss.{body}.{conc}.peak"
    monitor = rss_monitor_start(master_pid, stop_file)

    url = f"http://127.0.0.1:{port}/{body}"
    threads = min(conc, os.cpu_count() or 4)
    rps, p50, p99, requests, errors = run_wrk(
        url, conc, duration, threads, workload.headers
    )

    peak_rss = 0
    monitor.send_signal(signal.SIGTERM)
    try:
        monitor.wait(timeout=5)
    except subprocess.TimeoutExpired:
        monitor.kill()
    if stop_file.exists():
        try:
            peak_rss = int(stop_file.read_text().strip() or "0")
        except ValueError:
            peak_rss = 0

    return BenchSample(
        rps=rps,
        p50_ms=p50,
        p99_ms=p99,
        peak_rss_kb=peak_rss,
        requests=requests,
        errors=errors,
    )


def run_release_pass(
    arms: list[Arm],
    concurrencies: list[int],
    rounds: int,
    duration: str,
    workers: int,
    base_port: int,
    comp_level: int,
    workload_mode: str,
    dictionary_count: int,
    dcz_case: str,
    perf_attachment: PerfAttachment | None = None,
) -> tuple[dict, dict[str, str], int]:
    """Run interleaved rounds and return samples, engagement, and setup count."""
    samples: dict[str, dict[int, dict[str, list[BenchSample]]]] = {
        arm.label: {c: {b: [] for b in BODY_SIZES} for c in concurrencies}
        for arm in arms
    }

    bodies = {name: body_bytes(size) for name, size in BODY_SIZES.items()}
    procs: dict[str, tuple[subprocess.Popen, pathlib.Path, int]] = {}
    workloads: dict[str, Workload] = {}
    engagement: dict[str, str] = {}
    setup_successful_requests = 0
    backends: list[PacedBackend] = []
    workdirs: list[pathlib.Path] = []
    perf_proc: subprocess.Popen | None = None
    try:
        for i, arm in enumerate(arms):
            root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-{arm.label}-"))
            # mkdtemp gives 0700: run as root, workers drop to the
            # compiled-in nginx user and cannot enter it -> 403s.
            os.chmod(root, 0o755)
            workdirs.append(root)
            port = base_port + i * 2
            backend_port = port + 1
            # pace=False: the RELEASE pass measures real filter
            # throughput. Pacing the backend would cap both arms at the
            # same artificial ceiling and could mask a genuine
            # regression -- see PacedBackend's docstring.
            backend = PacedBackend(backend_port, bodies, pace=False)
            backend.start()
            backends.append(backend)
            workload = prepare_workload(root, workload_mode, dictionary_count, dcz_case)
            workloads[arm.label] = workload
            conf = write_conf(
                root,
                port,
                backend_port,
                arm,
                workers,
                "warn",
                comp_level,
                workload,
            )
            proc = start_nginx(arm, conf, root)
            procs[arm.label] = (proc, root, port)
            require_own_nginx_ready(proc, port, root, f"arm {arm.label!r}")
            engagement[arm.label] = verify_workload(port, workload)
            setup_successful_requests += 1

        # Warmup: one short untimed-ish run per arm/body so the cache is
        # warm before the FIRST measured round -- otherwise round 1 is
        # biased cold for every arm equally, which would still be fair for
        # an A/B delta but would understate absolute rps for both.
        for arm in arms:
            _proc, root, port = procs[arm.label]
            for body in BODY_SIZES:
                _rps, _p50, _p99, requests, errors = run_wrk(
                    f"http://127.0.0.1:{port}/{body}",
                    8,
                    WARMUP_DURATION,
                    4,
                    workloads[arm.label].headers,
                )
                setup_successful_requests += max(requests - errors, 0)

        if perf_attachment is not None:
            if len(arms) != 1:
                raise RuntimeError("worker perf attachment requires exactly one arm")
            perf_proc = start_worker_perf(
                procs[arms[0].label][0].pid, workers, perf_attachment
            )

        for _rnd in range(rounds):
            for conc in concurrencies:
                for body in BODY_SIZES:
                    # Interleave arms WITHIN each (round, conc, body) cell:
                    # this is what actually cancels drift, since it puts
                    # each arm's measurement for the same condition
                    # adjacent in wall-clock time rather than in two
                    # separate blocks.
                    for arm in arms:
                        proc, root, port = procs[arm.label]
                        sample = bench_one(
                            arm,
                            proc.pid,
                            root,
                            port,
                            body,
                            conc,
                            duration,
                            workloads[arm.label],
                        )
                        samples[arm.label][conc][body].append(sample)
        if perf_proc is not None:
            stop_worker_perf(perf_proc)
            perf_proc = None
    finally:
        if perf_proc is not None:
            perf_proc.kill()
            perf_proc.wait(timeout=5)
        for proc, _root, _port in procs.values():
            stop_nginx(proc)
        for backend in backends:
            backend.stop()
        for root in workdirs:
            shutil.rmtree(root, ignore_errors=True)

    return samples, engagement, setup_successful_requests


def evaluate_contention_self_check(
    results: dict[int, WitnessSample], concurrencies: list[int]
) -> None:
    """The debug pass's negative control on ITSELF, not on the module.

    Raises RuntimeError (a harness error) unless the paced workload
    demonstrably (a) makes the cache engage at all at the lowest swept
    concurrency, and (b) shows that engagement fall STRICTLY as
    concurrency rises to the highest. Both conditions are required --
    see the CONTENTION_MIN_* comment block for the three prior versions
    of this check and the real counterexample that defeated each one.

    Pure and side-effect-free by design specifically so it can be
    exercised directly by
    test_contention_self_check_negative_control() below with synthetic
    data, instead of only being reachable by actually running nginx.
    """
    lo_conc, hi_conc = min(concurrencies), max(concurrencies)
    lo, hi = results.get(lo_conc), results.get(hi_conc)
    lo_hr = lo.hit_rate if lo is not None else None
    hi_hr = hi.hit_rate if hi is not None else None

    hi_created_ok = hi is not None and hi.created >= CONTENTION_MIN_CREATED
    # ABSOLUTE floor: the cache must demonstrably engage at ALL when
    # barely contended. Without this, an all-miss run (hit rate 0.0 at
    # every concurrency) satisfies a purely relative "0.0 >= 0.0 * 1.5"
    # comparison -- that is not a benign edge case, it is the single
    # most important failure this harness exists to catch (the cache
    # never engaging) passing as a clean result.
    lo_engages = lo_hr is not None and lo_hr > CONTENTION_MIN_LO_HIT_RATE
    # STRICT relative fall: `>`, never `>=`, so two equal hit rates
    # (including two equal zeros) cannot be read as "falling."
    degrades = (
        lo_hr is not None
        and hi_hr is not None
        and lo_hr > hi_hr * CONTENTION_MIN_RELATIVE_RISE
    )

    if len(concurrencies) < 2 or not hi_created_ok or not lo_engages or not degrades:
        raise RuntimeError(
            "harness self-check FAILED: the paced workload did not "
            f"demonstrate genuine single-slot contention. At {lo_conc} "
            f"conn the hit rate was "
            f"{'n/a' if lo_hr is None else f'{lo_hr * 100:.1f}%'}; "
            f"at {hi_conc} conn it was "
            f"{'n/a' if hi_hr is None else f'{hi_hr * 100:.1f}%'} "
            f"(need the {lo_conc}-conn rate > "
            f"{CONTENTION_MIN_LO_HIT_RATE * 100:.0f}% -- the cache must "
            f"engage at all when barely contended -- AND strictly > "
            f"{CONTENTION_MIN_RELATIVE_RISE}x the {hi_conc}-conn rate, "
            f"and >= {CONTENTION_MIN_CREATED} 'created cctx' witnesses "
            f"at {hi_conc} conn). A single-slot worker cache can only "
            "show a real hit rate when concurrent compressions "
            "genuinely overlap and that overlap actually WORSENS as "
            "concurrency rises -- a hit rate that never engages, or "
            "that is flat or barely falling across the sweep, means "
            "this run never demonstrated that, so any hit rate it "
            "reported would be a workload artifact, not a measurement. "
            "This is the harness's own negative control failing, not a "
            "benign 100% (or 0%) hit rate."
        )


def run_debug_pass(
    arm: Arm,
    concurrencies: list[int],
    duration: str,
    workers: int,
    base_port: int,
    comp_level: int,
    workload_mode: str,
    dictionary_count: int,
    dcz_case: str,
) -> dict[int, WitnessSample]:
    """Separate pass, debug-level logging, only for engagement witnesses.
    Its own throughput is NOT reported -- see module docstring.

    Runs the FULL concurrency sweep against ONE long-lived nginx
    instance (never restarted between concurrencies) so `created` and
    `reused` accumulate across the whole sweep and the ring-sizing row's
    actual question -- does the hit rate DEGRADE as concurrency rises --
    is something this pass can show directly, not just a single
    snapshot.

    Delegates the self-check to evaluate_contention_self_check(), which
    raises RuntimeError (a harness error, not a "slow result") unless
    the paced workload demonstrates BOTH that the cache engages at all
    at the lowest swept concurrency (an ABSOLUTE floor,
    CONTENTION_MIN_LO_HIT_RATE) and that engagement STRICTLY falls to
    the highest (CONTENTION_MIN_RELATIVE_RISE). Both are required: a
    purely relative check alone was defeated by a workload where the
    cache never engages at all (0.0 hit rate at every concurrency
    trivially satisfies a relative "no worse than" comparison) -- see
    the CONTENTION_MIN_* comment block for the full history of three
    rejected check designs, each one defeated by a real counterexample.
    See PacedBackend's docstring for why the workload needs pacing to
    make genuine overlap possible at all.
    """
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"ab-bench-debug-{arm.label}-"))
    # mkdtemp gives 0700: run as root, workers drop to the compiled-in
    # nginx user and cannot enter it -> 403s.
    os.chmod(root, 0o755)
    bodies = {name: body_bytes(size) for name, size in BODY_SIZES.items()}
    backend_port = base_port + 1
    # pace=True: the DEBUG pass exists for CONTENTION (witness counts),
    # not throughput, so the pacing that creates that contention is
    # correct here -- see PacedBackend's docstring.
    backend = PacedBackend(backend_port, bodies, pace=True)
    results: dict[int, WitnessSample] = {}
    try:
        backend.start()
        port = base_port
        workload = prepare_workload(root, workload_mode, dictionary_count, dcz_case)
        conf = write_conf(
            root,
            port,
            backend_port,
            arm,
            workers,
            "debug",
            comp_level,
            workload,
        )
        proc = start_nginx(arm, conf, root)
        try:
            require_own_nginx_ready(proc, port, root, "debug pass")
            verify_workload(port, workload)
            elog_path = root / "error.log"
            prev_created = 0
            prev_reused = 0
            for conc in concurrencies:
                # Throughput-not-reported run purely to generate witness
                # lines under realistic concurrent load.
                run_wrk(
                    f"http://127.0.0.1:{port}/{DEBUG_BODY}",
                    conc,
                    duration,
                    min(conc, 4),
                    workload.headers,
                )
                time.sleep(0.3)  # let the debug log flush
                elog = elog_path.read_text("utf-8", "replace")
                total_created = len(re.findall(re.escape(CREATE_WITNESS), elog))
                total_reused = len(re.findall(re.escape(REUSE_WITNESS), elog))
                # Per-cell delta, not the running total, so each concurrency's
                # own hit rate is reported rather than a cumulative blend.
                created = total_created - prev_created
                reused = total_reused - prev_reused
                prev_created, prev_reused = total_created, total_reused
                results[conc] = WitnessSample(created=created, reused=reused)
        finally:
            stop_nginx(proc)
    finally:
        backend.stop()
        shutil.rmtree(root, ignore_errors=True)

    evaluate_contention_self_check(results, concurrencies)
    return results


def check_with_debug(binary: pathlib.Path) -> None:
    v = subprocess.run([str(binary), "-V"], capture_output=True, text=True, check=False)
    if "--with-debug" not in v.stderr:
        raise RuntimeError(
            f"{binary}: debug pass needs an nginx built --with-debug "
            f"(the reuse witnesses are ngx_log_debug lines); got: "
            f"{v.stderr.strip()}"
        )


def print_release_table(
    arms: list[Arm], concurrencies: list[int], samples: dict
) -> None:
    """Prints the release-pass table, including an `errors` column so a
    partially-failing run (non-2xx/3xx responses, which wrk itself
    counts inside "N requests in" alongside genuine successes) is
    visible instead of silently averaged into the rps/latency numbers.
    Any nonzero error count anywhere in the sweep gets a loud warning
    after the table -- a confident-looking table measured on error
    responses is the exact failure class this tool exists to avoid.
    """
    header = (
        f"{'arm':<14}{'conc':>6}{'body':>7}{'rps(med)':>11}"
        f"{'p50(ms)':>10}{'p99(ms)':>10}{'peakRSS(MB)':>13}"
        f"{'errors':>8}{'rounds':>8}"
    )
    print(header)
    print("-" * len(header))
    medians: dict[str, dict[int, dict[str, float]]] = {}
    any_errors = False
    for arm in arms:
        medians[arm.label] = {}
        for conc in concurrencies:
            medians[arm.label][conc] = {}
            for body in BODY_SIZES:
                sset = samples[arm.label][conc][body]
                rps_med = statistics.median(s.rps for s in sset)
                p50_med = statistics.median(s.p50_ms for s in sset)
                p99_med = statistics.median(s.p99_ms for s in sset)
                rss_peak = max((s.peak_rss_kb for s in sset), default=0) / 1024
                total_errors = sum(s.errors for s in sset)
                if total_errors > 0:
                    any_errors = True
                medians[arm.label][conc][body] = rps_med
                print(
                    f"{arm.label:<14}{conc:>6}{body:>7}{rps_med:>11.1f}"
                    f"{p50_med:>10.2f}{p99_med:>10.2f}{rss_peak:>13.1f}"
                    f"{total_errors:>8}{len(sset):>8}"
                )
        print()
    if any_errors:
        print(
            "WARNING: non-2xx/3xx responses occurred somewhere in this "
            "sweep (see the 'errors' column above). wrk counts those "
            "inside its own request total, so the rps/p50/p99 numbers "
            "for the affected cell(s) are measured PARTLY on error "
            "responses, not on successful compression -- do not treat "
            "them as a clean throughput measurement."
        )
        print()

    if len(arms) == 2:
        a, b = arms[0].label, arms[1].label
        print(f"delta ({b} vs {a}), rps median:")
        dheader = f"{'conc':>6}{'body':>7}{a + ' rps':>14}{b + ' rps':>14}{'delta':>10}"
        print(dheader)
        print("-" * len(dheader))
        for conc in concurrencies:
            for body in BODY_SIZES:
                ra = medians[a][conc][body]
                rb = medians[b][conc][body]
                delta = f"{((rb - ra) / ra * 100):+.1f}%" if ra > 0 else "n/a"
                print(f"{conc:>6}{body:>7}{ra:>14.1f}{rb:>14.1f}{delta:>10}")
        print()
        print(
            "NOTE: a delta at one body size does not generalize to another --"
            " report each size on its own, never a blanket speedup."
        )


def print_debug_table(
    label: str, results: dict[int, WitnessSample], concurrencies: list[int]
) -> None:
    print()
    print("=== DEBUG PASS: cache-engagement witnesses ===")
    print(
        "Throughput numbers from this pass are NOT reported and are NOT "
        "comparable to the release pass above -- debug-level logging on "
        "the hot path would distort them. This section is witness counts "
        "only. The harness self-check already confirmed the hit rate "
        "falls materially from the lowest to the highest swept "
        "concurrency; the table below is the actual per-cell evidence "
        "for the ring-sizing question -- does the hit rate DEGRADE as "
        "concurrency rises."
    )
    header = f"{'arm':<14}{'conc':>6}{'created':>9}{'reused':>8}{'hit rate':>10}"
    print(header)
    print("-" * len(header))
    prev_hr: float | None = None
    degraded = False
    for conc in concurrencies:
        w = results[conc]
        hr = w.hit_rate
        hr_s = f"{hr * 100:.1f}%" if hr is not None else "n/a"
        print(f"{label:<14}{conc:>6}{w.created:>9}{w.reused:>8}{hr_s:>10}")
        if hr is not None and prev_hr is not None and hr < prev_hr:
            degraded = True
        if hr is not None:
            prev_hr = hr
    print()
    if degraded:
        print(
            "hit rate DECREASES somewhere in this sweep as concurrency "
            "rises -- the single-slot contention the ring-sizing row "
            "expects. Use these per-conc numbers, not just the "
            "lowest-vs-highest self-check comparison, to size the ring."
        )
    else:
        print(
            "hit rate did NOT decrease anywhere across this per-cell "
            "sweep despite the self-check proving it fell materially "
            "from the lowest to the highest concurrency -- re-check "
            "before using these numbers to size the ring; a single-slot "
            "cache should degrade as concurrency rises."
        )


def test_contention_self_check_negative_control() -> None:
    """The self-check's OWN negative control -- exercises
    evaluate_contention_self_check() directly with synthetic
    WitnessSample data, no nginx involved. This exists because two
    prior self-check designs each individually looked correct under
    careful reading and both turned out to pass on real non-contending
    input; "read the code carefully" is not a substitute for a test
    that actually runs, so this is that test.

    Asserts three things:
      1. An all-zero-hit-rate run (the cache never engages at any
         concurrency) is REJECTED. This is the specific defect that
         defeated the second self-check design: `0.0 >= 0.0 * 1.5` is
         True, so a purely relative "does the rate fall" comparison
         passes on a workload that measured nothing at all.
      2. A run whose hit rate is IDENTICAL at every concurrency (a
         nonzero constant, not falling at all) is REJECTED -- proves
         the inequality is strict, not `>=`.
      3. A run with a genuine, large absolute-and-relative fall (the
         real numbers measured on this harness: 12.2% -> 3.1%) is
         ACCEPTED -- proves the check does not reject real contention
         along with the broken cases above.

    Called from `--self-test` (see main()), which runs this with no
    nginx/wrk dependency and exits before touching any of that --
    cheap enough to run on every invocation of this file as a smoke
    check, and independent of whatever machine happens to run it.
    """
    concurrencies = [8, 32]

    all_zero = {
        8: WitnessSample(created=500, reused=0),
        32: WitnessSample(created=2000, reused=0),
    }
    try:
        evaluate_contention_self_check(all_zero, concurrencies)
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "self-check negative control FAILED: an all-zero hit rate "
            "(the cache never engaged at ANY concurrency) was accepted "
            "as a valid contention result. This is the exact defect "
            "reported against the second self-check design -- fix "
            "evaluate_contention_self_check(), do not weaken this test."
        )

    flat_nonzero = {
        8: WitnessSample(created=100, reused=100),
        32: WitnessSample(created=100, reused=100),
    }
    try:
        evaluate_contention_self_check(flat_nonzero, concurrencies)
    except RuntimeError:
        pass
    else:
        raise AssertionError(
            "self-check negative control FAILED: an identical (flat, "
            "non-falling) hit rate at every concurrency was accepted. "
            "The relative-fall comparison must be a STRICT inequality "
            "so two equal values cannot pass."
        )

    genuine_decay = {
        8: WitnessSample(created=309, reused=2224),  # hit rate 87.8%
        32: WitnessSample(created=1439, reused=47),  # hit rate 3.2%
    }
    evaluate_contention_self_check(genuine_decay, concurrencies)  # must not raise


def run_self_test() -> int:
    """Runs the in-process negative control above and reports the
    result. No nginx, no wrk, no network -- exists so the self-check's
    own correctness can be verified on every invocation of this file,
    not just reasoned about. Exit code follows the harness-error
    contract: 0 on pass, 1 on failure.
    """
    try:
        test_contention_self_check_negative_control()
    except AssertionError as exc:
        print(f"SELF-TEST FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        "SELF-TEST OK: evaluate_contention_self_check() correctly "
        "rejects an all-zero hit rate, correctly rejects a flat "
        "non-falling hit rate, and correctly accepts a genuine decay."
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the self-check's own negative control (no nginx/wrk "
        "needed) and exit -- verifies evaluate_contention_self_check() "
        "correctly rejects a non-contending workload before trusting "
        "it against real hardware.",
    )
    ap.add_argument(
        "--arm-a", help="path/to/nginx[:label] for arm A (required unless --self-test)"
    )
    ap.add_argument(
        "--arm-b", help="path/to/nginx[:label] for arm B (optional; enables A/B)"
    )
    ap.add_argument(
        "--debug-binary",
        help="path to a --with-debug nginx binary for the SEPARATE debug "
        "pass (cache hit-rate witnesses). If omitted, hit rate is "
        "reported as unmeasured.",
    )
    ap.add_argument(
        "--concurrency",
        default=",".join(str(c) for c in DEFAULT_CONCURRENCY),
        help="comma-separated connection counts to sweep",
    )
    ap.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help="interleaved A/B rounds per (concurrency, body size) cell",
    )
    ap.add_argument("--duration", default=DEFAULT_DURATION, help="wrk -d per run")
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="nginx worker_processes (default 1: the TODO rows this "
        "harness gates are about PER-WORKER cache behaviour)",
    )
    ap.add_argument(
        "--comp-level",
        type=int,
        default=6,
        help="zstd_comp_level pinned in the generated config for both "
        "arms (default 6, matches the existing +79%% measurement). "
        "Pinned explicitly rather than left at each binary's compiled-in "
        "default so an A/B between two different binaries never mixes a "
        "level change into the change actually under measurement.",
    )
    ap.add_argument(
        "--workload",
        choices=("zstd", "dcz"),
        default="zstd",
        help="request workload (default zstd preserves the existing harness)",
    )
    ap.add_argument(
        "--dcz-dictionaries",
        type=int,
        choices=DCZ_DICTIONARY_COUNTS,
        default=1,
        help="configured dictionary count for --workload dcz",
    )
    ap.add_argument(
        "--dcz-case",
        choices=DCZ_CASES,
        default="hit",
        help="advertise the last configured dictionary or an absent one",
    )
    ap.add_argument("--base-port", type=int, default=18400)
    ap.add_argument("--json", help="write machine-readable results here")
    ap.add_argument(
        "--perf-stat-output",
        help="attach perf only to nginx workers during measured release runs",
    )
    ap.add_argument(
        "--perf-events",
        help="comma-separated perf events (required with --perf-stat-output)",
    )
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()

    if not args.arm_a:
        print("error: --arm-a is required unless --self-test is given", file=sys.stderr)
        return 2
    if bool(args.perf_stat_output) != bool(args.perf_events):
        print(
            "error: --perf-stat-output and --perf-events must be used together",
            file=sys.stderr,
        )
        return 2
    if args.perf_stat_output and args.workers != 1:
        print("error: worker perf attachment requires --workers 1", file=sys.stderr)
        return 2

    # Everything the scratch roots below create must stay readable by the
    # workers when the harness runs as root (they drop to the compiled-in
    # nginx user): a restrictive inherited umask would strip group/other
    # bits from every fixture created here, 403ing the workers even with
    # each scratch root itself chmod'd open -- same trap and same fix as
    # ci/tools/test_compression_matrix.py.
    os.umask(0o022)

    if shutil.which("wrk") is None:
        print("error: wrk not found on PATH", file=sys.stderr)
        return 2

    try:
        parse_wrk_duration_s(args.duration)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    concurrencies = [int(x) for x in args.concurrency.split(",") if x.strip()]

    arms: list[Arm] = []
    for _i, spec in enumerate((args.arm_a, args.arm_b)):
        if spec is None:
            continue
        path, label = parse_arm(spec)
        binary = pathlib.Path(path).resolve()
        if not binary.exists():
            print(f"error: arm binary not found: {binary}", file=sys.stderr)
            return 2
        arms.append(Arm(label=label, binary=binary))
    if len({a.label for a in arms}) != len(arms):
        print("error: arm labels must be distinct", file=sys.stderr)
        return 2

    workload_label = args.workload
    if args.workload == "dcz":
        workload_label += f"/{args.dcz_dictionaries}/{args.dcz_case}"
    print(
        f"=== RELEASE PASS: rps/p50/p99/RSS, {args.rounds} interleaved "
        f"round(s), workload={workload_label}, "
        "NO cache witnesses in this section ==="
    )
    try:
        perf_attachment = None
        if args.perf_stat_output:
            perf_attachment = PerfAttachment(
                pathlib.Path(args.perf_stat_output).resolve(), args.perf_events
            )
        samples, engagement, setup_successful_requests = run_release_pass(
            arms,
            concurrencies,
            args.rounds,
            args.duration,
            args.workers,
            args.base_port,
            args.comp_level,
            args.workload,
            args.dcz_dictionaries,
            args.dcz_case,
            perf_attachment,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Gate on SUCCESSFUL requests, not raw request count -- wrk's own
    # "N requests in" total includes non-2xx/3xx responses, so an
    # all-403 or all-502 run would otherwise clear this gate and print
    # a full throughput table measured on nothing.
    total_successful = sum(
        max(s.requests - s.errors, 0)
        for arm in arms
        for conc in concurrencies
        for body in BODY_SIZES
        for s in samples[arm.label][conc][body]
    )
    if total_successful == 0:
        print(
            "error: zero successful (non-error) requests across the whole sweep",
            file=sys.stderr,
        )
        return 1
    completed_successful_requests = total_successful + setup_successful_requests

    print_release_table(arms, concurrencies, samples)

    debug_results: dict[int, WitnessSample] = {}
    if args.debug_binary:
        debug_bin = pathlib.Path(args.debug_binary).resolve()
        if not debug_bin.exists():
            print(f"error: debug binary not found: {debug_bin}", file=sys.stderr)
            return 2
        try:
            check_with_debug(debug_bin)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        debug_arm = Arm(label="debug", binary=debug_bin)
        try:
            debug_results = run_debug_pass(
                debug_arm,
                concurrencies,
                args.duration,
                args.workers,
                args.base_port + len(arms) * 2 + 2,
                args.comp_level,
                args.workload,
                args.dcz_dictionaries,
                args.dcz_case,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print_debug_table(debug_arm.label, debug_results, concurrencies)
    else:
        print()
        print(
            "=== DEBUG PASS: not run (no --debug-binary given) -- cache "
            "hit rate is UNMEASURED, not inferred. ==="
        )

    if args.json:
        out = {
            "meta": {
                "concurrencies": concurrencies,
                "rounds": args.rounds,
                "duration": args.duration,
                "workers": args.workers,
                "arms": [a.label for a in arms],
                "workload": args.workload,
                "dcz_dictionaries": args.dcz_dictionaries
                if args.workload == "dcz"
                else None,
                "dcz_case": args.dcz_case if args.workload == "dcz" else None,
                "engagement": engagement,
                "successful_requests": total_successful,
                "completed_successful_requests": completed_successful_requests,
                "perf_scope": "nginx-workers-measured-release"
                if perf_attachment is not None
                else None,
                "commit": subprocess.run(
                    ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip(),
            },
            "release": {
                arm.label: {
                    str(conc): {
                        body: [
                            dataclasses.asdict(s)
                            for s in samples[arm.label][conc][body]
                        ]
                        for body in BODY_SIZES
                    }
                    for conc in concurrencies
                }
                for arm in arms
            },
            "debug": {
                str(conc): dataclasses.asdict(w) for conc, w in debug_results.items()
            }
            if debug_results
            else None,
        }
        pathlib.Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
