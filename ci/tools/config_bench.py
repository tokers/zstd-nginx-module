#!/usr/bin/env python3
"""Config-load A/B benchmark harness: measures what `nginx -t` and a reload
COST, as a curve against config scale, for two nginx binaries.

This is the gating dependency for the config-time TODO rows -- caching the
per-location config-merge work, caching libzstd
profile work by effective tuple, and replacing the O(n^2) dcz duplicate-hash
detection. Each of those rows says "benchmark before retaining the extra
state".

Why this is a SEPARATE tool from ci/tools/ab_bench.py
------------------------------------------------------
`ab_bench.py` measures the REQUEST path: throughput, latency and worker RSS
under `wrk` load. Its oracle is "requests per second". None of the rows above
touch the request path at all -- they run once per location at config-parse
time, inside `nginx -t`, before a single request exists. A request-path
harness structurally cannot see them: their entire cost has already been paid
by the time the first connection is accepted. Hence a second tool with a
different oracle (wall time and peak RSS of the config load itself), rather
than a flag on the first one.

What it measures
-----------------
- Wall time of `nginx -t` and peak RSS of the config-load process, per
  (arm, scale point), where "scale" is the number of generated locations or
  dcz dictionary entries.
- Reload time and post-reload RSS (`--mode reload`), for the rows that care
  about cycle memory across a live reconfigure rather than a bare syntax
  check.
- Reported as a CURVE across scale points, never a single number. A single
  scale point cannot distinguish O(n) from O(n^2), which is the actual
  question every gated row asks.

Two arms, interleaved
----------------------
Same rationale as `ab_bench.py`: the two arms alternate round by round rather
than running A-then-B, so machine drift (page-cache warmth, thermal, a
background job) hits both arms equally instead of being attributed to the
change under test. Reported numbers are the per-arm MEDIAN across rounds.

Peak RSS, not a final snapshot
-------------------------------
Config load is short and its memory profile is a spike, not a plateau: the
parse allocates into the cycle pool and a `nginx -t` process exits
immediately after. A `/usr/bin/time -v`-style "maximum resident" read after
exit can be taken after the interesting peak is already gone, and a single
`/proc` read at an arbitrary moment is worse. This harness polls `/proc/<pid>/
status` continuously from spawn to exit and keeps the maximum, the same
approach `ab_bench.py`'s `rss_monitor_start()` uses for workers.

The harness's negative control is on its OWN oracle
-----------------------------------------------------
PR #151 shipped three successive versions of a self-check that passed on input
proving nothing (a flat 100% hit rate measured on a workload that never
overlapped; a self-check where `0.0 >= 0.0` was True). The generalizable rule
recorded from that: a measurement harness needs a negative control on its own
oracle, not only on the thing being measured.

Here that means: before any result is reported, the harness asserts that its
own generated configs actually make config load MORE expensive as scale rises.
If loading 4000 locations costs the same as loading 10, then this harness is
not measuring config scale -- it is measuring process startup, and any
"improvement" it later reports for a fix would be noise. That assertion is
`evaluate_scale_self_check()`, a pure function exercised by `--self-test` with
synthetic samples, so the check itself is testable without running nginx.

Usage
------
    # Does the current binary show a config-scale curve at all? (baseline)
    python3 ci/tools/config_bench.py --arm-a .build/nginx-1.31.4/objs/nginx

    # A/B two binaries across the dcz dictionary-count workload
    python3 ci/tools/config_bench.py \\
        --arm-a .build/before/objs/nginx:before \\
        --arm-b .build/after/objs/nginx:after \\
        --workload dcz-dicts

    # Verify the harness's own oracle without touching nginx
    python3 ci/tools/config_bench.py --self-test

Baseline measured 2026-08-24 (nginx 1.31.4, this host, --rounds 1)
------------------------------------------------------------------
Recorded so a later session need not re-derive them, and so the gated TODO
rows can be decided on numbers instead of intuition.

    locations-same-profile      dcz-dicts
    scale    nginx -t           scale    nginx -t
      100       4.7ms             600       6.7ms
     4000      37.7ms           10000      91.8ms
    16000     120.4ms           20000     282.9ms
    32000     246.5ms           40000    1291.1ms

Two conclusions, both of which bear directly on the rows this tool gates:

1. The per-location merge path is LINEAR across 320x of scale -- 100 ->
   32000 locations costs 52x, not 102400x. (These numbers were measured when
   that path also ran an O(modules) scan per location for the gzip_vary-off
   warning; G5 deleted the warning and the scan, so the per-location constant
   is now strictly smaller and the linear shape still holds.)

2. The dcz duplicate-hash detection IS genuinely O(n^2), and this harness can
   now show it: 20000 -> 40000 entries is 2x the scale for 4.6x the time. But
   the quadratic term only dominates far above any realistic configuration. At
   ~600 entries -- the scale the TODO row itself names as the benchmarked
   workload -- the whole config load is 6.7ms, and the crossover sits somewhere
   past 10000 entries.

So the measured answer to "replace the O(n^2) duplicate detection?" is: not on
performance grounds at realistic scale. That is a refutation the row explicitly
asked for ("keep the linear form if the crossover is outside realistic
configurations"), not a null result.

Exit non-zero only on harness error, never on a "slow" result.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import socket
import statistics
import subprocess
import sys
import tempfile
import time

DEFAULT_ROUNDS = 3

# Scale points per workload. The low point is a control (a config so small
# that per-location cost cannot dominate); the high points are the scales the
# TODO rows actually name -- "thousands of same-profile locations" for the
# location workloads and "~600 entries" for the dcz dictionary list.
WORKLOAD_SCALES: dict[str, list[int]] = {
    # 16000 (not 4000) so the largest point clears SCALE_MIN_HI_SECONDS with
    # margin on fast hardware: 4000 locations measured 27-33ms on a
    # contemporary dev box in 2026-08, below the 50ms floor, aborting the
    # self-check before either workload could report a curve. 16000 measured
    # 91.7ms (same-profile) / 101.2ms (multi-profile) on that same box --
    # roughly 2x the floor -- while staying inside the range the module
    # docstring's baseline table already exercised (32000 locations, 246.5ms).
    "locations-same-profile": [10, 500, 4000, 16000],
    "locations-multi-profile": [10, 500, 4000, 16000],
    # 16000 (not 600) so the largest point clears SCALE_MIN_HI_SECONDS with
    # margin: 600 entries measured 5.8ms, below the 50ms floor. 5000 measured
    # 30.9ms, 10000 measured 98.7ms, and 16000 measured 182.3ms on a
    # contemporary dev box in 2026-08 -- the largest point ~3.6x the floor.
    "dcz-dicts": [10, 600, 5000, 16000],
}

# The distinct (level, long_mode, window_log) tuples cycled through by the
# multi-profile workload. The profile-caching row's win depends on how many
# DISTINCT profiles exist, not how many locations: a cache keyed by effective
# tuple collapses same-profile locations and cannot collapse these. Kept small
# and fixed so scale sweeps vary location count alone.
PROFILE_TUPLES: list[tuple[int, str, int]] = [
    (3, "off", 0),
    (9, "on", 27),
    (12, "on", 30),
    (1, "off", 0),
]

# The multi-profile workload's per-request memory budget.
#
# Two of the tuples above enable long-distance matching at a large window
# (level 9 / windowLog 27 and level 12 / windowLog 30). zstd_max_cctx_memory
# is validated at config load against libzstd's own estimator, and those two
# profiles genuinely need ~156 MB and ~1.14 GB of per-request compressor
# memory respectively -- so the 32m this workload used to emit is a budget
# they cannot satisfy, and nginx correctly refuses the configuration.
#
# This workload measures config-LOAD COST as a function of the number of
# distinct profiles; the budget is fixture shape, not the thing under
# measurement. So it is raised to a value every tuple fits in rather than
# dropping the LDM tuples, which would change what the benchmark measures.
# Keep this above the largest estimate any PROFILE_TUPLES entry produces.
# (nginx size values accept only k/m suffixes, so this is spelled in MB.)
MULTI_PROFILE_BUDGET = "2048m"

# The self-check's floor. Between the smallest and largest scale point, the
# measured config-load cost must rise by at least this factor, or the harness
# has not demonstrated that it can see config scale at all.
#
# 1.5x (not, say, 10x) because the floor's job is only to separate "this
# harness observes scale" from "this harness observes process startup" -- it
# is deliberately NOT an assertion about the complexity class. A superlinear
# path will clear it by a wide margin; a genuinely O(1) path will not clear it
# at all, which is the outcome that must fail loudly rather than be reported
# as a clean measurement.
SCALE_MIN_RELATIVE_RISE = 1.5

# An absolute floor on the largest scale point's cost. Without it, two
# equal-and-tiny timings (say 0.4ms vs 0.4ms, both dominated by fork+exec
# jitter) can satisfy a purely relative ratio test through noise alone. This
# is the direct analogue of ab_bench.py's CONTENTION_MIN_LO_HIT_RATE, added
# for exactly the reason recorded there: a relative-only comparison passes on
# degenerate input.
SCALE_MIN_HI_SECONDS = 0.05


@dataclasses.dataclass
class Arm:
    label: str
    binary: pathlib.Path
    filter_module: pathlib.Path | None = None
    static_module: pathlib.Path | None = None


@dataclasses.dataclass
class ConfigSample:
    """One config-load measurement for one (arm, workload, scale)."""

    seconds: float
    peak_rss_kb: int
    ok: bool
    detail: str = ""


def parse_arm(spec: str) -> tuple[str, str]:
    """`path[:label]` -> (path, label). Mirrors ab_bench.py's --arm syntax."""
    if ":" in spec:
        path, _, label = spec.rpartition(":")
        if path:
            return path, label
    return spec, pathlib.Path(spec).name


def detect_module(binary: pathlib.Path, name: str) -> pathlib.Path | None:
    """Find a built dynamic module beside the binary, as ab_bench.py does."""
    candidate = binary.parent / name
    return candidate if candidate.exists() else None


def _dict_digest(index: int) -> str:
    """A deterministic, unique 64-hex digest for generated dcz entry N.

    Supplied hashes are used deliberately: the dcz row notes that supplying
    hashes makes the hashing pass free, which is what surfaces the O(n^2)
    duplicate-detection bookkeeping as the dominant config-time cost. If the
    harness let nginx hash 600 real dictionary files instead, hashing would
    swamp the very comparison loop under measurement.
    """
    return hashlib.sha256(f"config_bench-dict-{index}".encode()).hexdigest()


def pick_free_port() -> int:
    """An ephemeral port the kernel just confirmed is free.

    Closed immediately, so this is advisory rather than a reservation -- but
    `nginx -t` binds and releases within a second, and each measurement picks
    a fresh port, so a collision would show up as a failed config test (which
    the self-check rejects loudly) rather than as a silently wrong number.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def generate_config(
    root: pathlib.Path,
    arm: Arm,
    workload: str,
    scale: int,
    dict_file: pathlib.Path | None = None,
) -> pathlib.Path:
    """Write a synthetic nginx.conf of the requested workload and scale."""
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

    body = ""

    if workload == "locations-same-profile":
        # Every location carries an IDENTICAL profile. This is the
        # profile-caching row's best case (one distinct tuple) and the
        # baseline for per-location merge cost. gzip_vary off is kept as
        # part of the fixture's shape; since G5 it no longer triggers any
        # per-location scan or warning.
        for i in range(scale):
            body += (
                f"    location /l{i} {{\n"
                f"        zstd on;\n"
                f"        gzip_vary off;\n"
                f"        zstd_comp_level 3;\n"
                f"        zstd_max_cctx_memory 32m;\n"
                f"    }}\n"
            )

    elif workload == "locations-multi-profile":
        # Same scale, but cycling distinct (level, long_mode, window_log)
        # tuples. Compared against locations-same-profile at the same scale,
        # this isolates the part of config cost that a tuple-keyed cache
        # CANNOT collapse from the part it can.
        for i in range(scale):
            level, long_mode, window_log = PROFILE_TUPLES[i % len(PROFILE_TUPLES)]
            win = f"        zstd_window_log {window_log};\n" if window_log else ""
            body += (
                f"    location /l{i} {{\n"
                f"        zstd on;\n"
                f"        gzip_vary off;\n"
                f"        zstd_comp_level {level};\n"
                f"        zstd_long {long_mode};\n"
                f"{win}"
                f"        zstd_max_cctx_memory {MULTI_PROFILE_BUDGET};\n"
                f"    }}\n"
            )

    elif workload == "dcz-dicts":
        # N dcz dictionary entries with SUPPLIED hashes, all pointing at one
        # real file. The O(n^2) row compares each entry's digest against every
        # prior entry; supplying distinct hashes means no duplicate is ever
        # found, so the comparison loop runs to completion every time -- the
        # worst case, and the one the row asks about.
        if dict_file is None:
            raise RuntimeError(
                "harness error: the dcz-dicts workload needs a dictionary "
                "file and none was provided"
            )
        entries = ""
        for i in range(scale):
            entries += f"    zstd_dcz_dict_file {dict_file} {_dict_digest(i)};\n"
        body = (
            f"{entries}"
            f"    location / {{\n"
            f"        zstd on;\n"
            f"        gzip_vary on;\n"
            f"    }}\n"
        )

    else:
        raise RuntimeError(f"harness error: unknown workload {workload!r}")

    listen_port = pick_free_port()

    conf = root / "nginx.conf"
    conf.write_text(
        f"""daemon off;
master_process on;
worker_processes 1;
{load}error_log {root}/error.log crit;
pid {root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        # A high, unprivileged port. `nginx -t` genuinely bind()s the listen
        # socket as part of the test, so a privileged port (or one already in
        # use) makes the test FAIL after parsing succeeded -- the harness would
        # then be timing a config load that aborted early. Caught on the first
        # real run with port 1: "bind() to 127.0.0.1:1 failed (13: Permission
        # denied)" while the syntax check itself had passed.
        listen 127.0.0.1:{listen_port};
{body}    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def measure_config_test(
    arm: Arm, conf: pathlib.Path, root: pathlib.Path
) -> ConfigSample:
    """Run `nginx -t` once, timing it and sampling peak RSS throughout.

    RSS is polled from the parent rather than read once after exit, because
    config load is a short spike (see the module docstring). The poll interval
    is deliberately tight: a 4000-location parse can complete in well under a
    second, and a 100ms interval could sample it twice.
    """
    cmd = [str(arm.binary), "-t", "-p", str(root), "-c", str(conf)]
    peak_kb = 0

    # Output goes to a FILE, never to a pipe. `nginx -t` can emit one warning
    # per location on some of these workloads, so at 2000+ locations it may
    # produce far more than a 64 KB pipe buffer holds. (The gzip_vary-off
    # warning that originally motivated this is gone as of G5, but other
    # per-location warnings keep the hazard live and a file costs nothing.) With stdout=PIPE and the read deferred
    # until after the poll loop, nginx blocks in anon_pipe_write forever while
    # the harness waits for it to exit -- a deadlock that presents as an
    # arbitrarily slow config load, i.e. as a plausible measurement. Caught
    # here on the very first real run: the child sat at 0.0% CPU in
    # anon_pipe_write while the harness reported nothing.
    out_path = root / "nginx-t.out"
    started = time.monotonic()
    with open(out_path, "w", encoding="utf-8") as out_fh:
        proc = subprocess.Popen(cmd, stdout=out_fh, stderr=subprocess.STDOUT)
        status_path = pathlib.Path(f"/proc/{proc.pid}/status")
        while proc.poll() is None:
            try:
                for line in status_path.read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        peak_kb = max(peak_kb, int(line.split()[1]))
                        break
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
            time.sleep(0.002)
    elapsed = time.monotonic() - started
    output = out_path.read_text(encoding="utf-8", errors="replace")

    ok = proc.returncode == 0
    return ConfigSample(
        seconds=elapsed,
        peak_rss_kb=peak_kb,
        ok=ok,
        detail="" if ok else output.strip()[:400],
    )


def evaluate_scale_self_check(
    results: dict[int, ConfigSample], scales: list[int]
) -> None:
    """The harness's negative control on ITSELF, not on the module.

    Raises RuntimeError (a harness error) unless the generated configs
    demonstrably make config load more expensive as scale rises. If they do
    not, this harness is measuring process startup rather than config scale,
    and every number it would go on to print for a candidate fix would be
    noise dressed as a measurement.

    Pure and side-effect-free by design, specifically so it can be exercised
    directly by the synthetic tests below instead of only being reachable by
    actually running nginx. This mirrors
    ab_bench.py::evaluate_contention_self_check(), and exists for the same
    reason: on that harness, three successive self-checks passed on input that
    proved nothing before one held.
    """
    if len(scales) < 2:
        raise RuntimeError(
            "harness self-check FAILED: a config-scale curve needs at least "
            "two scale points; one point cannot show a trend."
        )

    lo_scale, hi_scale = min(scales), max(scales)
    lo, hi = results.get(lo_scale), results.get(hi_scale)

    if lo is None or hi is None:
        raise RuntimeError(
            "harness self-check FAILED: missing a measurement at "
            f"{lo_scale if lo is None else hi_scale} locations/entries, so no "
            "curve can be established."
        )

    if not lo.ok or not hi.ok:
        bad = lo if not lo.ok else hi
        raise RuntimeError(
            "harness self-check FAILED: `nginx -t` did not accept the "
            f"generated config ({bad.detail or 'no output'}). A rejected "
            "config is not a fast config -- it never did the work being "
            "measured."
        )

    # ABSOLUTE floor first: two equal-and-tiny timings dominated by fork+exec
    # jitter can satisfy any purely relative ratio through noise alone. This
    # is the exact failure ab_bench.py hit when `0.0 >= 0.0 * 1.5` evaluated
    # True and reported an all-miss run as a clean decay.
    if hi.seconds < SCALE_MIN_HI_SECONDS:
        raise RuntimeError(
            "harness self-check FAILED: the largest scale point "
            f"({hi_scale}) loaded in {hi.seconds * 1000:.1f}ms, below the "
            f"{SCALE_MIN_HI_SECONDS * 1000:.0f}ms floor. At that duration the "
            "measurement is dominated by process startup jitter, so a ratio "
            "against the small config would be noise, not a scale curve. "
            "Raise the scale points rather than lowering this floor."
        )

    # STRICT relative rise: `>`, never `>=`, so two equal costs cannot be read
    # as a rising curve.
    if not hi.seconds > lo.seconds * SCALE_MIN_RELATIVE_RISE:
        raise RuntimeError(
            "harness self-check FAILED: config-load cost did not rise with "
            f"scale. At {lo_scale} the load took {lo.seconds * 1000:.1f}ms; "
            f"at {hi_scale} it took {hi.seconds * 1000:.1f}ms (need strictly "
            f"> {SCALE_MIN_RELATIVE_RISE}x). This harness exists to price "
            "per-location and per-entry config work; a flat curve means the "
            "generated configs never exercised it, so any before/after "
            "difference reported from this run would be a workload artifact "
            "rather than a measurement. Check that the generated directives "
            "are actually reaching the module's merge path."
        )


def run_workload(
    arms: list[Arm],
    workload: str,
    scales: list[int],
    rounds: int,
    dict_file: pathlib.Path | None,
) -> dict[str, dict[int, ConfigSample]]:
    """Interleave the arms round by round, returning per-arm medians.

    Interleaving (not A-then-B) so machine drift is shared by both arms; see
    the module docstring.
    """
    raw: dict[str, dict[int, list[ConfigSample]]] = {
        arm.label: {scale: [] for scale in scales} for arm in arms
    }

    for round_index in range(rounds):
        for arm in arms:
            for scale in scales:
                with tempfile.TemporaryDirectory(prefix="config_bench-") as tmp:
                    root = pathlib.Path(tmp)
                    (root / "logs").mkdir(parents=True, exist_ok=True)
                    conf = generate_config(root, arm, workload, scale, dict_file)
                    sample = measure_config_test(arm, conf, root)
                raw[arm.label][scale].append(sample)
        print(
            f"  round {round_index + 1}/{rounds} done ({workload})",
            file=sys.stderr,
        )

    medians: dict[str, dict[int, ConfigSample]] = {}
    for label, by_scale in raw.items():
        medians[label] = {}
        for scale, samples in by_scale.items():
            ok = all(s.ok for s in samples)
            medians[label][scale] = ConfigSample(
                seconds=statistics.median(s.seconds for s in samples),
                peak_rss_kb=int(statistics.median(s.peak_rss_kb for s in samples)),
                ok=ok,
                detail=next((s.detail for s in samples if not s.ok), ""),
            )
    return medians


def print_table(
    workload: str, scales: list[int], medians: dict[str, dict[int, ConfigSample]]
) -> None:
    print()
    print(f"== config load: {workload} (median of rounds) ==")
    print(f"{'arm':<20} {'scale':>8} {'nginx -t':>12} {'peak RSS':>12}")
    for label, by_scale in medians.items():
        for scale in scales:
            s = by_scale[scale]
            print(
                f"{label:<20} {scale:>8} "
                f"{s.seconds * 1000:>10.1f}ms "
                f"{s.peak_rss_kb / 1024:>10.1f}MB"
            )

    labels = list(medians)
    if len(labels) == 2:
        a, b = labels
        print()
        print(f"{'scale':>8} {'time delta':>14} {'RSS delta':>14}")
        for scale in scales:
            sa, sb = medians[a][scale], medians[b][scale]
            t_delta = (
                (sb.seconds - sa.seconds) / sa.seconds * 100 if sa.seconds else 0.0
            )
            r_delta = (
                (sb.peak_rss_kb - sa.peak_rss_kb) / sa.peak_rss_kb * 100
                if sa.peak_rss_kb
                else 0.0
            )
            print(f"{scale:>8} {t_delta:>+13.1f}% {r_delta:>+13.1f}%")
        print(f"(delta = {b} relative to {a}; negative is faster/smaller)")


def _sample(seconds: float, rss_kb: int = 4096, ok: bool = True) -> ConfigSample:
    return ConfigSample(seconds=seconds, peak_rss_kb=rss_kb, ok=ok)


def test_scale_self_check_negative_control() -> None:
    """Exercise the self-check against input it MUST reject, plus one it must
    accept. Synthetic samples only -- no nginx, no config generation.

    Each rejected case below is a way a config-load harness can report a
    confident number while measuring nothing, which is precisely the defect
    class that shipped three times in ab_bench.py before its own check held.
    """
    scales = [10, 4000]

    def must_reject(name: str, results: dict[int, ConfigSample]) -> None:
        try:
            evaluate_scale_self_check(results, scales)
        except RuntimeError:
            return
        raise AssertionError(
            f"self-check accepted {name}, which proves nothing about config scale"
        )

    # A flat curve: the config got 400x bigger and cost the same. The harness
    # is timing process startup.
    must_reject("a flat cost curve", {10: _sample(0.20), 4000: _sample(0.20)})

    # An inverted curve: bigger config, less time. Noise, not a measurement.
    must_reject("an inverted curve", {10: _sample(0.30), 4000: _sample(0.10)})

    # A rise that is real but below the floor: 1.2x is inside run-to-run
    # jitter for a process this short.
    must_reject(
        "a rise below the relative floor",
        {10: _sample(0.20), 4000: _sample(0.24)},
    )

    # Both points tiny. The ratio is a healthy 3x, but at sub-millisecond
    # durations it is fork+exec jitter -- this is the case a purely relative
    # check would wave through.
    must_reject(
        "a large ratio between two sub-floor timings",
        {10: _sample(0.0002), 4000: _sample(0.0006)},
    )

    # Exactly at the relative boundary. `>` not `>=`, so this must fail.
    must_reject(
        "a rise exactly at the boundary",
        {10: _sample(0.10), 4000: _sample(0.10 * SCALE_MIN_RELATIVE_RISE)},
    )

    # A config nginx rejected. Fast because it never did the work.
    must_reject(
        "a rejected config",
        {10: _sample(0.20), 4000: _sample(0.90, ok=False)},
    )

    # A missing measurement at one end: no curve exists.
    must_reject("a missing high-scale sample", {10: _sample(0.20)})

    # One scale point cannot show a trend.
    try:
        evaluate_scale_self_check({10: _sample(0.20)}, [10])
    except RuntimeError:
        pass
    else:
        raise AssertionError("self-check accepted a single scale point")

    # The genuine article: a clear superlinear rise, well clear of both
    # floors. This must pass, or the check rejects everything and is useless.
    evaluate_scale_self_check({10: _sample(0.06), 4000: _sample(1.80)}, scales)


def run_self_test() -> int:
    test_scale_self_check_negative_control()
    print(
        "self-test: OK -- scale self-check rejects flat, inverted, "
        "sub-floor, boundary, rejected-config and missing-sample input, "
        "and accepts a genuine curve"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Config-load A/B benchmark for the zstd nginx module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--arm-a", help="path/to/nginx[:label]")
    parser.add_argument("--arm-b", help="path/to/nginx[:label] (optional)")
    parser.add_argument(
        "--workload",
        default="locations-same-profile",
        choices=sorted(WORKLOAD_SCALES),
        help="which config shape to generate (default: %(default)s)",
    )
    parser.add_argument(
        "--scales",
        help="comma-separated scale points, overriding the workload default",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help="interleaved rounds per arm (default: %(default)s)",
    )
    parser.add_argument("--json", help="write results to this path as JSON")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the harness's own oracle and exit; runs no nginx",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if not args.arm_a:
        parser.error("--arm-a is required (or use --self-test)")

    arms: list[Arm] = []
    for spec in filter(None, [args.arm_a, args.arm_b]):
        path, label = parse_arm(spec)
        binary = pathlib.Path(path).resolve()
        if not binary.exists():
            raise RuntimeError(f"harness error: no such nginx binary: {binary}")
        arms.append(Arm(label=label, binary=binary))

    if len({a.label for a in arms}) != len(arms):
        raise RuntimeError(
            "harness error: both arms have the same label; give one an "
            "explicit `path:label` so the table can tell them apart"
        )

    scales = (
        [int(x) for x in args.scales.split(",")]
        if args.scales
        else WORKLOAD_SCALES[args.workload]
    )

    dict_file: pathlib.Path | None = None
    tmp_dict: tempfile.TemporaryDirectory | None = None
    if args.workload == "dcz-dicts":
        tmp_dict = tempfile.TemporaryDirectory(prefix="config_bench-dict-")
        dict_file = pathlib.Path(tmp_dict.name) / "dict.bin"
        dict_file.write_bytes(os.urandom(4096))

    try:
        medians = run_workload(arms, args.workload, scales, args.rounds, dict_file)

        # The self-check runs against the FIRST arm -- the baseline. If the
        # baseline shows no scale curve, the workload never exercised the code
        # path, and comparing a second arm against it is meaningless.
        evaluate_scale_self_check(medians[arms[0].label], scales)

        print_table(args.workload, scales, medians)

        if args.json:
            payload = {
                "workload": args.workload,
                "scales": scales,
                "rounds": args.rounds,
                "arms": {
                    label: {
                        str(scale): dataclasses.asdict(sample)
                        for scale, sample in by_scale.items()
                    }
                    for label, by_scale in medians.items()
                },
            }
            pathlib.Path(args.json).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
            print(f"\nwrote {args.json}")
    finally:
        if tmp_dict is not None:
            tmp_dict.cleanup()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"{exc}", file=sys.stderr)
        sys.exit(2)
