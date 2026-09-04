#!/usr/bin/env python3
"""CPU cache counter-delta recipe for the data-layout repack optimization row.

HYBRID CPU PINNING STRATEGY
-----------------------------
This host is a hybrid Intel 12th-gen (P-core + E-core) CPU: perf stat splits
every event across two PMUs (cpu_core/* and cpu_atom/*), and the non-pinned
core type returns <not counted> with 0.00% enable time. Naive perf stat then
yields half-empty, non-comparable numbers.

Solution: pin the workload to ONE core type and select explicit PMU-qualified
event names. Hybrid CPUs declare their cores via /sys/devices/cpu_core/cpus
and /sys/devices/cpu_atom/cpus; this script detects both and pins to P-cores
(the first range) by default. Pass --core-type=E to pin to E-cores instead.

Performance core (P) CPUs 0-15, Efficiency core (E) CPUs 16-31 on this host.

PURPOSE
-------
Measure the cache-miss and instruction-count overhead of dictionary negotiation
on the request-hot path. The optimization row proposes splitting a 104-byte
struct-of-arrays lookup into two arrays (a 40-byte index + pointer indirection)
to reduce cache misses on negotiation. This recipe establishes:

1. A baseline of cache-misses, cache-references, instructions, and cycles for
   the current code across 1, 4, and 16 configured dictionaries, with a hit
   and full-scan miss at each size
2. An A/B delta normalized by successful measured requests. perf attaches only
   to the pinned nginx worker after preflight and warmup, so harness, backend,
   wrk, startup, fixture, and cleanup work cannot contaminate the counters

The repack row is retained ONLY if the counter delta supports the "third-cacheline"
claim (fewer cache misses). Struct size reduction alone (pahole) does not retain
the row -- smaller struct != fewer misses.

USAGE
-----
    # Baseline: measure current code
    python3 ci/tools/perf_stat_recipe.py --nginx /path/to/nginx --json baseline.json

    # After optimization: measure again
    python3 ci/tools/perf_stat_recipe.py --nginx /path/to/nginx --json optimized.json

    # Compare
    python3 ci/tools/perf_stat_recipe.py --compare baseline.json optimized.json

    # Preserve the original plain-zstd single measurement when needed
    python3 ci/tools/perf_stat_recipe.py --nginx /path/to/nginx \
        --workload zstd --json zstd.json

Environment: requires
  - perf (installed at /usr/bin/perf)
  - /proc/sys/kernel/perf_event_paranoid <= 1 (this host has 1)
  - ab_bench.py in the same ci/tools directory
  - A working nginx binary
  - wrk load-testing tool

Exit status
-----------
0 on success (measurements recorded or comparison printed)
1 on harness error (missing tools, bad args, workload failed)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

TOOLS_DIR = pathlib.Path(__file__).resolve().parent
DCZ_DICTIONARY_COUNTS = (1, 4, 16)
DCZ_CASES = ("hit", "miss")


def cpu_identity() -> str:
    """Return stable CPU/PMU identity fields for cross-run compatibility."""
    wanted = ("vendor_id", "cpu family", "model", "stepping", "model name")
    fields: dict[str, str] = {}
    for line in pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            break
        key, separator, value = line.partition(":")
        if separator and key.strip() in wanted:
            fields[key.strip()] = value.strip()
    if not all(field in fields for field in wanted):
        raise RuntimeError("could not determine CPU identity from /proc/cpuinfo")
    return "; ".join(f"{field}={fields[field]}" for field in wanted)


@dataclasses.dataclass
class PerfCounters:
    """CPU cache and execution counters from perf stat."""

    cache_misses: int
    cache_references: int
    instructions: int
    cycles: int

    def miss_rate(self) -> float:
        """Cache miss rate (misses / references)."""
        if self.cache_references == 0:
            return 0.0
        return self.cache_misses / self.cache_references

    def ipc(self) -> float:
        """Instructions per cycle."""
        if self.cycles == 0:
            return 0.0
        return self.instructions / self.cycles

    def to_dict(self) -> dict:
        """Serialize to JSON."""
        return {
            "cache_misses": self.cache_misses,
            "cache_references": self.cache_references,
            "instructions": self.instructions,
            "cycles": self.cycles,
            "miss_rate": self.miss_rate(),
            "ipc": self.ipc(),
        }

    @staticmethod
    def from_dict(d: dict) -> PerfCounters:
        """Deserialize from JSON."""
        return PerfCounters(
            cache_misses=d["cache_misses"],
            cache_references=d["cache_references"],
            instructions=d["instructions"],
            cycles=d["cycles"],
        )


def normalize_counters(
    counters: PerfCounters, successful_requests: int
) -> dict[str, float]:
    """Return raw hardware counts per successful measured request."""
    if successful_requests <= 0:
        raise RuntimeError("cannot normalize perf counters without successful requests")
    return {
        "cache_misses": counters.cache_misses / successful_requests,
        "cache_references": counters.cache_references / successful_requests,
        "instructions": counters.instructions / successful_requests,
        "cycles": counters.cycles / successful_requests,
    }


def successful_requests_from_bench(result: dict) -> int:
    """Read successful requests from the measured release-pass window."""
    meta = result.get("meta", {})
    meta_total = meta.get("successful_requests")
    if isinstance(meta_total, int):
        return meta_total

    total = 0
    for arm in result.get("release", {}).values():
        for concurrency in arm.values():
            for samples in concurrency.values():
                for sample in samples:
                    total += max(sample["requests"] - sample["errors"], 0)
    return total


def dcz_scenarios() -> tuple[tuple[int, str], ...]:
    """Fixed lookup-depth matrix used by the repack measurement."""
    return tuple(
        (dictionary_count, case)
        for dictionary_count in DCZ_DICTIONARY_COUNTS
        for case in DCZ_CASES
    )


def build_dcz_bench_command(
    nginx_path: pathlib.Path,
    dictionary_count: int,
    case: str,
    result_path: pathlib.Path,
    perf_path: pathlib.Path,
    perf_events: str,
) -> list[str]:
    """Build one deterministic dcz hit/miss ab_bench invocation."""
    return [
        "python3",
        str(TOOLS_DIR / "ab_bench.py"),
        "--arm-a",
        f"{nginx_path}:baseline",
        "--rounds",
        "1",
        "--workers",
        "1",
        "--duration",
        "5s",
        "--workload",
        "dcz",
        "--dcz-dictionaries",
        str(dictionary_count),
        "--dcz-case",
        case,
        "--json",
        str(result_path),
        "--perf-stat-output",
        str(perf_path),
        "--perf-events",
        perf_events,
    ]


def detect_hybrid_cores() -> tuple[str, str, int]:
    """Detect P-core and E-core CPU ranges on hybrid x86 CPU.

    Returns
    -------
    (pcore_range: str, ecore_range: str, pcore_id: int)
        pcore_range: space-separated CPU ids
            (e.g. "0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")
        ecore_range: space-separated CPU ids
            (e.g. "16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31")
        pcore_id: first P-core id (0 on this host)

    Raises
    ------
    RuntimeError if hybrid CPU detection fails
    """
    try:
        with open("/sys/devices/cpu_core/cpus", encoding="utf-8") as f:
            pcore_str = f.read().strip()
        with open("/sys/devices/cpu_atom/cpus", encoding="utf-8") as f:
            ecore_str = f.read().strip()
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Hybrid CPU detection failed: {exc}. "
            "This recipe requires /sys/devices/cpu_core/cpus and "
            "/sys/devices/cpu_atom/cpus. Non-hybrid CPUs are not supported."
        ) from exc

    # Parse ranges like "0-15" into space-separated "0 1 2 3 ..."
    def expand_range(range_str: str) -> str:
        """Convert '0-15' to '0 1 2 3 ... 15'."""
        parts: list[str] = []
        for part in range_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                parts.extend(str(i) for i in range(int(start), int(end) + 1))
            else:
                parts.append(part)
        return " ".join(parts)

    pcore_ids = expand_range(pcore_str)
    ecore_ids = expand_range(ecore_str)
    pcore_id = int(pcore_str.split("-")[0].split(",")[0])

    return pcore_ids, ecore_ids, pcore_id


def parse_perf_output(
    perf_output: str,
    core_type: str,
) -> dict[str, int]:
    """Parse perf stat output for cache and execution counters.

    Parameters
    ----------
    perf_output : str
        perf stat stderr output
    core_type : str
        P or E, for error messaging

    Returns
    -------
    dict[str, int]
        Counters: cache_misses, cache_references, instructions, cycles

    Raises
    ------
    RuntimeError if output is invalid or <not counted>
    """
    counters = {}
    lines = perf_output.split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "time elapsed" in line:
            continue

        # Extract number and event name
        match = re.match(
            r"^([\d,]+|<not counted>)\s+(cpu_\w+/[\w\-]+/)",
            line,
        )
        if not match:
            continue

        count_str, event = match.groups()

        # Skip <not counted> entries
        if count_str == "<not counted>":
            raise RuntimeError(
                f"perf stat returned <not counted> for {event} on {core_type}"
                f"-cores. Workload pinned to wrong core type. "
                f"Output:\n{perf_output}"
            )

        # Convert "7,614" to 7614
        count = int(count_str.replace(",", ""))

        # Map event name to counter key
        if "cache-misses" in event:
            counters["cache_misses"] = count
        elif "cache-references" in event:
            counters["cache_references"] = count
        elif "instructions" in event:
            counters["instructions"] = count
        elif "cycles" in event:
            counters["cycles"] = count

    # Validate we got all four counters
    required = {"cache_misses", "cache_references", "instructions", "cycles"}
    if not required.issubset(counters.keys()):
        missing = required - counters.keys()
        raise RuntimeError(
            f"perf stat output missing counters: {missing}.\nOutput:\n{perf_output}"
        )

    return counters


def run_perf_stat(
    command: list[str],
    cpu_mask: str,
    core_type: str,
) -> PerfCounters:
    """Run perf stat on a command pinned to one core type.

    Parameters
    ----------
    command : list[str]
        Command to run
    cpu_mask : str
        Space-separated CPU ids
    core_type : str
        P or E, for log messaging

    Returns
    -------
    PerfCounters
        Parsed cache and execution counters

    Raises
    ------
    RuntimeError if perf stat fails or returns no counts
    """
    # Use taskset to pin to the CPU mask
    full_cmd = ["taskset", "-c", cpu_mask.replace(" ", ",")] + command

    # Run perf stat with explicit cpu_core/* or cpu_atom/* PMU events.
    pmu = "cpu_core" if core_type == "P" else "cpu_atom"
    perf_events = [
        f"{pmu}/cache-misses/",
        f"{pmu}/cache-references/",
        f"{pmu}/instructions/",
        f"{pmu}/cycles/",
    ]

    perf_cmd = ["/usr/bin/perf", "stat", "-e", ",".join(perf_events)] + full_cmd

    print(f"[{core_type}-core] Running: {' '.join(perf_cmd)}", file=sys.stderr)

    try:
        result = subprocess.run(
            perf_cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"perf stat timed out after 600s. Command: {' '.join(perf_cmd)}"
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "/usr/bin/perf not found. Install linux-tools or perf package."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"perf stat failed with exit code {result.returncode}.\n"
            f"stderr: {result.stderr}\n"
            f"stdout: {result.stdout}"
        )

    counters_dict = parse_perf_output(result.stderr, core_type)

    print(
        f"[{core_type}-core] counters: cache_misses={counters_dict['cache_misses']}, "
        f"cache_references={counters_dict['cache_references']}, "
        f"instructions={counters_dict['instructions']}, "
        f"cycles={counters_dict['cycles']}"
    )

    return PerfCounters(**counters_dict)


def qualified_perf_events(core_type: str) -> str:
    """Return the four PMU-qualified events for one hybrid core type."""
    pmu = "cpu_core" if core_type == "P" else "cpu_atom"
    return ",".join(
        f"{pmu}/{event}/"
        for event in ("cache-misses", "cache-references", "instructions", "cycles")
    )


def kill_process_group(process: subprocess.Popen) -> None:
    """Kill and reap a detached benchmark process group."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def wait_process_without_reaping(process: subprocess.Popen, timeout: float) -> bool:
    """Wait for exit while retaining the leader PID for group cleanup."""
    deadline = time.monotonic() + timeout
    while True:
        status = os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
        if status is not None:
            return status.si_code == os.CLD_EXITED and status.si_status == 0
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(0.05)


def run_pinned_bench(command: list[str], cpu_mask: str) -> None:
    """Run a benchmark pinned to one core set; perf attaches inside it."""
    full_command = ["taskset", "-c", cpu_mask.replace(" ", ","), *command]
    with (
        tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout_file,
        tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr_file,
    ):
        process = subprocess.Popen(
            full_command,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            start_new_session=True,
        )
        try:
            succeeded = wait_process_without_reaping(process, 600)
        except subprocess.TimeoutExpired as exc:
            kill_process_group(process)
            raise RuntimeError(
                "benchmark timed out after 600s; process group killed"
            ) from exc
        except BaseException:
            kill_process_group(process)
            raise
        if not succeeded:
            kill_process_group(process)
            stdout_file.seek(0)
            stderr_file.seek(0)
            raise RuntimeError(
                f"benchmark failed with exit code {process.returncode}.\n"
                f"stderr: {stderr_file.read()}\nstdout: {stdout_file.read()}"
            )
        process.wait(timeout=10)


def measure_baseline(
    nginx_path: str | pathlib.Path,
    output_json: str | None = None,
    core_type: str = "P",
) -> PerfCounters:
    """Measure cache counters for ab_bench.py release pass.

    Parameters
    ----------
    nginx_path : str or Path
        Path to nginx binary
    output_json : str | None
        If provided, save result to this JSON file
    core_type : str
        'P' (P-cores, default) or 'E' (E-cores)

    Returns
    -------
    PerfCounters
        Measured counters
    """
    nginx_path_obj = pathlib.Path(nginx_path).resolve()
    if not nginx_path_obj.exists():
        raise RuntimeError(f"nginx binary not found: {nginx_path_obj}")

    # Run ab_bench.py release pass under perf stat
    # Use 1 round and 5s duration for a quick baseline (faster than 3x10s default)
    bench_cmd = [
        "python3",
        str(TOOLS_DIR / "ab_bench.py"),
        "--arm-a",
        f"{nginx_path_obj}:baseline",
        "--rounds",
        "1",
        "--duration",
        "5s",  # Short measurement window
    ]

    # Detect hybrid CPU ranges
    pcore_ids, ecore_ids, _ = detect_hybrid_cores()
    cpu_mask = pcore_ids if core_type == "P" else ecore_ids

    # Run the benchmark under perf stat
    counters = run_perf_stat(bench_cmd, cpu_mask, core_type)

    # Save to JSON if requested
    if output_json:
        result = {
            "core_type": core_type,
            "cpu_mask": cpu_mask,
            "command": " ".join(bench_cmd),
            "counters": counters.to_dict(),
        }
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Saved to {output_json}")

    return counters


def measure_dcz_matrix(
    nginx_path: str | pathlib.Path,
    output_json: str | None = None,
    core_type: str = "P",
) -> dict[str, dict]:
    """Measure the fixed 1/4/16-dictionary hit/miss matrix."""
    nginx_path_obj = pathlib.Path(nginx_path).resolve()
    if not nginx_path_obj.exists():
        raise RuntimeError(f"nginx binary not found: {nginx_path_obj}")

    pcore_ids, ecore_ids, _ = detect_hybrid_cores()
    cpu_mask = pcore_ids if core_type == "P" else ecore_ids
    identity = cpu_identity()
    scenarios: dict[str, dict] = {}

    with tempfile.TemporaryDirectory(prefix="zstd-perf-stat-") as temp_dir:
        temp_root = pathlib.Path(temp_dir)
        for dictionary_count, case in dcz_scenarios():
            name = f"dicts-{dictionary_count}-{case}"
            bench_json = temp_root / f"{name}.json"
            perf_output = temp_root / f"{name}.perf"
            command = build_dcz_bench_command(
                nginx_path_obj,
                dictionary_count,
                case,
                bench_json,
                perf_output,
                qualified_perf_events(core_type),
            )
            run_pinned_bench(command, cpu_mask)
            try:
                bench_result = json.loads(bench_json.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"ab_bench produced no usable JSON for {name}: {exc}"
                ) from exc
            try:
                counters = PerfCounters(
                    **parse_perf_output(
                        perf_output.read_text(encoding="utf-8"), core_type
                    )
                )
            except FileNotFoundError as exc:
                raise RuntimeError(f"perf produced no output for {name}") from exc
            if bench_result.get("meta", {}).get("perf_scope") != (
                "nginx-workers-measured-release"
            ):
                raise RuntimeError(
                    f"ab_bench did not prove worker-only perf for {name}"
                )

            successful_requests = successful_requests_from_bench(bench_result)
            per_request = normalize_counters(counters, successful_requests)
            scenarios[name] = {
                "dictionary_count": dictionary_count,
                "case": case,
                "command": command,
                "measured_successful_requests": successful_requests,
                "engagement": bench_result.get("meta", {}).get("engagement"),
                "counters": counters.to_dict(),
                "per_successful_request": per_request,
            }

    result = {
        "schema_version": 2,
        "workload": "dcz",
        "core_type": core_type,
        "cpu_mask": cpu_mask,
        "cpu_identity": identity,
        "normalization": "measured_successful_requests",
        "scenarios": scenarios,
    }
    if output_json:
        pathlib.Path(output_json).write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        print(f"Saved to {output_json}")
    return scenarios


def print_counters(
    label: str,
    counters: PerfCounters,
) -> None:
    """Print a set of counter values."""
    print(f"\n{label}:")
    print(f"  cache_misses:      {counters.cache_misses:>12,}")
    print(f"  cache_references:  {counters.cache_references:>12,}")
    print(f"  instructions:      {counters.instructions:>12,}")
    print(f"  cycles:            {counters.cycles:>12,}")
    print(f"  miss_rate:         {counters.miss_rate():>12.2%}")
    print(f"  IPC:               {counters.ipc():>12.2f}")


@dataclasses.dataclass
class CounterDelta:
    """Delta between two measurements."""

    cache_misses: int
    cache_references: int
    instructions: int
    cycles: int
    miss_rate: float
    ipc: float

    @staticmethod
    def compute(baseline: PerfCounters, optimized: PerfCounters) -> CounterDelta:
        """Compute delta between baseline and optimized."""
        return CounterDelta(
            cache_misses=optimized.cache_misses - baseline.cache_misses,
            cache_references=optimized.cache_references - baseline.cache_references,
            instructions=optimized.instructions - baseline.instructions,
            cycles=optimized.cycles - baseline.cycles,
            miss_rate=optimized.miss_rate() - baseline.miss_rate(),
            ipc=optimized.ipc() - baseline.ipc(),
        )


def _percent_delta(baseline: float, optimized: float) -> float:
    if baseline == 0:
        raise RuntimeError("cannot compare against a zero normalized counter")
    return (optimized - baseline) / baseline


def compare_dcz_results(baseline_result: dict, optimized_result: dict) -> None:
    """Compare dcz matrix cells using counters per successful request."""
    identity_fields = (
        "schema_version",
        "workload",
        "core_type",
        "cpu_mask",
        "cpu_identity",
        "normalization",
    )
    expected_identity = {
        "schema_version": 2,
        "workload": "dcz",
        "normalization": "measured_successful_requests",
    }
    for field, value in expected_identity.items():
        if baseline_result.get(field) != value or optimized_result.get(field) != value:
            raise RuntimeError(f"dcz comparison requires {field}={value!r}")
    for field in identity_fields:
        if baseline_result.get(field) != optimized_result.get(field):
            raise RuntimeError(f"dcz comparison requires matching {field}")
    for result in (baseline_result, optimized_result):
        if result.get("core_type") not in ("P", "E"):
            raise RuntimeError("dcz comparison requires core_type P or E")
        if not isinstance(result.get("cpu_mask"), str) or not result["cpu_mask"]:
            raise RuntimeError("dcz comparison requires a non-empty cpu_mask")
        if (
            not isinstance(result.get("cpu_identity"), str)
            or not result["cpu_identity"]
        ):
            raise RuntimeError("dcz comparison requires a non-empty cpu_identity")

    baseline_cells = baseline_result.get("scenarios", {})
    optimized_cells = optimized_result.get("scenarios", {})
    expected = {f"dicts-{count}-{case}" for count, case in dcz_scenarios()}
    if set(baseline_cells) != expected or set(optimized_cells) != expected:
        raise RuntimeError(
            "dcz comparison requires matching 1/4/16 dictionary hit/miss matrices"
        )

    for dictionary_count, case in dcz_scenarios():
        name = f"dicts-{dictionary_count}-{case}"
        for cell in (baseline_cells[name], optimized_cells[name]):
            if (
                cell.get("dictionary_count") != dictionary_count
                or cell.get("case") != case
            ):
                raise RuntimeError(f"dcz scenario metadata does not match {name}")
            expected_encoding = "dcz" if case == "hit" else "zstd"
            engagement = cell.get("engagement")
            if not isinstance(engagement, dict) or set(engagement.values()) != {
                expected_encoding
            }:
                raise RuntimeError(
                    f"dcz scenario {name} requires {expected_encoding} engagement"
                )

    print("\nDCZ COUNTERS PER SUCCESSFUL REQUEST")
    header = (
        f"{'scenario':<16}{'base req':>11}{'opt req':>11}"
        f"{'miss delta':>13}{'ref delta':>12}{'insn delta':>13}"
        f"{'cycle delta':>14}"
    )
    print(header)
    print("-" * len(header))
    for dictionary_count, case in dcz_scenarios():
        name = f"dicts-{dictionary_count}-{case}"
        baseline = baseline_cells[name]
        optimized = optimized_cells[name]
        baseline_norm = normalize_counters(
            PerfCounters.from_dict(baseline["counters"]),
            baseline["measured_successful_requests"],
        )
        optimized_norm = normalize_counters(
            PerfCounters.from_dict(optimized["counters"]),
            optimized["measured_successful_requests"],
        )
        miss_delta = _percent_delta(
            baseline_norm["cache_misses"], optimized_norm["cache_misses"]
        )
        reference_delta = _percent_delta(
            baseline_norm["cache_references"],
            optimized_norm["cache_references"],
        )
        instruction_delta = _percent_delta(
            baseline_norm["instructions"], optimized_norm["instructions"]
        )
        cycle_delta = _percent_delta(baseline_norm["cycles"], optimized_norm["cycles"])
        print(
            f"{name:<16}{baseline['measured_successful_requests']:>11}"
            f"{optimized['measured_successful_requests']:>11}{miss_delta:>+12.1%}"
            f"{reference_delta:>+12.1%}{instruction_delta:>+13.1%}"
            f"{cycle_delta:>+14.1%}"
        )


def compare_results(baseline_json: str, optimized_json: str) -> None:
    """Compare two measurement runs.

    Parameters
    ----------
    baseline_json : str
        Path to baseline measurement result
    optimized_json : str
        Path to optimized measurement result
    """
    with open(baseline_json, encoding="utf-8") as f:
        baseline_result = json.load(f)
    with open(optimized_json, encoding="utf-8") as f:
        optimized_result = json.load(f)

    if "scenarios" in baseline_result or "scenarios" in optimized_result:
        compare_dcz_results(baseline_result, optimized_result)
        return

    baseline = PerfCounters.from_dict(baseline_result["counters"])
    optimized = PerfCounters.from_dict(optimized_result["counters"])

    print("\n" + "=" * 70)
    print("COUNTER DELTA ANALYSIS")
    print("=" * 70)

    print_counters("BASELINE (current code)", baseline)
    print_counters("OPTIMIZED (with repack)", optimized)

    delta = CounterDelta.compute(baseline, optimized)

    print("\nDELTA:")
    miss_pct = delta.cache_misses / baseline.cache_misses
    refs_pct = delta.cache_references / baseline.cache_references
    insns_pct = delta.instructions / baseline.instructions
    cycles_pct = delta.cycles / baseline.cycles
    print(f"  cache_misses:      {delta.cache_misses:>+12,} ({miss_pct:>+6.1%})")
    print(f"  cache_references:  {delta.cache_references:>+12,} ({refs_pct:>+6.1%})")
    print(f"  instructions:      {delta.instructions:>+12,} ({insns_pct:>+6.1%})")
    print(f"  cycles:            {delta.cycles:>+12,} ({cycles_pct:>+6.1%})")
    print(f"  miss_rate:         {delta.miss_rate:>+12.2%}")
    print(f"  IPC:               {delta.ipc:>+12.3f}")

    # Verdict
    print("\n" + "=" * 70)
    if delta.cache_misses < 0:
        claim_pct = delta.cache_misses / baseline.cache_misses
        print(
            f"✓ SUPPORTS CLAIM: {abs(delta.cache_misses):,} fewer "
            f"cache misses ({claim_pct:.1%})"
        )
        print("  Repack row retained.")
    else:
        support_pct = delta.cache_misses / baseline.cache_misses
        print(
            f"✗ DOES NOT SUPPORT: {delta.cache_misses:+,} cache misses "
            f"({support_pct:+.1%})"
        )
        print("  Repack row should be REFUTED.")
    print("=" * 70 + "\n")


def normalize_cli_argv(argv: list[str]) -> list[str]:
    """Map documented flag-first spellings onto the argparse subcommands."""
    if argv[:1] in (["-h"], ["--help"]):
        return argv
    if argv and argv[0] == "--compare":
        return ["compare", *argv[1:]]
    if argv and argv[0].startswith("-"):
        return ["measure", *argv]
    return argv


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # "measure" subcommand
    measure_parser = subparsers.add_parser(
        "measure",
        help="Measure baseline or optimized code",
        aliases=["baseline"],
    )
    measure_parser.add_argument(
        "--nginx",
        required=True,
        help="Path to nginx binary",
    )
    measure_parser.add_argument(
        "--json",
        help="Save result to JSON file",
    )
    measure_parser.add_argument(
        "--core-type",
        choices=["P", "E"],
        default="P",
        help="Pin to P-cores (default) or E-cores",
    )
    measure_parser.add_argument(
        "--workload",
        choices=("dcz", "zstd"),
        default="dcz",
        help="measure the dcz lookup matrix (default) or legacy zstd workload",
    )

    # "compare" subcommand
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare baseline and optimized measurements",
    )
    compare_parser.add_argument(
        "baseline",
        help="Baseline measurement JSON file",
    )
    compare_parser.add_argument(
        "optimized",
        help="Optimized measurement JSON file",
    )

    argv = normalize_cli_argv(sys.argv[1:])
    args = parser.parse_args(argv)

    if args.command in ("measure", "baseline"):
        if not args.nginx:
            parser.print_help()
            return 1
        try:
            if args.workload == "dcz":
                measure_dcz_matrix(
                    args.nginx,
                    output_json=args.json,
                    core_type=args.core_type,
                )
            else:
                measure_baseline(
                    args.nginx,
                    output_json=args.json,
                    core_type=args.core_type,
                )
            return 0
        except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    elif args.command == "compare":
        try:
            compare_results(args.baseline, args.optimized)
            return 0
        except (FileNotFoundError, json.JSONDecodeError, KeyError, RuntimeError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
