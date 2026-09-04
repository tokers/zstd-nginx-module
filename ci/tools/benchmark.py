#!/usr/bin/env python3
"""Reproducible compression benchmark: zstd levels vs gzip.

Measures compression ratio and single-threaded CPU throughput on
representative web payloads, using the same libzstd / zlib the host
nginx links against (the `zstd` and `gzip` CLIs). This is a *library*
benchmark — it characterises the codecs the module drives, not nginx
request overhead, so the numbers are stable and reproducible across
machines (throughput scales with CPU; ratio does not).

Usage:
    python3 ci/tools/benchmark.py                 # human table
    python3 ci/tools/benchmark.py --json results.json
    python3 ci/tools/benchmark.py --levels 1,3,9,19 --repeat 5

Exit non-zero only on harness error (missing zstd/gzip), never on a
"slow" result — this is measurement, not a pass/fail gate.
"""

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import time

# ci/tools/benchmark.py -> ci/tools -> ci -> repo root: THREE parents
# since the ci/ move (was tools/ at the root, where two sufficed).
REPO = pathlib.Path(__file__).resolve().parent.parent.parent


def build_payloads() -> dict[str, bytes]:
    """Representative, deterministic web payloads."""
    payloads: dict[str, bytes] = {}

    fixture = REPO / "ci" / "t" / "suite" / "test"
    if fixture.is_file():
        payloads["html-58k (test fixture)"] = fixture.read_bytes()

    # Highly compressible JSON-ish API response.
    row = b'{"id":%d,"name":"item-%d","active":true,"tags":["a","b","c"]}'
    payloads["json-api-256k"] = (
        b"[" + b",".join(row % (i, i) for i in range(4000)) + b"]"
    )

    # JS-like text with realistic redundancy.
    js_line = b"function handler_%d(req,res){return res.json({ok:true,n:%d});}\n"
    payloads["js-512k"] = b"".join(js_line % (i, i) for i in range(8000))

    # Low-entropy worst case (already-compressed-ish): pseudo-random.
    import random

    random.seed(1)  # deterministic
    payloads["random-256k (incompressible)"] = bytes(
        random.getrandbits(8) for _ in range(256 * 1024)
    )
    return payloads


def run_codec(cmd: list[str], data: bytes, repeat: int) -> tuple[int, float]:
    """Return (compressed_size, best wall-seconds over `repeat` runs)."""
    best = float("inf")
    out = b""
    for _ in range(repeat):
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, input=data, capture_output=True, check=True)
        dt = time.perf_counter() - t0
        best = min(best, dt)
        out = proc.stdout
    return len(out), best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--levels", default="1,3,6,9,19", help="comma-separated zstd levels"
    )
    ap.add_argument(
        "--repeat", type=int, default=3, help="runs per measurement (best time kept)"
    )
    ap.add_argument("--json", help="write machine-readable results here")
    args = ap.parse_args()

    zstd = shutil.which("zstd")
    gzip = shutil.which("gzip")
    if not zstd or not gzip:
        print("error: need both `zstd` and `gzip` on PATH", file=sys.stderr)
        return 2

    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    payloads = build_payloads()
    results: list[dict] = []

    header = f"{'payload':<30}{'codec':<10}{'in':>9}{'out':>9}{'ratio':>8}{'MB/s':>9}"
    print(header)
    print("-" * len(header))

    for name, data in payloads.items():
        n = len(data)

        gz_size, gz_t = run_codec([gzip, "-6", "-c"], data, args.repeat)
        gz_mbps = (n / gz_t) / 1e6
        results.append(
            {
                "payload": name,
                "codec": "gzip-6",
                "in": n,
                "out": gz_size,
                "ratio": n / gz_size,
                "mbps": gz_mbps,
            }
        )
        print(
            f"{name:<30}{'gzip-6':<10}{n:>9}{gz_size:>9}"
            f"{n / gz_size:>8.2f}{gz_mbps:>9.1f}"
        )

        for lv in levels:
            sz, t = run_codec([zstd, f"-{lv}", "-c", "-q"], data, args.repeat)
            mbps = (n / t) / 1e6
            results.append(
                {
                    "payload": name,
                    "codec": f"zstd-{lv}",
                    "in": n,
                    "out": sz,
                    "ratio": n / sz,
                    "mbps": mbps,
                }
            )
            print(
                f"{'':<30}{'zstd-' + str(lv):<10}{n:>9}{sz:>9}"
                f"{n / sz:>8.2f}{mbps:>9.1f}"
            )
        print()

    if args.json:
        meta = {
            "zstd_version": subprocess.run(
                [zstd, "--version"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip(),
            "commit": subprocess.run(
                ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip(),
            "repeat": args.repeat,
        }
        pathlib.Path(args.json).write_text(
            json.dumps({"meta": meta, "results": results}, indent=2)
        )
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
