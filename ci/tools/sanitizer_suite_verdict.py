#!/usr/bin/env python3
"""Fail closed on incomplete TAP suites and module-attributable sanitizer reports."""

from __future__ import annotations

import argparse
import glob
import re
import sys
from pathlib import Path

FINDING = re.compile(
    r"(?:(?:Address|Leak|UndefinedBehavior)Sanitizer:|runtime error:)",
    re.IGNORECASE,
)
MODULE = re.compile(r"(?:src/)?ngx_http_zstd(?:_[A-Za-z0-9_]+)?", re.IGNORECASE)
PLAN = re.compile(r"^1\.\.([0-9]+)(?:\s*#.*)?$")
RESULT = re.compile(r"^(?:not )?ok\s+([0-9]+)(?:\s|$)")
LOG_MARKER = re.compile(
    r"^(?:Bail out!|(?:not )?ok\s|1\.\.[0-9]+|"
    r"[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]+ \[[a-z]+\])"
)


def check_suite(spec: str) -> bool:
    try:
        label, path_text, status_text = spec.split(":", 2)
        status = int(status_text)
    except ValueError:
        print(
            f"invalid --suite value: {spec!r}; expected LABEL:PATH:STATUS",
            file=sys.stderr,
        )
        return False

    path = Path(path_text)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"{label}: cannot read TAP log {path}: {exc}", file=sys.stderr)
        return False

    ok = True
    if status != 0:
        print(f"{label}: suite exited {status}, expected 0", file=sys.stderr)
        ok = False
    if any(line.startswith("Bail out!") for line in lines):
        print(f"{label}: TAP bailout reported", file=sys.stderr)
        ok = False
    if any(line.startswith("not ok ") for line in lines):
        print(f"{label}: failing TAP result reported", file=sys.stderr)
        ok = False

    plans = [int(match.group(1)) for line in lines if (match := PLAN.match(line))]
    results = [int(match.group(1)) for line in lines if (match := RESULT.match(line))]
    if len(plans) != 1:
        print(
            f"{label}: expected exactly one TAP plan, found {len(plans)}",
            file=sys.stderr,
        )
        return False
    plan = plans[0]
    if plan <= 0 or len(results) != plan or sorted(results) != list(range(1, plan + 1)):
        print(
            f"{label}: TAP results do not exactly satisfy plan 1..{plan} "
            f"({len(results)} result lines)",
            file=sys.stderr,
        )
        ok = False
    if ok:
        print(f"{label}: suite exit 0 and all {plan} TAP results reported")
    return ok


def finding_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if FINDING.search(line)]
    blocks = []
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        for index in range(start + 1, end):
            if LOG_MARKER.match(lines[index]):
                end = index
                break
        blocks.append("\n".join(lines[start:end]))
    return blocks


def check_sanitizers(patterns: list[str]) -> bool:
    paths = sorted({path for pattern in patterns for path in glob.glob(pattern)})
    if not paths:
        print("no sanitizer report/log files were produced", file=sys.stderr)
        return False

    attributable: list[tuple[str, str]] = []
    findings = 0
    for path_text in paths:
        text = Path(path_text).read_text(encoding="utf-8", errors="replace")
        for block in finding_blocks(text):
            findings += 1
            if MODULE.search(block):
                attributable.append((path_text, block))

    if attributable:
        print("sanitizer finding attributable to the zstd module:", file=sys.stderr)
        for path_text, block in attributable:
            print(f"--- {path_text} ---", file=sys.stderr)
            print(block, file=sys.stderr)
        return False
    print(
        f"no module-attributable sanitizer finding in {len(paths)} log(s); "
        f"parsed {findings} report(s)"
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--suite", action="append", default=[], metavar="LABEL:PATH:STATUS"
    )
    parser.add_argument("--sanitizer-log", action="append", default=[], metavar="GLOB")
    args = parser.parse_args()
    if not args.suite or not args.sanitizer_log:
        parser.error("at least one --suite and --sanitizer-log are required")
    suite_results = [check_suite(spec) for spec in args.suite]
    suite_ok = all(suite_results)
    sanitizer_ok = check_sanitizers(args.sanitizer_log)
    return 0 if suite_ok and sanitizer_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
