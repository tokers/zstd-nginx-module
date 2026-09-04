#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Protect the measured four-lane PR/deep topology and fan-out eligibility lead."""

from __future__ import annotations

import copy
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load(name: str) -> dict:
    with (ROOT / ".github" / "workflows" / name).open(encoding="utf-8") as src:
        return yaml.safe_load(src)


def needs(job: dict) -> set[str]:
    value = job.get("needs", [])
    return {value} if isinstance(value, str) else set(value)


def edge_errors(filename: str, jobs: dict, edges: dict[str, set[str]]) -> list[str]:
    return [
        f"{filename}:{job} breaks a four-lane dependency chain"
        for job, expected in edges.items()
        if job not in jobs or needs(jobs[job]) != expected
    ]


def check_ci(ci: dict) -> list[str]:
    errors: list[str] = []
    expected = {
        "lint": "./.github/workflows/lint.yml",
        "build-test": "./.github/workflows/build-test.yml",
        "security-scanners": "./.github/workflows/security-scanners.yml",
        "harness-fault-arms": "./.github/workflows/harness-fault-arms.yml",
        "windows-build": "./.github/workflows/windows-build.yml",
    }
    jobs = ci.get("jobs", {})
    if set(jobs) != set(expected):
        errors.append("ci.yml must contain only the measured PR workflow set")
    for job, target in expected.items():
        if job not in jobs or jobs[job].get("uses") != target or needs(jobs[job]):
            errors.append(f"ci.yml:{job} must remain an independent call to {target}")
    trigger = ci.get("on", ci.get(True, {}))
    trigger_names = set(trigger) if isinstance(trigger, dict) else set(trigger or [])
    if trigger_names != {"pull_request", "push", "workflow_dispatch"}:
        errors.append("ci.yml must remain PR/manual plus the focused master signal")
    elif not isinstance(trigger["push"], dict) or trigger["push"].get("branches") != [
        "master"
    ]:
        errors.append("ci.yml push must remain limited to master")
    push_guard = "github.event_name != 'push'"
    for job in ("lint", "build-test", "security-scanners", "windows-build"):
        if jobs.get(job, {}).get("if") != push_guard:
            errors.append(f"ci.yml:{job} must skip the focused master signal")
    if jobs.get("harness-fault-arms", {}).get("if") is not None:
        errors.append("ci.yml:harness-fault-arms must run on the master signal")

    return errors


def check_build(build: dict) -> list[str]:
    errors: list[str] = []
    jobs = build.get("jobs", {})
    allowed_build = {
        "resolve",
        "validation",
        "release-build-fanout",
        "build",
        "build-arm64",
        "build-old-libzstd",
        "linkage",
        "cvary-interop",
        "build-asan",
        "tests",
        "tests-asan",
    }
    if set(jobs) != allowed_build:
        errors.append("build-test.yml contains a job outside the four-lane design")
    build_edges = {
        "resolve": set(),
        "validation": set(),
        "release-build-fanout": {"resolve"},
        "build": {"resolve"},
        "build-arm64": {"resolve"},
        "tests": {"resolve", "build"},
        "build-asan": {"resolve", "release-build-fanout"},
        "tests-asan": {"build-asan"},
        "build-old-libzstd": {"resolve", "release-build-fanout"},
        "cvary-interop": {"resolve", "release-build-fanout"},
        "linkage": {"resolve", "cvary-interop"},
    }
    errors.extend(edge_errors("build-test.yml", jobs, build_edges))
    fanout = jobs.get("release-build-fanout", {})
    if fanout.get("runs-on") != "ubuntu-24.04":
        errors.append("build-test.yml fan-out barrier must stay off the four-lane pool")
    steps = fanout.get("steps", [])
    if len(steps) != 1 or steps[0].get("run") != "sleep 10":
        errors.append(
            "build-test.yml fan-out barrier must preserve the ten-second "
            "best-effort eligibility lead for the delayed fan-out chains"
        )
    if "coverage" in jobs:
        errors.append("coverage is a deep report, not a PR job")
    return errors


def check_deep(deep: dict) -> list[str]:
    errors: list[str] = []
    trigger = deep.get("on", deep.get(True, {}))
    trigger_names = set(trigger) if isinstance(trigger, dict) else set(trigger or [])
    if trigger_names != {"schedule", "workflow_dispatch"}:
        errors.append("ci-deep.yml must remain weekly/manual and outside PR CI")
    jobs = deep.get("jobs", {})
    allowed_deep = {
        "build-flavors",
        "fuzz",
        "memcheck",
        "harness-memcheck",
        "helgrind",
        "scanners",
        "coverage",
        "codeql",
        "asan-soak",
    }
    if set(jobs) != allowed_deep:
        errors.append("ci-deep.yml contains a job outside the four-lane design")
    deep_edges = {
        "memcheck": set(),
        "coverage": {"memcheck"},
        "codeql": {"coverage"},
        "build-flavors": {"codeql"},
        "scanners": {"build-flavors"},
        "asan-soak": {"scanners"},
        "harness-memcheck": set(),
        "helgrind": {"harness-memcheck"},
        "fuzz": set(),
    }
    errors.extend(edge_errors("ci-deep.yml", jobs, deep_edges))
    if (
        jobs.get("fuzz", {}).get("strategy", {}).get("max-parallel") != 2
        or jobs.get("build-flavors", {}).get("strategy", {}).get("max-parallel") != 1
    ):
        errors.append(
            "CI Deep matrices must reserve two fuzz lanes and serialize flavors"
        )
    fuzz_include = (
        jobs.get("fuzz", {}).get("strategy", {}).get("matrix", {}).get("include", [])
    )
    fuzz_targets = {
        entry.get("binary") for entry in fuzz_include if isinstance(entry, dict)
    }
    if len(fuzz_include) != 2 or fuzz_targets != {
        "fuzz_accept_encoding",
        "fuzz_dcz",
    }:
        errors.append("CI Deep must run both parser fuzz targets in its two lanes")
    return errors


def findings(ci: dict, build: dict, deep: dict) -> list[str]:
    return check_ci(ci) + check_build(build) + check_deep(deep)


def selftest(  # pylint: disable=too-many-statements
    ci: dict, build: dict, deep: dict
) -> int:
    baseline = findings(ci, build, deep)
    if baseline:
        for error in baseline:
            print(f"FAIL topology baseline is invalid: {error}", file=sys.stderr)
        return 1
    cases = []
    changed = copy.deepcopy(ci)
    changed["jobs"]["fuzzing"] = {"uses": "./.github/workflows/fuzzing.yml"}
    cases.append(("long PR job", changed, build, deep))
    changed = copy.deepcopy(ci)
    changed["jobs"]["lint"]["needs"] = "build-test"
    cases.append(("serialized PR workflow call", changed, build, deep))
    changed = copy.deepcopy(ci)
    changed["jobs"]["security-scanners"]["uses"] = "./.github/workflows/valgrind.yml"
    cases.append(("rewired PR workflow call", changed, build, deep))
    changed = copy.deepcopy(ci)
    del changed["jobs"]["build-test"]["if"]
    cases.append(("duplicate master build", changed, build, deep))
    changed = copy.deepcopy(ci)
    changed[True]["push"] = None
    cases.append(("unbounded master signal", changed, build, deep))
    changed = copy.deepcopy(build)
    changed["jobs"]["build"]["needs"] = ["resolve", "validation"]
    cases.append(("lost PR lane overlap", ci, changed, deep))
    changed = copy.deepcopy(build)
    changed["jobs"]["validation"]["needs"] = "build"
    cases.append(("serialized validation lane", ci, changed, deep))
    changed = copy.deepcopy(build)
    changed["jobs"]["build-arm64"]["needs"] = "build-arm64"
    cases.append(("invalid hosted arm64 dependency", ci, changed, deep))
    changed = copy.deepcopy(build)
    changed["jobs"]["release-build-fanout"]["steps"][0]["run"] = "true"
    cases.append(("lost best-effort fan-out eligibility lead", ci, changed, deep))
    changed = copy.deepcopy(deep)
    changed["jobs"]["fuzz"]["strategy"]["max-parallel"] = 3
    cases.append(("five-lane deep fan-out", ci, build, changed))
    changed = copy.deepcopy(deep)
    changed["jobs"]["fuzz"]["strategy"]["matrix"]["include"].pop()
    cases.append(("missing deep fuzz target", ci, build, changed))
    changed = copy.deepcopy(deep)
    changed[True]["pull_request"] = {}
    cases.append(("deep PR trigger", ci, build, changed))
    changed = copy.deepcopy(build)
    changed["jobs"]["unlisted"] = {}
    cases.append(("unlisted PR child job", ci, changed, deep))
    changed = copy.deepcopy(deep)
    changed["jobs"]["unlisted"] = {}
    cases.append(("unlisted deep child job", ci, build, changed))
    failed = False
    for label, ci_doc, build_doc, deep_doc in cases:
        if findings(ci_doc, build_doc, deep_doc):
            print(f"ok   topology rejects {label}")
        else:
            print(f"FAIL topology accepted {label}", file=sys.stderr)
            failed = True
    return int(failed)


def main() -> int:
    try:
        ci, build, deep = load("ci.yml"), load("build-test.yml"), load("ci-deep.yml")
    except (OSError, yaml.YAMLError) as exc:
        print(f"lint-ci-topology: could not parse workflows: {exc}", file=sys.stderr)
        return 2
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest(ci, build, deep)
    if len(sys.argv) != 1:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        return 2
    errors = findings(ci, build, deep)
    for error in errors:
        print(f"lint-ci-topology: {error}", file=sys.stderr)
    if errors:
        return 1
    print(
        "lint-ci-topology: PR/deep workflows preserve the measured four-lane topology"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
