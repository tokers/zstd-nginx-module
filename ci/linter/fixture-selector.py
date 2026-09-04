#!/usr/bin/env python3
"""Print (or write) the approved runner selector the -ok policy fixture must use.

WHY THIS EXISTS
    ci/linter/fixtures/policy/schedule-only-runner-labels-ok/ is the POSITIVE
    control for the runner-label check: same shape as the drift fixture, but a
    selector `workflow_policy.py` must accept. Hardcoding a selector in it makes
    that control wrong for every adopter, because step 13 of ci/PROMPT.md tells
    a hosted-only adopter to turn SELF_HOSTED_ALLOWED off. The fixture then
    asserts a selector the adopter deliberately rejects, the control fails, and
    the failure looks like a bug in the checker rather than a stale fixture.
    Reported by the nginx-cache-turbo-module adoption, 2026-08-10.

    Deriving the selector from workflow_policy.py makes the fixture correct by
    construction: whatever a repo approves is what its positive control asserts.

USAGE
    ci/linter/fixture-selector.py            print the selector
    ci/linter/fixture-selector.py --write F  rewrite F's `runs-on:` line in place

    Called by ci/linter/selftest.sh before the -ok fixture is checked.

EXIT
    0 selector printed/written, 1 SELF_HOSTED_ALLOWED is False (a hosted-only
    repo has no approved self-hosted selector, so the fixture pair does not
    apply).
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent


def approved_selector() -> str | None:
    """APPROVED_SELECTOR, or None if this repo allows no self-hosted runners."""
    spec = importlib.util.spec_from_file_location(
        "workflow_policy", HERE / "workflow_policy.py"
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not getattr(mod, "SELF_HOSTED_ALLOWED", False):
        return None
    return mod.APPROVED_SELECTOR


def main(argv: list[str]) -> int:
    sel = approved_selector()
    if sel is None:
        # Hosted-only repo: no approved self-hosted selector exists, so there is
        # nothing for the positive control to assert. Silent exit 1 lets the
        # caller skip the rewrite without failing the selftest.
        return 1

    if len(argv) >= 2 and argv[0] == "--write":
        path = pathlib.Path(argv[1])
        text = path.read_text(encoding="utf-8")
        # Only the first job-level `runs-on:`; the fixture has exactly one.
        new, n = re.subn(
            r"(?m)^(\s*runs-on: ).*$", lambda m: m.group(1) + sel, text, count=1
        )
        if n != 1:
            print(f"{path}: no runs-on: line to rewrite", file=sys.stderr)
            return 1
        if new != text:
            path.write_text(new, encoding="utf-8")
        return 0

    print(sel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
