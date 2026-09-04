#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-runners.sh -- fork PRs must never select the self-hosted
# runners, and every runner selector must name labels that exist.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `runners`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=ci-runners selects it, like every other checker here.
#
# Why it is a GATE and not advice: the self-hosted runners are persistent and shared
# with the Debian package builds. A pull_request-triggered job executes scripts
# from the PR head, so one workflow missing the fork fallback hands an arbitrary
# contributor code execution on the build host. This is a public template repo;
# taking outside contributions is the point.
#
# The second half is a LABEL check, and it covers workflows the trust half does
# not: a schedule-only workflow has no fork to keep off the build host, but a
# typo in its pool labels is still a job that never starts. actionlint cannot
# cover that gap -- it validates labels only for a literal `runs-on`, and every
# self-hosted selector here is a `fromJSON(...)` ternary, on which it stays
# silent. Silence and a pass are the same output.
#
# Usage: ci/linter/lint-ci-runners.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the approved runner selector is APPROVED_SELECTOR in workflow_policy.py.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^\.github/workflows/.*\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-ci-runners: no workflow files to check"; exit 0; }

need python3 "apt-get install python3"
# The check is whole-tree by nature -- a runner policy is a property of the SET
# of workflows, not of one file -- so the file list above is only used to decide
# whether this checker is RELEVANT to the change, never to narrow what it reads.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" runners
