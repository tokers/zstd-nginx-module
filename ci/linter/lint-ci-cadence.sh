#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-cadence.sh -- a workflow_call member has ci.yml as its only
# PR entry point, and does not carry a second `push:`/`pull_request:` of its own.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `cadence`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=ci-cadence selects it.
#
# The failure it prevents is invisible in the one place people look. Both runs
# are GREEN: the member runs once on the PR and once on the merge commit, over a
# tree identical to the head that just passed. Different concurrency keys, so
# cancel-in-progress cannot collapse them. Nothing goes red, nothing is slower,
# and the only evidence is the runner bill plus a README whose description of
# what runs when has quietly stopped being true.
#
# `schedule:` is allowed on a member -- codeql.yml and ci-deep.yml are reached
# from ci.yml AND on their own cadence, which is the intended shape.
#
# Usage: ci/linter/lint-ci-cadence.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the single-orchestrator topology this assumes is ci.yml; a module that
# deliberately keeps a member on push: for its own branch wants the rule relaxed
# in workflow_policy.py, not a bypass here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^\.github/workflows/.*\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-ci-cadence: no workflow files to check"; exit 0; }

need python3 "apt-get install python3"
# Whole-tree by nature: the question is which workflows are members of the
# ci.yml tree, so the file list only decides whether this checker is relevant.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" cadence
