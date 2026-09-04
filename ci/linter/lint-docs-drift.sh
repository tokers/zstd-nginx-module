#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-docs-drift.sh -- README.md and .github/workflows/ describe the
# same pipeline.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `docs`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=docs-drift selects it.
#
# Both drift directions are silent and neither fails anything else:
#   * a workflow added with no README row is a gate nobody knows exists, so
#     nobody notices when a later refactor deletes it;
#   * a README row for a workflow that no longer exists is a badge that 404s and
#     a documented guarantee the repo does not actually have.
# This is a TEMPLATE repo: its README is the specification nine sibling modules
# are rolled out against, so a stale claim there propagates.
#
# Structural facts only -- no exact job counts, no durations, no subtest tallies.
# Those are the brittle claims that make a drift check annoying enough to delete,
# and the ones a lane-timing comment already owns.
#
# Usage: ci/linter/lint-docs-drift.sh [files...]   Env: LINT_MODE=staged|all
# Extend: add a structural fact to check_docs(); resist adding a count.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^(\.github/workflows/.*\.ya?ml|README\.md)$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-docs-drift: no workflow or README changes"; exit 0; }

need python3 "apt-get install python3"
# Whole-tree by nature: the check compares two SETS, so a narrowed file list
# would let a workflow deletion pass whenever README.md was the only file staged.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" docs
