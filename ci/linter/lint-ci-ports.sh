#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-ports.sh -- every runtime-bearing CI job owns a distinct
# test port band, actually binds the band it declared, and proves the band free
# BEFORE the first step that binds it.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `ports`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=ci-ports selects it.
#
# The failure it prevents does not look like a port bug. build-test.yml and
# asan.yml pin the SAME self-hosted runner and have DISJOINT concurrency groups,
# so nothing serialises them: two jobs run ci/tools/test_runtime.py at once, on
# the same default port, and the second one's listener collides with the first
# one's server. What CI reports is an "Address already in use" in one job and a
# missing-response assertion in the other -- two unrelated-looking reds, one
# cause, and a rerun usually hides it.
#
# Usage: ci/linter/lint-ci-ports.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the band width and the driver's default live in
# ci/tools/test_runtime.py and ci/tools/max-port.sh; this only checks the wiring.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^\.github/workflows/.*\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-ci-ports: no workflow files to check"; exit 0; }

need python3 "apt-get install python3"
# Whole-tree by nature: band UNIQUENESS is a property of the set of workflows,
# so the file list only decides whether this checker is relevant to the change.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" ports
