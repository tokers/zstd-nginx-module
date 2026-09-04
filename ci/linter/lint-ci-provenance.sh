#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-provenance.sh -- every step that extracts an archive or
# executes a downloaded artifact must be preceded, in the same job, by a
# gpg/sha256 trust-anchor assertion. A cache-hit path is not exempt: a cached
# tarball is exactly as untrusted as a fresh download until re-checked.
#
# The rule and the detector live in ci/linter/workflow_policy.py (subcommand
# `provenance`); this wrapper exists so run-all.sh picks the check up by glob
# and LINT_ONLY=ci-provenance selects it.
#
# The failure it prevents: a release/origin/cache compromise becomes code
# execution on the self-hosted runner the moment CI unpacks or runs what it
# just fetched with no verification -- audit sha e289021 F3.
#
# Usage: ci/linter/lint-ci-provenance.sh [files...]   Env: LINT_MODE=staged|all
# Extend: a new trust-anchor shape (a detached signature against a different
# tool, a different pinned-hash naming convention) goes in TRUST_ANCHOR_RE in
# workflow_policy.py, not here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^\.github/workflows/.*\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-ci-provenance: no workflow files to check"; exit 0; }

need python3 "apt-get install python3"
# Whole-tree by nature: a download in one step and its extract/exec several
# steps later are the same JOB, so the file list only decides relevance.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" provenance
