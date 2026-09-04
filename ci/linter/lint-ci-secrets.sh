#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/linter/lint-ci-secrets.sh -- a workflow_call member declares the secrets it
# needs by name and typed `required: true`; callers never use `secrets: inherit`.
#
# The rule and the reasoning live in ci/linter/workflow_policy.py (subcommand
# `secrets`); this wrapper exists so run-all.sh picks the check up by glob and
# LINT_ONLY=ci-secrets selects it.
#
# The failure it prevents is a silent one at the call boundary. An undeclared
# secret is not passed at all, so the member sees an empty string and dies
# somewhere downstream of the cause -- a checkout that 404s, a curl that 401s --
# with nothing pointing back at the missing declaration.
#
# This repo declares no secrets and is vacuously green on the member half by
# design; see the subcommand docstring. The caller half is live today.
#
# Usage: ci/linter/lint-ci-secrets.sh [files...]   Env: LINT_MODE=staged|all
# Extend: the stance (typed-per-member, never inherit) is a repo policy decision
# recorded in workflow_policy.py, not something to bypass here.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^\.github/workflows/.*\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-ci-secrets: no workflow files to check"; exit 0; }

need python3 "apt-get install python3"
# Whole-tree by nature: the check pairs callers with the members they call, so
# the file list only decides whether this checker is relevant.
exec python3 "$(git rev-parse --show-toplevel)/ci/linter/workflow_policy.py" secrets
