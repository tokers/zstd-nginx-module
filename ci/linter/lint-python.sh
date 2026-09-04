#!/usr/bin/env bash
# ci/linter/lint-python.sh -- ruff lint + format check over tracked *.py.
#
# ruff replaces flake8/pyflakes/isort/black here: one binary, no venv, and it
# is what the superrepo's tools/ scripts are already checked with. It covers
# ci/linter/workflow_policy.py and ci/tools/test_runtime.py -- both gate logic,
# so an unlinted break here is a check that stops checking rather than a script
# that stops running.
#
# Keep this dispatched even when the count is low: an adopted module that adds
# its first ci/tools/ helper gets it checked from the first commit. Run an
# extension census (`git ls-files | sed -n 's/.*\.//p' | sort | uniq -c`) when
# deriving a linter set for a new module -- a tracked-but-unlinted language is
# a silent pass in exactly the way a selector matching zero files is.
#
# `ruff format --check` reports formatting WITHOUT rewriting: a linter that
# edits files behind a commit hook changes what you are about to commit.
#
# Usage: ci/linter/lint-python.sh [files...]   Env: LINT_MODE=staged|all
# Extend: per-rule config goes in a [tool.ruff] block in pyproject.toml at the
# repo root, not in flags here, so editors and CI see the same rules.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '\.py$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-python: no Python files to check"; exit 0; }

echo "lint-python: ${#FILES[@]} file(s)"
need ruff "apt-get install ruff  (or: pipx install ruff)"
rc=0
say "ruff check"
ruff check "${FILES[@]}" || rc=1
say "ruff format --check"
ruff format --check "${FILES[@]}" || rc=1
exit "$rc"
