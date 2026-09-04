#!/usr/bin/env bash
# ci/linter/lint-sh.sh -- shellcheck over every *.sh / *.bash in the tree.
#
# -S warning, not info: the info tier (SC2015, SC2086 in safe positions) fires
# on existing build scripts and would land this gate red on arrival, which only
# teaches everyone to --no-verify. Same floor as the shellcheck the actionlint
# hook runs inside `run:` blocks (SHELLCHECK_OPTS=-Swarning), so an SC2164 is
# not ignored in a .sh file while blocking in a workflow.
#
# Usage: ci/linter/lint-sh.sh [files...]   Env: LINT_MODE=staged|all
# Extend: raise to -S info only together with a pass that fixes the backlog.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

# .githooks/* has no extension but is bash; an unchecked commit hook is the
# one script whose bug silently disables every other check here.
mapfile_checked FILES lint_files '\.(sh|bash)$|^\.githooks/' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-sh: no shell files to check"; exit 0; }

echo "lint-sh: ${#FILES[@]} file(s)"
need shellcheck "apt-get install shellcheck"
shellcheck -S warning -x "${FILES[@]}"
say "clean"
