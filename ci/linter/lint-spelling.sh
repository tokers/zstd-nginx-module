#!/usr/bin/env bash
# ci/linter/lint-spelling.sh -- codespell over prose: docs, comments, log
# strings, error messages.
#
# The findings this catches are cosmetic one at a time and expensive in
# aggregate: a typo in an error message is the string a future maintainer greps
# for and does not find, and a typo in a README is the sentence a reader stops
# to re-parse. Neither shows up in any other gate here -- every checker in this
# directory reads code as code, and prose is where this repo keeps most of its
# reasoning.
#
# SCOPE: every tracked file. The vendored upstream test suite is already outside
# lint_files' reach via LINT_EXCLUDE_RE, which is load-bearing here rather than
# incidental -- 95 of the 98 raw findings on this tree came from
# ci/vendor/nginx-tests/, and none of them are misspellings. The directives
# below are how you keep a deliberate example out of the findings: same line as
# the word, naming the word -- never a file-wide skip.
# `isnt` is a Test::More predicate.               # codespell:ignore isnt
# `clen` is that suite's content-length variable. # codespell:ignore clen
# Pointing codespell at vendored code produces a permanently red gate made
# entirely of false positives, which is the shape that teaches --no-verify.
#
# No --write-changes, ever. codespell picks one candidate from an ambiguous
# list -- the vendored variable above maps to "clean, clan" -- and an auto-fixer
# would silently pick wrong inside a string literal or an identifier.
#
# Extend, cheapest first: a one-off deliberate example gets an inline
# `codespell:ignore <word>` on its own line. A genuine domain word that recurs
# goes in ci/linter/codespell-ignore.txt, one per line. Neither is a reason to
# widen LINT_EXCLUDE_RE, which blinds every checker here to whole files.
#
# Usage: ci/linter/lint-spelling.sh [files...]   Env: LINT_MODE=staged|all
#
# VERIFY BEFORE TRUSTING (a green checker proves nothing until seen red):
#   printf '# teh gate must catch this\n' > _p.sh   # codespell:ignore teh
#   ci/linter/lint-spelling.sh _p.sh                # expect a finding, exit 65
#   rm _p.sh

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '.' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-spelling: no files to check"; exit 0; }

echo "lint-spelling: ${#FILES[@]} file(s)"

need codespell "pipx install codespell"
say "codespell"

ROOT="$(repo_root)"
IGNORE="$ROOT/ci/linter/codespell-ignore.txt"
args=()
[ -f "$IGNORE" ] && args+=(--ignore-words "$IGNORE")

# Normalise codespell's exit status into this suite's 0/1/2 contract. It exits
# 65 on findings (its own convention); run-all.sh happens to bucket that as
# "findings", but the hook, lint.yml and a human reading the raw status all see
# an undocumented value -- and a future codespell using 2 would be reported as
# "tool missing", masking a real red. Reported by the
# nginx-cache-turbo-module adoption 2026-08-10.
rc=0
codespell "${args[@]}" -- "${FILES[@]}" || rc=1
exit "$rc"
