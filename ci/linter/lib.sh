#!/usr/bin/env bash
# ci/linter/lib.sh -- shared helpers for the ci/linter/lint-*.sh scripts.
#
# Sourced, never executed. Provides:
#   repo_root            absolute path of the checkout
#   lint_files <regex>   emit the file list to lint, one per line, NUL-safe
#                        callers use `mapfile -t`. Honours LINT_MODE:
#                          staged (default in the git hook) -- staged files only
#                          all                              -- every tracked file
#                        and an explicit file list passed in "$@" by run-all.sh.
#   mapfile_checked <array> <producer> [args...]
#                        populate an array only after its producer succeeds
#   need <tool> <hint>   hard-fail with an install hint when a linter is absent
#   say / warn / die     consistent output
#
# Missing tools are a HARD FAILURE, never a silent skip: a gate that quietly
# disappears when its tool is uninstalled reports green while checking nothing.
# Run ci/linter/install-linters.sh to get them all.

set -euo pipefail

repo_root() { git rev-parse --show-toplevel; }

say()  { printf '  %s\n' "$*"; }
warn() { printf '  WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

need() {
    command -v "$1" >/dev/null 2>&1 && return 0
    die "$1 not found. Install it: $2   (or run ci/linter/install-linters.sh)"
}

mapfile_checked() {
    local array_name="$1" tmp rc; shift
    tmp="$(mktemp)" || die "mktemp failed"
    if [ "${MAPFILE_CHECKED_FAULT:-}" = "partial-error" ]; then
        printf '%s\n' plausible-prefix >"$tmp"
        rm -f "$tmp"
        return 23
    fi
    if "$@" >"$tmp"; then
        mapfile -t "$array_name" <"$tmp"
        rm -f "$tmp"
        return 0
    else
        rc=$?
        rm -f "$tmp"
        return "$rc"
    fi
}

# Paths never linted: byte-exact fuzz inputs, vendored trees, build output.
#
# `(^|/)vendor/` and not `^ci/vendor/`: the pattern matches a vendored tree at
# any depth, so a second one added later is excluded without editing this regex.
# Linting vendored code produces findings nobody may fix -- they are upstream's,
# and a hand-edit is reverted by the next refresh. Same regex shape as the
# top-level exclude in .pre-commit-config.yaml, so the hook and these scripts
# select the same files.
LINT_EXCLUDE_RE='^ci/fuzz/corpus/|^ci/fuzz/regressions/|(^|/)vendor/|(^|/)objs/|(^|/)\.build/|(^|/)node_modules/|(^|/)\.venv/'

# lint_files <match-regex> [explicit files...]
lint_files() {
    local match_re="$1"; shift
    local list
    if [ "$#" -gt 0 ]; then
        list=$(printf '%s\n' "$@")
    elif [ "${LINT_MODE:-all}" = "staged" ]; then
        list=$(git diff --cached --name-only --diff-filter=ACMR) || die "git diff --cached failed"
    else
        list=$(git ls-files) || die "git ls-files failed"
    fi
    printf '%s\n' "$list" \
        | grep -Ev "$LINT_EXCLUDE_RE" \
        | grep -E "$match_re" \
        | while read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done \
        || true
}
