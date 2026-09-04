#!/usr/bin/env bash
# ci/linter/run-all.sh -- run every ci/linter/lint-*.sh and report once.
#
# This is what .githooks/pre-commit calls and what a human should call before
# pushing. It does NOT stop at the first failure: seeing all four failures in
# one run beats four commit attempts.
#
# Usage:
#   ci/linter/run-all.sh                 lint every tracked file
#   ci/linter/run-all.sh --staged        lint only staged files (hook mode)
#   ci/linter/run-all.sh --list          list the checks and exit
#   ci/linter/run-all.sh <file>...       lint exactly these files
#
# Env:
#   LINT_MODE=staged|all      same as --staged / default
#   LINT_ONLY="c sh"          run only these checkers (names below)
#   LINT_SKIP_SEMGREP=1       loud opt-out of the slowest C pass
#   LINT_JOBS=N               parallel checkers (default 0 = one per checker,
#                             1 = serial; use 1 when bisecting a hang)
#
# Exit: 0 all clean, 1 findings, 2 a linter is missing (install-linters.sh).
#
# The checkers are independent, so they run concurrently and each one's output
# is buffered to its own file and replayed whole, in the fixed glob order. Never
# stream them interleaved: findings carry a file:line but not a checker name, so
# interleaving makes them unattributable, which is the whole reason to buffer.
# Order stays glob order and not completion order so two runs of a dirty tree
# produce the same transcript.
#
# Extend: drop a new ci/linter/lint-<name>.sh in place -- it is picked up by
# glob, no edit here. Keep the "no files of this kind" case exiting 0.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# || exit 2, not a bare cd: every checker resolves its paths relative to the
# repo root, so failing to get there would lint the wrong tree -- or nothing at
# all -- and report clean. Same "could not run" status as a missing linter.
cd "$ROOT" || exit 2

MODE="${LINT_MODE:-all}"
FILES=()
for a in "$@"; do
    case "$a" in
        --staged) MODE=staged ;;
        --all)    MODE=all ;;
        --list)   ls ci/linter/lint-*.sh; exit 0 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *)        FILES+=("$a") ;;
    esac
done
export LINT_MODE="$MODE"

echo "== lint (mode: $MODE) =="

# Selected checkers, in glob order. Built first so the replay loop below can
# walk the same list it launched.
ALL=()
SEL=()
for s in ci/linter/lint-*.sh; do
    name="$(basename "$s" .sh)"; name="${name#lint-}"
    ALL+=("$name")
    if [ -n "${LINT_ONLY:-}" ] && [[ " $LINT_ONLY " != *" $name "* ]]; then
        continue
    fi
    SEL+=("$name")
done

# An empty selection is "could not run", never "clean". A typo in LINT_ONLY
# used to leave both loops below iterating zero times, printing "all linters
# clean" and exiting 0 -- a gate that silently lints nothing is worse than no
# gate. Same exit 2 as a missing linter.
if [ "${#SEL[@]}" -eq 0 ]; then
    if [ "${#ALL[@]}" -eq 0 ]; then
        echo "no ci/linter/lint-*.sh found -- wrong tree?" >&2
    else
        echo "LINT_ONLY=\"${LINT_ONLY:-}\" matched no checker; known: ${ALL[*]}" >&2
    fi
    exit 2
fi

JOBS="${LINT_JOBS:-0}"
[ "$JOBS" -eq 0 ] 2>/dev/null && JOBS="${#SEL[@]}"
[ "$JOBS" -ge 1 ] 2>/dev/null || JOBS=1

# mktemp -d, not a fixed path: two checkouts (or a hook racing a manual run)
# would otherwise share buffers. Trap covers the Ctrl-C path too.
BUF="$(mktemp -d "${TMPDIR:-/tmp}/lint-buf.XXXXXX")"
trap 'rm -rf "$BUF"' EXIT INT TERM

for name in "${SEL[@]}"; do
    # Bounded fan-out: block until a slot frees. `wait -n` needs bash 4.3+,
    # which install-linters.sh already assumes.
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n; done
    {
        "ci/linter/lint-$name.sh" "${FILES[@]+"${FILES[@]}"}" \
            > "$BUF/$name.out" 2>&1
        # Exit status travels in a file, not in $?: the reaping `wait` below is
        # collective, so per-child statuses are not otherwise recoverable.
        echo "$?" > "$BUF/$name.rc"
    } &
done
wait

rc=0 missing=0 failed=()
for name in "${SEL[@]}"; do
    cat "$BUF/$name.out"
    # A missing .rc means the subshell died before writing one (OOM-killer,
    # SIGKILL). Treat it as a failure, never as a pass.
    crc="$(cat "$BUF/$name.rc" 2>/dev/null || echo 1)"
    case "$crc" in
        0) ;;
        2) missing=1; failed+=("$name(tool missing)") ;;
        *) rc=1;      failed+=("$name") ;;
    esac
done

if [ "$missing" -eq 1 ]; then
    echo "== FAIL: ${failed[*]} -- run ci/linter/install-linters.sh ==" >&2
    exit 2
fi
if [ "$rc" -ne 0 ]; then
    echo "== FAIL: ${failed[*]} ==" >&2
    exit 1
fi
echo "== all linters clean =="
