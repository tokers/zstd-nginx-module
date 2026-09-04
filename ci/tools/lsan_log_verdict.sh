#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Grade verbose ASan/LSan log_path output without treating LLVM's ptrace
# preflight heuristic as proof that leak detection failed. Usage:
#
#   ci/tools/lsan_log_verdict.sh '/tmp/lsan-smoke.*'
#
# The caller must enable verbosity=1 so every process that reaches the LSan
# exit hook writes "LeakSanitizer: checking for leaks". This script also runs
# the shared deliberate-leak control. It returns 0 only when every log reached
# the exit hook, no real detector failure/finding exists, and the control was
# detected. Return 1 means a sanitizer finding; return 2 is indeterminate.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/linter/lib.sh
. "$SCRIPT_DIR/../linter/lib.sh"
# shellcheck source=ci/tools/lsan_positive_control.sh
. "$SCRIPT_DIR/lsan_positive_control.sh"

LSAN_FINDING_RE='ERROR: (Address|Leak|UndefinedBehavior)Sanitizer|SUMMARY: (Address|Leak|UndefinedBehavior)Sanitizer|runtime error:'
LSAN_FAILURE_RE='Failed suspending threads|Failed spawning a tracer thread|Waiting on the tracer thread failed|LeakSanitizer has encountered a fatal error'
LSAN_PREFLIGHT_RE='ptrace appears to be blocked|LeakSanitizer may hang|Child exited with signal'

lsan_log_verdict() {
    local control_rc="$1"
    shift
    local file missing=0

    if [ "$#" -eq 0 ]; then
        echo "LSan INDETERMINATE: no verbose sanitizer logs were produced" >&2
        return 2
    fi

    if grep -qE "$LSAN_FINDING_RE" "$@" 2>/dev/null
    then
        echo "Sanitizer finding:" >&2
        grep -nE -m 20 "$LSAN_FINDING_RE" "$@" >&2 || true
        return 1
    fi

    if grep -qE "$LSAN_FAILURE_RE" "$@" 2>/dev/null
    then
        echo "LSan INDETERMINATE: the real stop-the-world operation failed" >&2
        grep -nE -m 20 "$LSAN_FAILURE_RE" "$@" >&2 || true
        return 2
    fi

    for file in "$@"; do
        if ! grep -q 'LeakSanitizer: checking for leaks' "$file" 2>/dev/null; then
            echo "LSan INDETERMINATE: exit hook marker missing from $file" >&2
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || return 2

    case "$control_rc" in
        0) ;;
        1)
            echo "LSan INDETERMINATE: deliberate leak was not detected" >&2
            return 2
            ;;
        *)
            echo "LSan INDETERMINATE: deliberate-leak control could not run" >&2
            return 2
            ;;
    esac

    if grep -qE "$LSAN_PREFLIGHT_RE" "$@" 2>/dev/null
    then
        echo "LSan preflight warning ignored: real exit hooks and deliberate-leak control passed"
    fi
    echo "LSan verified: no sanitizer findings across $# process log(s)"
}

lsan_check_log_glob() {
    local pattern="$1" control_rc
    local -a logs=()

    # The quoted program executes in the child.
    # shellcheck disable=SC2016
    mapfile_checked logs env LC_ALL=C bash -c \
        'compgen -G "$1" || [ $? -eq 1 ]' _ "$pattern" || return $?
    if lsan_positive_control; then
        control_rc=0
    else
        control_rc=$?
    fi
    lsan_log_verdict "$control_rc" "${logs[@]}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ "$#" -ne 1 ]; then
        echo "usage: $0 '<asan-log-glob>'" >&2
        exit 2
    fi
    set -e
    lsan_check_log_glob "$1"
fi
