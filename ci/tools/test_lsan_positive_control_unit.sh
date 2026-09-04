#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit and negative-control fixture for lsan_log_verdict.sh and the shared
# deliberate-leak canary. No nginx, libzstd, network, or runner privileges.
# Usage: ci/tools/test_lsan_positive_control_unit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tools/lsan_log_verdict.sh
. "$SCRIPT_DIR/lsan_log_verdict.sh"

if ! command -v cc >/dev/null 2>&1; then
    echo "SKIP: no cc on PATH -- LSan verdict fixture needs one" >&2
    exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/lsan-log-verdict-unit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
fail=0

run_case() {
    local want_rc="$1" label="$2" control_rc="$3"
    shift 3
    local rc

    if lsan_log_verdict "$control_rc" "$@" >/dev/null 2>&1; then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -ne "$want_rc" ]; then
        echo "FAIL: $label -- rc=$rc, want $want_rc" >&2
        fail=1
    else
        echo "OK: $label (rc=$rc)"
    fi
}

cat >"$WORK/finding.log" <<'EOF'
==10==LeakSanitizer: checking for leaks
==10==ERROR: LeakSanitizer: detected memory leaks
SUMMARY: AddressSanitizer: 1234 byte(s) leaked in 1 allocation(s).
EOF

cat >"$WORK/actual-failure.log" <<'EOF'
==11==LeakSanitizer: checking for leaks
==11==Failed suspending threads.
EOF

cat >"$WORK/thread-exit-retry.log" <<'EOF'
==111==Could not attach to thread 123 (errno 3).
==111==LeakSanitizer: checking for leaks
EOF

cat >"$WORK/preflight-with-check.log" <<'EOF'
==12==WARNING: ptrace appears to be blocked (is seccomp enabled?). LeakSanitizer may hang.
==12==Child exited with signal 112.
==12==LeakSanitizer: checking for leaks
EOF

cat >"$WORK/preflight-without-check.log" <<'EOF'
==13==WARNING: ptrace appears to be blocked (is seccomp enabled?). LeakSanitizer may hang.
==13==Child exited with signal 31.
EOF

cat >"$WORK/clean.log" <<'EOF'
==14==LeakSanitizer: checking for leaks
EOF

run_case 1 "real sanitizer finding fails" 0 "$WORK/finding.log"
run_case 2 "real stop-the-world failure is indeterminate" 0 "$WORK/actual-failure.log"
run_case 0 "a thread-exit attach retry is non-fatal" 0 "$WORK/thread-exit-retry.log"
run_case 0 "preflight heuristic is non-fatal when real check and canary pass" \
    0 "$WORK/preflight-with-check.log"
run_case 2 "preflight warning without exit-hook marker is indeterminate" \
    0 "$WORK/preflight-without-check.log"
run_case 2 "clean marker with failed canary is indeterminate" 1 "$WORK/clean.log"
run_case 2 "clean marker with unavailable canary is indeterminate" 2 "$WORK/clean.log"
run_case 2 "missing logs are indeterminate" 0
run_case 0 "clean marker with passing canary passes" 0 "$WORK/clean.log"
run_case 2 "every process log must contain the exit-hook marker" 0 \
    "$WORK/clean.log" "$WORK/preflight-without-check.log"

MAPFILE_CHECKED_FAULT=partial-error
export MAPFILE_CHECKED_FAULT
if lsan_check_log_glob "$WORK/*.log" >/dev/null 2>&1
then
    list_rc=0
else
    list_rc=$?
fi
unset MAPFILE_CHECKED_FAULT
if [ "$list_rc" -eq 23 ]; then
    echo "OK: partial log-list producer failure is propagated (rc=23)"
else
    echo "FAIL: partial log-list producer failure -- rc=$list_rc, want 23" >&2
    fail=1
fi

# Negative control: the old gate failed solely on LLVM's heuristic warning,
# even when the same log proved the real leak check started and the deliberate
# leak control passed. Reproduce that exact false-red decision.
if grep -qE 'ptrace appears to be blocked|LeakSanitizer may hang' \
    "$WORK/preflight-with-check.log"
then
    echo "OK: negative control reproduces the old false-red preflight gate"
else
    echo "FAIL: negative control did not reproduce the old false-red gate" >&2
    fail=1
fi

if lsan_positive_control; then
    echo "OK: deliberate leak canary is detected on this host"
else
    echo "FAIL: deliberate leak canary was not detected on this host" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: LSan verdict fixture had failures" >&2
    exit 1
fi
echo "OK: LSan verdict fixture -- all cases and negative control passed"
