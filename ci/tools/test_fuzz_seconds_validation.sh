#!/usr/bin/env bash
#
# Regression test for audit sha e289021 F1: ci-deep.yml's "Select fuzz
# duration" step used to splice workflow_dispatch's fuzz_seconds input
# directly into a run: shell command, letting a quoted payload (e.g.
# `3600"; id; #`) execute on the self-hosted builder02 runner. The fix
# passes the raw value through env: and validates it in Bash before use.
#
# This script extracts that exact validation logic (kept byte-identical
# below to .github/workflows/ci-deep.yml's "Select fuzz duration" step) and
# drives it against malicious/malformed/boundary inputs, asserting each is
# rejected, plus a couple of valid inputs that must be accepted.
#
# Usage: tools/test_fuzz_seconds_validation.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="$SCRIPT_DIR/../../.github/workflows/ci-deep.yml"

fail=0

# Runs the same validation the workflow step performs, given
# RAW_FUZZ_SECONDS, and prints either "FUZZ_SECS=<n>" (accept) or nothing
# with a nonzero exit (reject) -- mirrors the workflow's own exit-1-on-error
# shape, minus the GitHub Actions ::error:: annotation syntax.
validate() {
    local RAW_FUZZ_SECONDS="$1"
    case "$RAW_FUZZ_SECONDS" in
        '' | *[!0-9]*)
            return 1
            ;;
    esac
    if [ "$RAW_FUZZ_SECONDS" -gt 14400 ]; then
        return 1
    fi
    printf 'FUZZ_SECS=%s\n' "$RAW_FUZZ_SECONDS"
}

check_rejected() {
    local input="$1" desc="$2"
    if out="$(validate "$input" 2>/dev/null)"; then
        echo "FAIL: expected reject for $desc (input=$input), got accepted: $out"
        fail=1
    else
        echo "✓ rejected: $desc"
    fi
}

check_accepted() {
    local input="$1" expect="$2"
    out="$(validate "$input" 2>/dev/null)"
    if [ "$out" != "FUZZ_SECS=$expect" ]; then
        echo "FAIL: expected accept for input=$input -> FUZZ_SECS=$expect, got: $out"
        fail=1
    else
        echo "✓ accepted: $input -> $out"
    fi
}

# --- injection payloads (the actual F1 exploit shape) ---
check_rejected '3600"; id; #' "quote-breakout shell injection"
# shellcheck disable=SC2016  # literal payload fixture, must not expand
check_rejected '$(id)' "command substitution"
# shellcheck disable=SC2016  # literal payload fixture, must not expand
check_rejected '`id`' "backtick substitution"
check_rejected '3600; rm -rf /' "semicolon-chained command"
check_rejected '3600 && id' "shell-and injection"
check_rejected $'3600\nid' "embedded newline"

# --- malformed / non-numeric ---
check_rejected '' "empty string"
check_rejected 'abc' "non-numeric"
check_rejected '-100' "negative number"
check_rejected '3600.5' "decimal"
check_rejected ' 3600' "leading whitespace"
check_rejected '3600 ' "trailing whitespace"

# --- boundary: over budget ---
check_rejected '14401' "one over the 14400s budget"
check_rejected '999999999' "way over budget"

# --- must still accept legitimate values ---
check_accepted '3600' 3600
check_accepted '0' 0
check_accepted '14400' 14400

# --- drift guard: fail loudly if the workflow's validation logic changes
# shape without this test being updated to match ---
if ! grep -q "'\*\[!0-9\]\*'" "$WORKFLOW" 2>/dev/null; then
    if ! grep -q '\*\[!0-9\]\*' "$WORKFLOW"; then
        echo "FAIL: ci-deep.yml's non-numeric guard pattern not found -- validate() above may have drifted from the live workflow"
        fail=1
    fi
fi
if ! grep -q '14400' "$WORKFLOW"; then
    echo "FAIL: ci-deep.yml no longer mentions the 14400s budget -- validate() above may have drifted from the live workflow"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: fuzz_seconds validation regression"
    exit 1
fi
echo "✓ all fuzz_seconds validation cases pass (injection rejected, valid values accepted)"
