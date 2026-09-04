#!/usr/bin/env bash
#
# Unit fixture for soak_asan_verdict() (ci/tools/soak_asan_verdict.sh).
#
# A27-F9: ci/tools/soak.sh used to fail the ASAN/UBSAN soak when
# "$WORK/logs/asan*" merely EXISTED, never reading its content -- so a
# LeakSanitizer that could not even start (ptrace blocked by this runner
# pool's LXC seccomp/yama profile -- see soak_asan_verdict.sh's header)
# looked identical to a real finding. Observed in CI: PR #214 run
# 33117464973, job "A/UBSan / ASan/UBSan soak (60s)" attempt 1 failed
# with "FAIL: ASAN/UBSAN report:" whose entire payload was
#   ==4635==WARNING: ptrace appears to be blocked (is seccomp enabled?).
#   ==4635==Child exited with signal 32.
# with all four soak workers having reported clean in the same run.
# Attempt 2 (identical binary, identical soak) passed with no asan* file
# written at all.
#
# This drives soak_asan_verdict() directly against four fixtures, sources
# the SAME file soak.sh sources (no hand-copied logic to drift), and ends
# with a mandatory negative control: the ORIGINAL `ls`-only gate applied to
# the ptrace-only fixture, proving that gate fails on exactly this input --
# the false-failure this whole row exists to fix.
#
# No nginx, no libzstd, no network -- pure Bash.
#
# Usage: tools/test_soak_asan_verdict_unit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tools/soak_asan_verdict.sh
. "$SCRIPT_DIR/soak_asan_verdict.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/soak-asan-verdict-unit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail=0

# assert_verdict <fixture-file-or-empty> <expected-rc> <label>
# expected-rc: 0 pass, 1 fail (real finding), 2 indeterminate (ptrace).
# A "-" fixture means "no log file at all" (absent-log case).
assert_verdict() {
    local fixture="$1" expected="$2" label="$3"
    local rc

    if [ "$fixture" = "-" ]; then
        set +e
        soak_asan_verdict "$WORK/does-not-exist.*"
        rc=$?
        set -e
    else
        set +e
        soak_asan_verdict "$fixture"
        rc=$?
        set -e
    fi

    if [ "$rc" -ne "$expected" ]; then
        echo "FAIL: $label -- soak_asan_verdict returned $rc, want $expected" >&2
        fail=1
        return
    fi
    echo "OK: $label (rc=$rc)"
}

# ── Fixture 1: ptrace/seccomp startup noise only, no finding ──────────
# Verbatim shape of the PR #214 attempt-1 payload above.
cat >"$WORK/asan.ptrace_only" <<'EOF'
==4635==WARNING: ptrace appears to be blocked (is seccomp enabled?). LeakSanitizer may hang.
==4635==Child exited with signal 32.
EOF
assert_verdict "$WORK/asan.ptrace_only" 2 "ptrace/seccomp warning only => INDETERMINATE (not a finding)"

# ── Fixture 2: a real ASan finding ────────────────────────────────────
cat >"$WORK/asan.real_asan" <<'EOF'
==4712==ERROR: AddressSanitizer: heap-use-after-free on address 0x60200000eff0 at pc 0x0000004a3b21 bp 0x7ffd7f3b3aa0 sp 0x7ffd7f3b3a98
READ of size 8 at 0x60200000eff0 thread T0
    #0 0x4a3b20 in ngx_http_zstd_body_filter
SUMMARY: AddressSanitizer: heap-use-after-free
EOF
assert_verdict "$WORK/asan.real_asan" 1 "real heap-use-after-free => FAIL"

# ── Fixture 3: a real UBSan finding (its own "runtime error:" shape,
#    NOT the ERROR:/SUMMARY: banner ASan/LSan use) ────────────────────
cat >"$WORK/asan.real_ubsan" <<'EOF'
ngx_http_zstd_filter_module.c:512:14: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
EOF
assert_verdict "$WORK/asan.real_ubsan" 1 "UBSan runtime error: line => FAIL"

# ── Fixture 4: no log at all (absent) ─────────────────────────────────
assert_verdict "-" 0 "no asan* log file at all => PASS"

# ── Mandatory negative control ────────────────────────────────────────
# Revert to the historical bug: a bare `ls ... >/dev/null 2>&1` gate that
# fails on EXISTENCE alone, applied to fixture 1 (ptrace-only noise, no
# finding). It must now report FAIL -- proving this fixture reproduces
# the exact false-positive PR #214 hit, and that soak_asan_verdict() is
# the thing that fixes it rather than something incidental.
echo
echo "-- negative control: reverting to the ls-only existence gate --"
neg_control_output=""
neg_control_rc=0
if ls "$WORK"/asan.ptrace_only >/dev/null 2>&1; then
    neg_control_output="FAIL: ASAN/UBSAN report:
$(cat "$WORK/asan.ptrace_only")"
    neg_control_rc=1
fi
echo "$neg_control_output"
if [ "$neg_control_rc" -ne 1 ]; then
    echo "FAIL: negative control did not reproduce the original bug" \
         "(expected the ls-only gate to fail on ptrace-only noise)" >&2
    fail=1
else
    echo "OK: negative control reproduces the original false failure" \
         "(ls-only gate FAILs on ptrace-only noise, as PR #214 observed)"
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: soak_asan_verdict unit fixture had failures" >&2
    exit 1
fi
echo "OK: soak_asan_verdict unit fixture -- all cases + negative control passed"
