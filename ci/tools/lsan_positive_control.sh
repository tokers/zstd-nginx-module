#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# lsan_positive_control() -- prove LeakSanitizer's exit-time check can
# actually detect a DELIBERATE leak in the current environment, before any
# caller trusts a "no leak" verdict from it.
#
# Why this exists: this runner pool intermittently blocks ptrace (LXC
# seccomp/yama on builder02), which is what LSan's exit-time tracer needs.
# When blocked, LSan emits "ptrace appears to be blocked (is seccomp
# enabled?)" and detects NOTHING -- the process just exits, and a caller
# that only greps its log for that one signature string is trusting an
# implementation detail of the warning message, not proving the detector
# ran. Observed directly in build-test.yml run 33084048220 ("Tests
# ASAN+UBSAN" job): the "Run smoke tests under ASAN+UBSAN" step printed
# "All smoke tests clean under ASAN+UBSAN" (neither a finding nor the
# ptrace signature in its log), and SECONDS later in the SAME job the
# "zstd_dict_file reload leak check" step (ci/tools/test_reload_leak.sh)
# hit the ptrace-blocked signature 4 times in a row. Same job, same
# runner, same environment -- so the smoke step's "clean" almost
# certainly meant "LSan's exit-time check never ran here either", not "no
# leak found". A clean log and a never-ran log are bitwise
# indistinguishable without an independent proof the detector fired.
#
# This function is that proof: it compiles a tiny known-leaking canary
# (a bare `malloc` with no free) with the SAME sanitizer the caller is
# using, runs it with detect_leaks=1 and a distinct exitcode, and requires
# that exact exitcode back. Only then is "clean" from the caller's real
# log trustworthy; anything else means the detector could not run here,
# which is INDETERMINATE, not a pass.
#
# Originally inline in ci/tools/test_reload_leak.sh; extracted so the
# smoke-tests step in .github/workflows/build-test.yml can share the
# exact same proof instead of a second, divergent copy.
#
# Verdict (return code) -- THREE distinct codes, not two, because "the
# control could not even be attempted" (no toolchain here) is a different
# fact than "the control ran and LSan failed it" (ptrace is blocked here):
# collapsing them would make a caller skip its real leak test on any
# runner that simply lacks an ASan-capable `cc`, silently losing coverage
# that runner always had before this function existed.
#   0  -- positive control PASSED: LSan caught the deliberate leak here.
#          The caller's own verdict for this run can be trusted.
#   1  -- positive control ATTEMPTED and FAILED: the canary compiled and
#          ran but its deliberate leak was not caught. LSan's exit-time
#          check is provably not working in this environment right now
#          (ptrace blocked is the known cause on this runner pool). Any
#          "clean" reading from the caller's real log is INDETERMINATE,
#          not a pass -- the caller should skip trusting its own leak
#          check and report INDETERMINATE instead.
#   2  -- control could NOT be attempted at all (no `cc` on PATH, or the
#          ASan compile itself failed -- e.g. no ASan runtime installed).
#          This says nothing about whether LSan's exit-time check works;
#          it means this function has no evidence either way. A caller
#          MUST NOT treat this as "indeterminate" and skip its real leak
#          check -- fall back to running that check exactly as if this
#          function did not exist (its historical behavior).
#
# Nothing is printed on success; failure paths are silent too -- the
# caller decides how loudly to report each code for its own context (a
# GitHub ::warning::, a distinct exit code, whatever fits the step).
#
# Usage (sourced):
#   if lsan_positive_control; then trust_clean
#   elif [ $? -eq 2 ]; then run_real_check_unverified   # could not attempt
#   else report_indeterminate; fi                        # attempted, failed
# Usage (direct):   ci/tools/lsan_positive_control.sh; echo $?
lsan_positive_control() {
    local work canary_c canary_bin crc

    command -v cc >/dev/null 2>&1 || return 2

    work="$(mktemp -d "${TMPDIR:-/tmp}/lsan-positive-control.XXXXXX")" || return 2
    canary_c="$work/canary.c"
    canary_bin="$work/canary"

    cat >"$canary_c" <<'EOF'
#include <stdlib.h>
int main(void) { malloc(1234); return 0; }
EOF

    if ! cc -fsanitize=address -o "$canary_bin" "$canary_c" 2>/dev/null; then
        rm -rf "$work"
        return 2
    fi

    crc=0
    ASAN_OPTIONS="detect_leaks=1:exitcode=23" \
        timeout 30 "$canary_bin" >/dev/null 2>&1 || crc=$?

    rm -rf "$work"

    [ "$crc" -eq 23 ] && return 0
    return 1
}

# Allow direct execution for ad hoc probing of the current environment:
#   ci/tools/lsan_positive_control.sh; echo $?
# Sourcing (as test_reload_leak.sh and the smoke-tests step do) must not
# run this -- BASH_SOURCE differs from $0 only when sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    lsan_positive_control
    exit $?
fi
