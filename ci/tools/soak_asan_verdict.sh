#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# soak_asan_verdict() -- triage an ASAN_OPTIONS log_path glob's content and
# decide whether the soak passes, fails, or is INDETERMINATE.
#
# A27-F9: ci/tools/soak.sh used to gate on whether ANY "$WORK/logs/asan*"
# file existed at all, never reading it. log_path (see soak.sh's
# ASAN_OPTIONS) makes the sanitizer runtime write EVERY file it wants to
# emit into that glob -- including pure diagnostics that are not findings,
# such as LeakSanitizer's own "ptrace appears to be blocked (is seccomp
# enabled?)" startup warning. On this runner pool (LXC seccomp/yama on
# builder02) that warning fires routinely: the same signature shows up in
# ci/tools/test_reload_leak.sh and the "Run smoke tests under ASAN+UBSAN"
# step in .github/workflows/build-test.yml, both of which already read
# content instead of existence for exactly this reason. This file extracts
# that same triage into one function so soak.sh and this unit fixture share
# one source of truth instead of two copies drifting apart.
#
# Verdict (mirrors the valgrind/helgrind branch a few lines below this
# call site in soak.sh, and the two existing ptrace-aware call sites
# above):
#   0 (pass, clean)          -- no log, or a log with no recognized
#                                sanitizer finding and no ptrace-blocked
#                                signature (diagnostics of some other,
#                                unrecognized kind still count as clean
#                                here -- this function only fails on an
#                                actual finding).
#   1 (fail)                 -- a real ASan/LSan/UBSan finding.
#   2 (indeterminate)        -- LeakSanitizer's exit-time check could not
#                                run (ptrace blocked). NOT a pass and NOT
#                                a fail: the leak lane checked nothing
#                                this run, so a plain 0 would misreport
#                                "no leaks" when nothing was actually
#                                verified.
#
# The log content (if any) is always echoed by the caller-visible path
# (soak.sh cats it), independent of this function's return code, so the
# condition stays visible in the job log instead of going silent -- this
# function only classifies, it does not print.
#
# Usage: soak_asan_verdict <file> [<file> ...]
#   A caller like `soak_asan_verdict "$WORK"/logs/asan*` that had no
#   matching files (glob left unexpanded, nullglob off) is handled: this
#   function treats a sole non-existent path as "no log" (verdict 0),
#   the same as the historical `ls ... >/dev/null 2>&1` gate finding
#   nothing.
soak_asan_verdict() {
    local existing=()
    local f

    for f in "$@"; do
        [ -f "$f" ] && existing+=("$f")
    done

    # No log at all: nothing to triage, and nothing was written, so this
    # is a clean pass (the historical "ls found nothing" case).
    [ "${#existing[@]}" -eq 0 ] && return 0

    # Real sanitizer findings fail unconditionally, checked FIRST: a run
    # can produce a ptrace warning from one worker and a real finding
    # from another (log_path writes one file per process), and checking
    # ptrace first would let the warning short-circuit the verdict and
    # mask the finding -- the same ordering test_reload_leak.sh and the
    # build-test.yml smoke-tests step already use, for the same reason.
    #
    # Patterns, and why these specifically -- this repo builds with
    # -fsanitize=address,undefined -fno-sanitize-recover=undefined, and
    # these are what each sanitizer's real output actually looks like,
    # not a guess from memory:
    #   ERROR: (Address|Leak|UndefinedBehavior)Sanitizer  -- the banner
    #     every ASan/LSan finding opens with (heap-buffer-overflow,
    #     use-after-free, detected memory leaks, ...).
    #   SUMMARY: (Address|Leak|UndefinedBehavior)Sanitizer -- the summary
    #     line every finding also emits; belt and suspenders in case a
    #     report is truncated before its ERROR banner but the summary
    #     line still lands.
    #   runtime error: -- UBSan's OWN finding format. It is not an
    #     "ERROR:"/"SUMMARY:" banner at all -- that shape belongs to
    #     ASan/LSan. -fno-sanitize-recover=undefined means the process
    #     aborts on the first one, so a single line is sufficient.
    if grep -qE 'ERROR: (Address|Leak|UndefinedBehavior)Sanitizer|SUMMARY: (Address|Leak|UndefinedBehavior)Sanitizer|runtime error:' \
        "${existing[@]}" 2>/dev/null; then
        return 1
    fi

    # The known lockdown signature (see the file header): LSan's
    # exit-time tracer was blocked/killed before it could inspect
    # anything. No verdict exists in either direction for the leak lane.
    if grep -qE 'ptrace appears to be blocked|LeakSanitizer may hang|Child exited with signal' \
        "${existing[@]}" 2>/dev/null; then
        return 2
    fi

    # A log existed but held neither a recognized finding nor the
    # ptrace-blocked signature: pass. (Nothing currently writes
    # log_path files outside those two shapes, but this function's job
    # is to fail on findings, not on "log exists" -- the exact defect
    # A27-F9 exists to fix.)
    return 0
}

# Allow direct execution for ad hoc triage of an already-captured log:
#   ci/tools/soak_asan_verdict.sh /path/to/asan.*
# Sourcing (as soak.sh and the unit fixture do) must not run this --
# BASH_SOURCE differs from $0 only when sourced.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    soak_asan_verdict "$@"
    exit $?
fi
