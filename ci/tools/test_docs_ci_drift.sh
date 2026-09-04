#!/usr/bin/env bash
#
# Regression test for audit sha e289021 F7: README/SECURITY/CONTRIBUTING
# drifted materially from the live CI workflows (stale badge count, dead
# AGENTS.md link, a workflow present in .github/workflows/ but undocumented,
# a false -Werror claim). The full fix was a one-time manual re-sync;
# nothing then stopped it drifting again on the next workflow add/rename.
#
# This does NOT try to keep exact TAP subtest counts in sync (that's
# exactly the kind of brittle exact-count claim the F7 fix already
# recommended dropping) -- it checks structural facts that are cheap to
# keep true and expensive to silently get wrong:
#   - every workflow file under .github/workflows/ is referenced somewhere
#     in README.md (by filename), so a new/renamed workflow can't go
#     undocumented
#   - every workflow referenced in README.md's badges/table actually exists
#     under .github/workflows/, so a removed/renamed workflow can't leave a
#     dead link/badge behind
#   - SECURITY.md does not link the removed AGENTS.md
#   - CONTRIBUTING.md does not claim the fuzz harness builds with -Werror
#     unless fuzz/build.sh (or equivalent) actually passes it
#
# Usage: tools/test_docs_ci_drift.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ci/tools/ -> ci/ -> repo root: TWO levels since the ci/ move. One climb
# lands in ci/, where README.md and .github/ do not exist -- and the loop
# below would then report every workflow undocumented.
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
cd "$MODULE_DIR" || exit 1
# shellcheck source=ci/linter/lib.sh
. "$MODULE_DIR/ci/linter/lib.sh"

collect_directives() {
    mapfile_checked DIRECTIVES sed -n \
        's/^### \(zstd[_a-z]*\)$/\1/p' README.md
}

produce_readme_workflows() {
    grep -oE 'workflows/[A-Za-z0-9_-]+\.yml' README.md \
        | sed 's#workflows/##' \
        | sort -u
}

collect_readme_workflows() {
    mapfile_checked README_WORKFLOWS produce_readme_workflows
}

case "${1:-}" in
    --selftest-directive-list)
        collect_directives || exit $?
        exit 0
        ;;
    --selftest-workflow-list)
        collect_readme_workflows || exit $?
        exit 0
        ;;
esac

fail=0
toc="$(sed -n '/^# Table of Contents$/,/^# Status$/p' README.md)"
local_suites="$(sed -n '/^Run the suites locally:/,/^# Unit tests/p' README.md)"
deep_suite_step="$(sed -n '/name: Run ci\/t\//,/^  fuzz:/p' .github/workflows/ci-deep.yml)"

# Every public directive heading must be reachable from the README index.
collect_directives || exit $?
for directive in "${DIRECTIVES[@]}"; do
    if ! grep -Fq -- "[$directive](#$directive)" <<<"$toc"; then
        echo "FAIL: README directive section $directive is missing from the table of contents"
        fail=1
    fi
done

# Commands advertised as the local/deep full suite must include every Perl suite.
for suite in ci/t/*.t; do
    name="$(basename "$suite")"
    grep -Fq -- "$name" <<<"$local_suites" || {
        echo "FAIL: README local test instructions omit $name"
        fail=1
    }
    if ! grep -F -- "$name" <<<"$deep_suite_step" \
        | grep -Eq '^[[:space:]]*prove '; then
        echo "FAIL: CI Deep full-suite claim omits $name"
        fail=1
    fi
done

# --- every real workflow file is mentioned in README.md ---
for wf in .github/workflows/*.yml; do
    name="$(basename "$wf")"
    if ! grep -q "$name" README.md; then
        echo "FAIL: .github/workflows/$name exists but is not referenced in README.md (undocumented workflow)"
        fail=1
    fi
done

# --- every workflow filename README.md references actually exists ---
collect_readme_workflows || exit $?
for name in "${README_WORKFLOWS[@]}"; do
    [ -f ".github/workflows/$name" ] || {
        echo "FAIL: README.md references .github/workflows/$name, which does not exist (stale/dead link or badge)"
        fail=1
    }
done

# --- SECURITY.md must not link the removed AGENTS.md ---
if [ -f SECURITY.md ] && grep -q 'AGENTS\.md' SECURITY.md; then
    echo "FAIL: SECURITY.md still links AGENTS.md, which was removed (PR #79)"
    fail=1
fi

# --- README's -DZSTD_STATIC_LINKING_ONLY claim must match auto/zstd's
# actual behavior (audit A31b-F5): the flag is committed to CFLAGS only
# inside the `ZSTD_INC`/`ZSTD_LIB` static-archive branch (auto/zstd's
# "we try the static library first" section) -- auto-discovery (no
# ZSTD_INC/ZSTD_LIB) and pkg-config never define it. The documented plain
# `./configure --add-dynamic-module=...` command therefore does not carry
# the flag, so README.md must say so explicitly rather than imply the
# flag is just "on" for anyone following the docs. This is a docs-drift
# regression test, not a build-behavior change: it never touches
# auto/zstd or the release build flags. ---
# shellcheck disable=SC2016  # literal grep pattern: $ZSTD_INC/$ must not expand
if ! grep -q '^[[:space:]]*ngx_zstd_opt_I="-I\$ZSTD_INC -DZSTD_STATIC_LINKING_ONLY"$' auto/zstd; then
    echo "FAIL: auto/zstd no longer stages -DZSTD_STATIC_LINKING_ONLY in the ZSTD_INC/ZSTD_LIB static-archive branch the way this test expects -- update auto/zstd's staging line or this test together with README.md's Installation/Compatibility wording"
    fail=1
fi
# Extract the WHOLE auto-discovery `else` branch (from its marker comment to
# the closing `fi` at the same indent) rather than a fixed window, so the flag
# cannot be reintroduced anywhere inside it and still pass this test.
zstd_autodisco_branch=$(
    sed -n '/^    # auto-discovery: prefer dynamic linking/,/^fi$/p' auto/zstd
)
if [ -z "$zstd_autodisco_branch" ]; then
    echo "FAIL: could not locate auto/zstd's auto-discovery branch (the '# auto-discovery: prefer dynamic linking' marker or its closing 'fi' moved) -- update this test together with auto/zstd and README.md"
    fail=1
elif printf '%s\n' "$zstd_autodisco_branch" | grep -q 'DZSTD_STATIC_LINKING_ONLY'; then
    echo "FAIL: auto/zstd's auto-discovery branch now mentions -DZSTD_STATIC_LINKING_ONLY -- README.md's 'plain ./configure does not enable it' claim is stale and must be rewritten to match"
    fail=1
fi
# shellcheck disable=SC2016  # literal README phrase, backticks must not run
if ! grep -Fq 'does not enable `-DZSTD_STATIC_LINKING_ONLY`' README.md; then
    echo "FAIL: README.md Installation section no longer states that the plain ./configure command does not enable -DZSTD_STATIC_LINKING_ONLY (audit A31b-F5 regression)"
    fail=1
fi
if grep -Fq 'production and CI builds enable that flag' README.md; then
    echo "FAIL: README.md re-introduced the 'production and CI builds enable that flag' phrasing, which reads as the flag being on by default rather than requiring ZSTD_INC/ZSTD_LIB pointed at a static libzstd (audit A31b-F5 regression)"
    fail=1
fi

# --- CONTRIBUTING.md's -Werror claim about the fuzz harness must match
# reality: only assert this if a fuzz build step actually exists and does
# NOT pass -Werror, since a future CI change legitimately flipping this on
# would make the check obsolete rather than wrong. ---
if [ -f CONTRIBUTING.md ] && grep -qi 'fuzz.*-Werror\|-Werror.*fuzz' CONTRIBUTING.md; then
    if ! grep -rq -- '-Werror' fuzz/ 2>/dev/null && ! grep -rlq -- '-Werror' .github/workflows/*.yml 2>/dev/null; then
        echo "FAIL: CONTRIBUTING.md claims the fuzz harness builds with -Werror, but no fuzz build step passes it"
        fail=1
    fi
fi

# --- README's static-probe skippable-chain bound must match
# NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES (audit A30-F6): the README states
# a concrete "up to 4 leading skippable frames" bound and says the
# declared-window check applies to the first REGULAR frame reached after
# that chain. Anchor both on the real code so a future change to the
# bound, or to which frame the window check targets, breaks this test
# instead of silently drifting the prose again. ---
skip_frames_define=$(
    grep -E '^#define[[:space:]]+NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES[[:space:]]+[0-9]+' \
        src/ngx_http_zstd_frame_probe.h
)
if [ -z "$skip_frames_define" ]; then
    echo "FAIL: could not find NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES in src/ngx_http_zstd_frame_probe.h -- update this test together with the source"
    fail=1
else
    skip_bound="$(printf '%s\n' "$skip_frames_define" | grep -oE '[0-9]+$')"
    if ! grep -Fq "up to $skip_bound leading skippable frames" README.md; then
        echo "FAIL: README.md's stated skippable-chain bound does not match NGX_HTTP_ZSTD_STATIC_MAX_SKIP_FRAMES ($skip_bound) in src/ngx_http_zstd_frame_probe.h -- update README.md's Declared-window/Magic-number validation prose"
        fail=1
    fi
fi
if ! grep -q 'ngx_http_zstd_static_probe_verdict' src/ngx_http_zstd_static_module.c; then
    echo "FAIL: ngx_http_zstd_static_probe_verdict no longer exists in src/ngx_http_zstd_static_module.c -- the window-check anchor this test relies on moved or was renamed; update this test together with README.md"
    fail=1
fi
if ! grep -Fq 'first regular frame' README.md; then
    echo "FAIL: README.md no longer states that the declared-window check applies to the first REGULAR frame reached after the leading skippable-frame chain (audit A30-F6 regression)"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: docs/CI drift detected (audit sha e289021 F7 regression)"
    exit 1
fi
echo "✓ README/SECURITY/CONTRIBUTING workflow references match .github/workflows/ contents"
