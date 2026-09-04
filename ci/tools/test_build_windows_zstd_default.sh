#!/usr/bin/env bash
#
# Regression test for audit A30-F3: ci/tools/build-windows.sh defaulted
# REF_ZSTD_MODULE to a fixed historical commit (~154 commits behind at audit
# time) even though README.md presents this script alongside CURRENT
# behaviour, so the documented default silently built a stale module.
#
# The fix resolves REPO_ZSTD_MODULE/REF_ZSTD_MODULE from the running
# script's own checkout (HEAD) by default, keeping the old fixed commit only
# as a fallback for a standalone copy of the script outside any checkout,
# and keeps the REPO_ZSTD_MODULE/REF_ZSTD_MODULE overrides fully working.
#
# This cannot run the real script end-to-end (no MSVC / Windows toolchain
# here), so it isolates the default-resolution block -- the part of
# build-windows.sh between "### version + SHA-256 pins" and
# "# Download + verify" -- and drives it standalone with git stubs, which is
# testable without a Windows runtime.
#
# Usage: ci/tools/test_build_windows_zstd_default.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_WINDOWS_SH="$SCRIPT_DIR/build-windows.sh"

fail=0
ok() { printf 'OK: %s\n' "$*"; }
bad() {
    printf 'FAIL: %s\n' "$*"
    fail=1
}

# extract_resolution_block -- pulls the REPO_ZSTD_MODULE/REF_ZSTD_MODULE
# default-resolution logic (and its _zstd_module_repo_root helper) out of
# build-windows.sh, verbatim, between two anchor comments. If the anchors
# ever drift this fails loudly rather than silently testing stale logic.
extract_resolution_block() {
    awk '
        /^# Module refs/ { grab=1 }
        grab { print }
        /^fi$/ && grab { exit }
    ' "$BUILD_WINDOWS_SH"
}

BLOCK="$(extract_resolution_block)"
if ! grep -q '_zstd_module_repo_root' <<<"$BLOCK"; then
    echo "FATAL: could not extract the zstd-module default-resolution block from $BUILD_WINDOWS_SH -- anchors drifted" >&2
    exit 2
fi

echo "== case: inside a checkout, no override -> defaults to HEAD of that checkout =="
CKROOT="$(mktemp -d)"
(
    cd "$CKROOT"
    git init -q
    git config user.email test@example.com
    git config user.name test
    mkdir -p ci/tools
    cp "$BUILD_WINDOWS_SH" ci/tools/build-windows.sh
    git add -A
    git commit -q -m init
)
HEAD_SHA="$(git -C "$CKROOT" rev-parse HEAD)"
unset REPO_ZSTD_MODULE REF_ZSTD_MODULE
OUT="$(bash -c '
set -euo pipefail
'"$BLOCK"'
echo "REPO=$REPO_ZSTD_MODULE"
echo "REF=$REF_ZSTD_MODULE"
' "$CKROOT/ci/tools/build-windows.sh")"
if grep -q "REPO=$CKROOT" <<<"$OUT" && grep -q "REF=$HEAD_SHA" <<<"$OUT"; then
    ok "in-checkout default resolves REPO to the checkout and REF to its HEAD ($HEAD_SHA)"
else
    bad "in-checkout default did not resolve to the checkout's HEAD: $OUT"
fi

echo "== case: explicit REPO_ZSTD_MODULE/REF_ZSTD_MODULE override wins =="
OUT="$(REPO_ZSTD_MODULE="https://example.invalid/fork.git" REF_ZSTD_MODULE="deadbeef" bash -c '
set -euo pipefail
'"$BLOCK"'
echo "REPO=$REPO_ZSTD_MODULE"
echo "REF=$REF_ZSTD_MODULE"
' "$CKROOT/ci/tools/build-windows.sh")"
if grep -q "REPO=https://example.invalid/fork.git" <<<"$OUT" && grep -q "REF=deadbeef" <<<"$OUT"; then
    ok "explicit override is preserved, default resolution does not clobber it"
else
    bad "override was not preserved: $OUT"
fi

echo "== case: outside any checkout -> falls back to the documented pin =="
OUTSIDE="$(mktemp -d)"
unset REPO_ZSTD_MODULE REF_ZSTD_MODULE
OUT="$(bash -c '
set -euo pipefail
'"$BLOCK"'
echo "REPO=$REPO_ZSTD_MODULE"
echo "REF=$REF_ZSTD_MODULE"
' "$OUTSIDE/build-windows.sh")"
if grep -q "REPO=https://github.com/myguard-labs/nginx-zstd-module.git" <<<"$OUT" \
    && grep -q "REF=37cf9ac6b58284ae2da95620f4905930d1277b54" <<<"$OUT"; then
    ok "outside a checkout, falls back to the documented fixed pin"
else
    bad "fallback pin did not apply outside a checkout: $OUT"
fi

rm -rf "$CKROOT" "$OUTSIDE"

if [ "$fail" -eq 0 ]; then
    echo "all build-windows.sh zstd-module default cases pass"
else
    echo "one or more build-windows.sh zstd-module default cases FAILED"
fi
exit "$fail"
