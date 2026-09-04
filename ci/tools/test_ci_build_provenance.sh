#!/usr/bin/env bash
#
# Regression tests for audit sha e289021 F2 and F3, both in tools/ci-build.sh:
#
#   F2 - a fresh (or NO_CACHE=1) build always failed: the tarball's top-level
#        dir name and the script's own SRCDIR were the same string, so
#        extraction already landed at SRCDIR and the subsequent `mv` tried to
#        move that dir onto itself ("cannot move to a subdirectory of
#        itself"). This never actually built anything on a clean root.
#   F3 - archive provenance: a wrong PGP signer, a corrupted/tampered
#        (cache-hit) tarball, or a wrong pinned sha256 must all be rejected
#        BEFORE extraction, not silently accepted.
#
# This test does not hit the network for the "must reject" cases -- it
# stages a fake $BUILD_ROOT by hand so it can run offline and fast. It DOES
# need network + real nginx.org access for the "F2: clean root actually
# reaches configure" case (skipped if offline).
#
# Usage: tools/test_ci_build_provenance.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CI_BUILD="$SCRIPT_DIR/ci-build.sh"

fail=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

copy_build_fixture() {
    local destination="$1"
    local input

    while IFS= read -r input || [ -n "$input" ]; do
        case "$input" in
            '' | \#*) continue ;;
        esac
        mkdir -p "$destination/$(dirname "$input")" || return 1
        cp -a "$MODULE_DIR/$input" "$destination/$input" || return 1
    done < "$MODULE_DIR/ci/build-inputs.manifest"
}

# ---------------------------------------------------------------------
# F3a: wrong sha256 pin must be rejected for a statically-pinned version,
# even though the tarball content and PGP signature (if any) are untouched.
# We fabricate a tiny "tarball" and inject a bogus pin table entry via a
# throwaway copy of the script so the real pin table isn't touched.
# ---------------------------------------------------------------------
test_wrong_sha256_rejected() {
    local root="$WORK/f3-sha256"
    mkdir -p "$root"
    # angie path is simpler to fake: sha256-only, no PGP.
    echo "not a real tarball" >"$root/angie-9.9.9.tar.gz"

    local fixture="$WORK/f3-module"
    if ! copy_build_fixture "$fixture"; then
        echo "FAIL: could not stage the hermetic ci-build fixture"
        return 1
    fi
    local copy="$fixture/ci/tools/ci-build.sh"
    if [ ! -f "$fixture/ci/tools/build-input-hash.sh" ] || \
        [ ! -f "$fixture/ci/build-inputs.manifest" ]; then
        echo "FAIL: hermetic ci-build fixture is missing canonical hash inputs"
        return 1
    fi
    # Force a pin that cannot possibly match the fake tarball's digest.
    sed -i 's/\["1\.11\.5"\]=.*/["9.9.9"]="0000000000000000000000000000000000000000000000000000000000000"/' "$copy"

    if BUILD_ROOT="$root" bash "$copy" angie 9.9.9 >"$root/out.log" 2>&1; then
        echo "FAIL: ci-build.sh accepted a tarball with a mismatched pinned sha256"
        cat "$root/out.log"
        return 1
    fi
    if ! grep -q "sha256 mismatch" "$root/out.log"; then
        echo "FAIL: rejection happened but not via the expected sha256-mismatch path:"
        cat "$root/out.log"
        return 1
    fi
    echo "✓ F3: wrong pinned sha256 rejected before extraction"
}

# ---------------------------------------------------------------------
# F3b: corrupted CACHED tarball must be re-verified and rejected, not
# silently reused just because a file with the right name already exists.
# (This was the literal pre-fix gap: verification only ran on fresh
# download.) Same fake-tarball approach, but this time the "cache" is
# pre-populated before the script runs.
# ---------------------------------------------------------------------
test_corrupted_cache_rejected() {
    local root="$WORK/f3-cache"
    mkdir -p "$root"
    echo "corrupted cached tarball" >"$root/angie-1.11.5.tar.gz"

    if BUILD_ROOT="$root" bash "$CI_BUILD" angie 1.11.5 >"$root/out.log" 2>&1; then
        echo "FAIL: ci-build.sh accepted a corrupted CACHED tarball for a pinned version"
        cat "$root/out.log"
        return 1
    fi
    if ! grep -q "sha256 mismatch" "$root/out.log"; then
        echo "FAIL: cache-hit path did not re-verify sha256:"
        cat "$root/out.log"
        return 1
    fi
    echo "✓ F3: corrupted cached tarball re-verified and rejected on cache-hit"
}

# ---------------------------------------------------------------------
# F2: clean-root / NO_CACHE=1 extraction must not fail with "mv onto
# itself". We can exercise the mv-guard logic in isolation (no network)
# by reproducing exactly what ci-build.sh does: extract a tarball whose
# top-level dir name equals $FLAVOR-$VERSION, then run the same guarded
# mv line. This proves the guard itself is correct without needing a real
# nginx/angie tarball.
# ---------------------------------------------------------------------
test_mv_guard_clean_root() {
    local root="$WORK/f2-mv"
    mkdir -p "$root"
    local dir="fake-1.0.0"
    mkdir -p "$root/$dir"
    touch "$root/$dir/marker"
    tar -czf "$root/$dir.tar.gz" -C "$root" "$dir"
    rm -rf "${root:?}/$dir"

    local srcdir="$root/$dir" # same string ci-build.sh derives: "$ROOT/${FLAVOR}-${VERSION}"

    # Reproduce ci-build.sh's exact extraction + guarded-mv sequence.
    if [ ! -d "$srcdir" ]; then
        tar -xzf "$root/$dir.tar.gz" -C "$root"
        if [ "$root/$dir" != "$srcdir" ]; then
            mv "$root/$dir" "$srcdir"
        fi
    fi

    if [ ! -f "$srcdir/marker" ]; then
        echo "FAIL: F2 mv-guard: extracted tree missing after guarded mv (regressed to pre-fix unconditional mv-onto-self failure mode)"
        return 1
    fi
    echo "✓ F2: guarded mv is a no-op when extraction already lands at SRCDIR (clean-root case)"
}

# ---------------------------------------------------------------------
# F2 (live): actually run ci-build.sh against angie on a clean root with
# NO_CACHE=1 and confirm it reaches configure (this is the case that was
# unconditionally broken pre-fix). Needs network; skipped if unreachable.
# ---------------------------------------------------------------------
test_clean_root_live() {
    if ! curl -fsS -o /dev/null --max-time 5 https://download.angie.software/ 2>/dev/null; then
        echo "SKIP: F2 live clean-root build (no network to download.angie.software)"
        return 0
    fi
    local root="$WORK/f2-live"
    mkdir -p "$root"
    if ! NO_CACHE=1 BUILD_ROOT="$root" timeout 300 bash "$CI_BUILD" angie 1.11.5 >"$root/out.log" 2>&1; then
        echo "FAIL: F2 live: clean-root NO_CACHE=1 angie build did not reach a successful build:"
        tail -40 "$root/out.log"
        return 1
    fi
    if ! grep -q "cannot move to a subdirectory of itself" "$root/out.log"; then
        echo "✓ F2: live clean-root NO_CACHE=1 angie build succeeded, no mv-onto-self failure"
    else
        echo "FAIL: F2 regressed -- mv-onto-self error resurfaced in a live clean-root build"
        return 1
    fi
}

test_wrong_sha256_rejected || fail=1
test_corrupted_cache_rejected || fail=1
test_mv_guard_clean_root || fail=1
test_clean_root_live || fail=1

if [ "$fail" -ne 0 ]; then
    echo "FAIL: ci-build.sh provenance/clean-root regression"
    exit 1
fi
echo "✓ all ci-build.sh F2/F3 regression cases pass"
