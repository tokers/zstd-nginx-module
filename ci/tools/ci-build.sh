#!/bin/bash
# Build and test zstd-nginx-module against nginx or angie.
#
#   ci/tools/ci-build.sh [flavor] [version] [mode]
#     flavor : nginx (default) | angie
#     version: source version, e.g. 1.31.2. Omit (or pass "" with flavor=nginx)
#              to resolve the current mainline release from nginx.org.
#     mode   : release (default) | coverage
#              coverage adds --coverage to cc-opt/ld-opt and builds into a
#              SEPARATE tree (.build/<flavor>-<version>-coverage/) so a
#              coverage-instrumented .so is never the one a non-coverage job
#              picks up by cache hit. It is never bolted onto release as a
#              flag: gcda/gcno files left in a shared tree would poison the
#              next plain build's cache key without changing the key itself.
#
# Built tree persists at .build/<flavor>-<version>[-<mode>]/objs/{<flavor>,ngx_http_zstd_*.so}
# so a caller (a CI job) can find the binary and both dynamic modules after
# the script exits — unlike the old single-nginx version of this script, which
# built under /tmp and deleted it on exit. NO_CACHE=1 forces a from-scratch
# rebuild of a given flavor/version/mode triple.
#
# nginx tarballs are verified via PGP against the signer keys VENDORED in
# ci/tools/keys/ (committed to this repo) — never fetched from nginx.org at CI
# time. Bootstrapping the verification keys from the same origin that serves
# the tarball+signature gives an origin compromise the ability to substitute
# all three (audit sha e289021 F3); a key rotation is a reviewed PR that adds
# a new file under ci/tools/keys/, not a runtime fetch. For a statically-pinned
# nginx version (nginx-stable in ci-deep.yml's matrix) the sha256 is ALSO
# checked against NGINX_SHA256 below, same as angie -- floating mainline
# (resolved at CI run time, see build-test.yml's `resolve` job) has no static
# pin and relies on PGP alone. angie.software does not publish a PGP
# signature for release tarballs, so angie tarballs are checked by sha256
# only, pinned in ANGIE_SHA256 below (computed once from an HTTPS fetch, same
# approach the sibling nginx-skeleton-module repo uses for both flavors). A
# version not in a pin table still builds (this script tracks moving
# releases; refusing to build an unpinned version would break every future
# version bump until someone updates the table first) but prints a loud
# warning so the gap is visible.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ci/tools/ -> ci/ -> repo root. TWO levels: this script lived in tools/ at
# the root until the ci/ move, where one dirname was enough. A single climb
# now lands in ci/, where the module config and .build/ do not exist, and the
# build silently configures against the wrong tree.
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

FLAVOR="${1:-nginx}"
VERSION="${2:-}"
MODE="${3:-release}"

case "$FLAVOR" in
    nginx | angie) ;;
    *)
        echo "ERROR: unsupported flavor: $FLAVOR (want: nginx|angie)" >&2
        exit 2
        ;;
esac

case "$MODE" in
    release | coverage) ;;
    *)
        echo "ERROR: unsupported mode: $MODE (want: release|coverage)" >&2
        exit 2
        ;;
esac

if [ -z "$VERSION" ]; then
    if [ "$FLAVOR" != "nginx" ]; then
        echo "ERROR: a version is required for flavor=$FLAVOR" >&2
        exit 2
    fi
    # Resolve the current mainline release; nginx.org only keeps the newest
    # mainline tarball, so a hardcoded version eventually 404s.
    VERSION="$(curl -fsSL https://nginx.org/en/download.html |
        grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' |
        sort -V | tail -1)"
    if [ -z "$VERSION" ]; then
        echo "ERROR: could not resolve mainline nginx version from nginx.org" >&2
        exit 1
    fi
fi

# --- pinned sha256 for angie tarballs we've actually verified ---
declare -A ANGIE_SHA256=(
    ["1.12.1"]="5f4f203be2aca6fe20770b489c720e46e51d337e521065e7e472b61e24e3d2f5"
    ["1.11.5"]="b5f297c6df2a74b9d0091a7cdd747fffd2d0e1d0be43632da61c1c7539db2043"
)

# --- pinned sha256 for statically-pinned nginx-stable versions we've
# actually verified (floating mainline, resolved at CI run time, has no
# entry here and relies on the PGP check alone) ---
declare -A NGINX_SHA256=(
    ["1.30.4"]="4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b"
    ["1.30.3"]="e5823dc6f45610993def93ebf6cfce68264af4958c77e874b7d20f3709001b8f"
)

KEYRING_DIR="$SCRIPT_DIR/keys"

ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
NO_CACHE="${NO_CACHE:-0}"
ZSTD_MODULE_DIR="$MODULE_DIR"

case "$FLAVOR" in
    nginx)
        DIR="nginx-${VERSION}"
        URL="https://nginx.org/download/${DIR}.tar.gz"
        ;;
    angie)
        DIR="angie-${VERSION}"
        URL="https://download.angie.software/files/${DIR}.tar.gz"
        ;;
esac

# Coverage gets its own build tree so an instrumented .so is never served by
# a plain release cache hit -- see the mode note in the file header.
if [ "$MODE" = "coverage" ]; then
    SRCDIR="$ROOT/${FLAVOR}-${VERSION}-coverage"
else
    SRCDIR="$ROOT/${FLAVOR}-${VERSION}"
fi
TARBALL="$ROOT/${DIR}.tar.gz"

echo "=========================================================================="
echo "  zstd-nginx-module CI Build"
echo "=========================================================================="
echo ""
echo "Module: $ZSTD_MODULE_DIR"
echo "Flavor: $FLAVOR  Version: $VERSION  Mode: $MODE"
echo "Build tree: $SRCDIR"
echo ""

mkdir -p "$ROOT"

if [ "$NO_CACHE" = "1" ]; then
    rm -rf "$SRCDIR" "$TARBALL"
fi

# Input stamp. A build tree is keyed by flavor/version/mode only, but its objects
# also depend on every path in ci/build-inputs.manifest. On a
# persistent self-hosted runner the directory outlives these inputs, so without a
# stamp a changed src/ silently reuses the old objects and CI reports on a binary
# that no longer matches the tree. The Actions cache does not save us: a cache
# MISS still finds the retained local directory.
STAMP_INPUTS="$(bash "$SCRIPT_DIR/build-input-hash.sh" "$ZSTD_MODULE_DIR")"
STAMP_FILE="$SRCDIR/.myguard-build-inputs"
if [ -d "$SRCDIR" ] && [ "$(cat "$STAMP_FILE" 2>/dev/null || true)" != "$STAMP_INPUTS" ]; then
    echo "Build inputs changed since this tree was built -- rebuilding from scratch."
    rm -rf "$SRCDIR"
fi

echo "=========================================================================="
echo "Phase 1: Downloading $FLAVOR $VERSION"
echo "=========================================================================="
echo ""

if [ ! -f "$TARBALL" ]; then
    wget -q -O "$TARBALL" "$URL"
    echo "✓ Downloaded ${DIR}.tar.gz"
else
    echo "✓ Using cached ${DIR}.tar.gz"
fi

# Verification always runs, cache hit or fresh download -- a cached tarball
# is exactly as untrusted as a freshly-downloaded one until re-checked
# (audit sha e289021 F3: "cached archives are not reverified" was a gap in
# the pre-fix version of this script).
if [ "$FLAVOR" = "nginx" ]; then
    # Always fetch over HTTPS and verify the detached PGP signature against
    # the nginx release-signing keys VENDORED in ci/tools/keys/ (not fetched
    # from nginx.org, which also serves the tarball+signature -- see the
    # file header). A plain HTTP download lets a network attacker swap the
    # source that we then configure and compile.
    if [ ! -f "${TARBALL}.asc" ]; then
        wget -q "${URL}.asc" -O "${TARBALL}.asc"
    fi

    gnupghome="$(mktemp -d)"
    export GNUPGHOME="$gnupghome"
    chmod 700 "$gnupghome"
    shopt -s nullglob
    keyfiles=("$KEYRING_DIR"/*.key)
    shopt -u nullglob
    if [ ${#keyfiles[@]} -eq 0 ]; then
        echo "✗ no vendored keys found in $KEYRING_DIR" >&2
        rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
        exit 1
    fi
    for keyfile in "${keyfiles[@]}"; do
        gpg --quiet --import "$keyfile" 2>/dev/null
    done

    if gpg --quiet --verify "${TARBALL}.asc" "$TARBALL"; then
        echo "✓ PGP signature verified for ${DIR}.tar.gz"
    else
        echo "✗ PGP signature verification FAILED for ${DIR}.tar.gz" >&2
        rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
        exit 1
    fi
    rm -rf "$gnupghome"
    unset GNUPGHOME

    EXPECTED="${NGINX_SHA256[$VERSION]:-}"
    if [ -n "$EXPECTED" ]; then
        ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "✗ sha256 mismatch for ${DIR}.tar.gz" >&2
            echo "  expected: $EXPECTED" >&2
            echo "  actual:   $ACTUAL" >&2
            rm -f "$TARBALL" "${TARBALL}.asc"
            exit 1
        fi
        echo "✓ sha256 verified for ${DIR}.tar.gz"
    fi
else
    EXPECTED="${ANGIE_SHA256[$VERSION]:-}"
    if [ -n "$EXPECTED" ]; then
        ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
        if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "✗ sha256 mismatch for ${DIR}.tar.gz" >&2
            echo "  expected: $EXPECTED" >&2
            echo "  actual:   $ACTUAL" >&2
            rm -f "$TARBALL"
            exit 1
        fi
        echo "✓ sha256 verified for ${DIR}.tar.gz"
    else
        echo "WARNING: no pinned sha256 for angie $VERSION -- add one to" \
            "ANGIE_SHA256 in tools/ci-build.sh (downloaded tarball is" \
            "UNVERIFIED)" >&2
    fi
fi

if [ ! -d "$SRCDIR" ]; then
    tar -xzf "$TARBALL" -C "$ROOT"
    # The tarball's top-level dir name ($DIR = "<flavor>-<version>") and our
    # build-tree name ($SRCDIR) are the same string, so the extracted path
    # IS already $SRCDIR -- moving it onto itself fails ("cannot move to a
    # subdirectory of itself") on a clean root / NO_CACHE=1 run. Only mv if
    # extraction actually landed somewhere else.
    if [ "$ROOT/$DIR" != "$SRCDIR" ]; then
        mv "$ROOT/$DIR" "$SRCDIR"
    fi
fi

printf '%s\n' "$STAMP_INPUTS" > "$STAMP_FILE"

cd "$SRCDIR"

echo ""
echo "=========================================================================="
echo "Phase 2: Configuring $FLAVOR with zstd module"
echo "=========================================================================="
echo ""

# The flags below are what t/ requires, not preferences — build-test.yml's
# nginx carries the same set, and CI Deep's binary has to match or the suite
# fails on the build rather than on the module:
#   http_sub_module      — t/00-filter.t TEST 33 uses sub_filter
#   http_auth_request    — t/00-filter.t TEST 58 uses auth_request
#     (without either, config load fails with "unknown directive" and
#      Test::Nginx bails out of the whole TAP file)
#   --with-debug         — TEST 91 asserts on a debug-level error.log line
#   no ZSTD_STATIC_LINKING_ONLY for release — this script's normal output is a
#     deployable dynamic module against libzstd.so, whose ABI does not
#     guarantee the static-only entry points. Coverage is the exception: it
#     exercises estimator-only config paths and is never published as the
#     deployable artifact.
# Coverage adds --coverage to BOTH cc-opt and ld-opt via the configure
# argument, not env CC/CFLAGS -- nginx's configure probes the compiler with
# its own invocations (`` `$CC -v ...` ``, unquoted so it also splits on a
# ccache prefix) and ignores a bare CC=/CFLAGS= override entirely: nothing in
# configure or the generated Makefile ever reads it.
CC_OPT=""
LD_OPT=""
if [ "$MODE" = "coverage" ]; then
    CC_OPT="$CC_OPT -DZSTD_STATIC_LINKING_ONLY --coverage -O0"
    LD_OPT="--coverage"
fi

# ccache goes through --with-cc, the one flag configure actually reads for the
# compiler pathname, not env CC= (same reason as above). CCACHE_COMPILERCHECK
# content -- not the mtime-based default -- so a compiler reinstalled at the
# same path with the same version string still hits cache; skipped under
# coverage, where --coverage recompiles from a clean tree every run anyway and
# a cache lookup only adds an unproductive stat.
CC_BIN="gcc"
if [ "$MODE" != "coverage" ] && command -v ccache >/dev/null 2>&1; then
    export CCACHE_COMPILERCHECK=content
    CC_BIN="ccache gcc"
fi

# mold as the linker, cheapest cache layer of all (no key, no invalidation
# logic -- just a faster ld). Skipped under coverage: --coverage's own gcov
# runtime linking has known mold interop gaps, and this script has no ASan
# mode to skip it for yet (asan.yml builds outside ci-build.sh entirely).
if [ "$MODE" != "coverage" ] && command -v mold >/dev/null 2>&1; then
    LD_OPT="$LD_OPT -fuse-ld=mold"
fi

./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/"$FLAVOR" \
    --with-debug \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_realip_module \
    --with-http_v2_module \
    --with-http_sub_module \
    --with-http_auth_request_module \
    --with-cc="$CC_BIN" \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    --add-dynamic-module="$ZSTD_MODULE_DIR" \
    2>&1 | tail -5

echo "✓ Configuration complete"

echo ""
echo "=========================================================================="
echo "Phase 3: Compiling $FLAVOR"
echo "=========================================================================="
echo ""

make -j"$(nproc)" 2>&1 | tail -10
if [ "$MODE" != "coverage" ]; then
    "$ZSTD_MODULE_DIR/ci/tools/check-zstd-dynamic-linkage.sh" \
        objs/ngx_http_zstd_filter_module.so
fi

echo ""
echo "=========================================================================="
echo "Phase 4: Verifying compiled modules"
echo "=========================================================================="
echo ""

if [ -f objs/ngx_http_zstd_filter_module.so ]; then
    echo "✓ Filter module compiled: objs/ngx_http_zstd_filter_module.so"
    file objs/ngx_http_zstd_filter_module.so
else
    echo "✗ Filter module NOT found!"
    exit 1
fi

if [ -f objs/ngx_http_zstd_static_module.so ]; then
    echo "✓ Static module compiled: objs/ngx_http_zstd_static_module.so"
    file objs/ngx_http_zstd_static_module.so
else
    echo "✗ Static module NOT found!"
    exit 1
fi

if [ ! -f "objs/$FLAVOR" ]; then
    echo "✗ $FLAVOR binary NOT found!"
    exit 1
fi

echo ""
echo "=========================================================================="
echo "✓ Build successful!"
echo "=========================================================================="
echo ""
echo "Server + modules ready in: $SRCDIR/objs/"
echo "  - $FLAVOR"
echo "  - ngx_http_zstd_filter_module.so"
echo "  - ngx_http_zstd_static_module.so"
