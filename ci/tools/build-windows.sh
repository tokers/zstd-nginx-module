#!/bin/bash
#
# Windows/MSVC build of nginx with this repo's modules: the zstd module
# pair by default, and/or the unified nginx-compression module and
# ngx_brotli, plus optionally headers-more. Produces a static nginx.exe
# comparable to the nginx.org Windows binary, plus the modules.
#
# Prerequisites:
#   1. Visual Studio (or Build Tools) with the C++ workload.
#   2. MSYS2 (https://www.msys2.org/), with git and cmake available in
#      the shell (pacman -S git mingw-w64-x86_64-cmake).
#   3. Strawberry Perl (https://strawberryperl.com/). OpenSSL's Windows
#      build requires a NATIVE perl; the MSYS perl generates paths the
#      MSVC toolchain cannot use. Auto-detected below; override with
#      STRAWBERRY_PERL=/c/path/to/perl/bin if installed elsewhere.
#
# Launching the build shell (the part every old guide gets wrong):
#   1. Open "x64 Native Tools Command Prompt for VS" (runs vcvars64,
#      which sets PATH/INCLUDE/LIB/LIBPATH for cl and link).
#   2. From THAT prompt, start MSYS2 inheriting the environment:
#         set MSYS2_PATH_TYPE=inherit
#         C:\msys64\msys2_shell.cmd -mingw64 -use-full-path -here
#   3. cd to an empty BUILD WORKSPACE directory and run this script
#      from there (it may live anywhere — a repo checkout, a copy, a
#      curl); all sources and the build land in the workspace.
#
# Module toggles (env or edit below). Each toggle names a MODULE; the
# libraries a module needs are derived, so any combination works:
#   WITH_ZSTD=1          the zstd module pair (the default).
#   WITH_BROTLI=1        the standalone ngx_brotli module.
#   WITH_COMPRESSION=1   the unified nginx-compression module
#                        (compression/ in the zstd-module checkout).
#   WITH_HEADERS_MORE=1  headers-more.
# Library builds follow the modules: BUILDLIB_ZSTD / BUILDLIB_BROTLI
# default to 1 when any enabled module can use the library. The
# standalone modules REQUIRE theirs (their configure fails without it),
# so those defaults are refused when overridden; the unified module
# treats a missing library as a build shape (that backend is simply
# absent), so BUILDLIB_*=0 is a legal way to build it without one.
# A standalone module and the unified one may be built together; the
# unified module's static filter anchor orders it first so it gets the
# first shot at every response. Examples:
#   ./ci/tools/build-windows.sh                              (the default)
#   WITH_ZSTD=1 WITH_BROTLI=1 ./ci/tools/build-windows.sh
#   WITH_COMPRESSION=1 REPO_ZSTD_MODULE=<fork> REF_ZSTD_MODULE=<commit> \
#       ./ci/tools/build-windows.sh
#     (until compression/ lands on master, WITH_COMPRESSION needs a ref
#     that carries it; the script checks and says so)
#
# Every downloaded tarball is pinned by version and SHA-256 in
# ci/tools/windows-pins.sh, the one source of those pins (a bump edits
# that file and nothing else). Every pin is verified up front, before
# any compile (verify() prints the actual digest on a mismatch, so a
# stale pin is a copy-paste away from fixed).
#
# KNOW WHAT YOU ARE BUILDING — Windows nginx caveats (nginx.org's own
# position; this script does not change them):
#   * Effectively single-worker: the win32 event core services
#     connections from one worker via select() (hence the FD_SETSIZE
#     define below). This build is for a LOCAL DEV BOX, not production
#     traffic.
#   * No HTTP/3: deliberately absent from the configure list, not an
#     oversight — nginx's QUIC stack needs UDP capabilities the win32
#     event core does not provide.
#
# Running the result as a Windows service (optional): nginx.exe has no
# service mode of its own; a thin wrapper such as shawl
# (https://github.com/mtkennerly/shawl) works well. From an ADMIN shell:
#     shawl.exe add --name "Local Nginx" --no-log-cmd \
#         --cwd C:/path/to/nginx-1.x.x -- nginx.exe -c conf/nginx.conf
#     sc config "Local Nginx" start=auto
#     sc start  "Local Nginx"
# and to remove:  sc stop "Local Nginx" & sc delete "Local Nginx"

set -euo pipefail

### module toggles #####################################################
WITH_ZSTD=${WITH_ZSTD:-1}
WITH_BROTLI=${WITH_BROTLI:-0}
WITH_COMPRESSION=${WITH_COMPRESSION:-0}
WITH_HEADERS_MORE=${WITH_HEADERS_MORE:-1}

for t in WITH_COMPRESSION WITH_ZSTD WITH_BROTLI WITH_HEADERS_MORE; do
    case "${!t}" in
        0 | 1) ;;
        *)
            echo "ERROR: $t must be 0 or 1 (got '${!t}')" >&2
            exit 1
            ;;
    esac
done

# Library builds default to "some enabled module can use it"; override
# to 0 only for the unified module, whose backends are optional.
BUILDLIB_ZSTD=${BUILDLIB_ZSTD:-$((WITH_ZSTD || WITH_COMPRESSION))}
BUILDLIB_BROTLI=${BUILDLIB_BROTLI:-$((WITH_BROTLI || WITH_COMPRESSION))}

for t in BUILDLIB_ZSTD BUILDLIB_BROTLI; do
    case "${!t}" in
        0 | 1) ;;
        *)
            echo "ERROR: $t must be 0 or 1 (got '${!t}')" >&2
            exit 1
            ;;
    esac
done
if [ "$WITH_ZSTD" = 1 ] && [ "$BUILDLIB_ZSTD" = 0 ]; then
    echo "ERROR: the standalone zstd module pair requires libzstd (its" \
        "auto/zstd probe is fatal); BUILDLIB_ZSTD=0 only fits WITH_ZSTD=0" >&2
    exit 1
fi
if [ "$WITH_BROTLI" = 1 ] && [ "$BUILDLIB_BROTLI" = 0 ]; then
    echo "ERROR: the standalone ngx_brotli module requires libbrotli (its" \
        "config errors without it); BUILDLIB_BROTLI=0 only fits WITH_BROTLI=0" >&2
    exit 1
fi

if [ "$WITH_COMPRESSION" = 1 ] && { [ "$WITH_ZSTD" = 1 ] || [ "$WITH_BROTLI" = 1 ]; }; then
    echo "NOTE: building the unified module beside a standalone one; the" \
        "unified module runs first in the body-filter chain and" \
        "supersedes it (static filter-anchor policy)." >&2
fi

### version + SHA-256 pins #############################################
# Sourced from ci/tools/windows-pins.sh beside this script -- THE one
# place the pins live (a bump edits that file and nothing else). A hard
# dependency with a loud guard and no inline defaults: a fallback default
# would silently build the wrong version, which is worse than stopping.
# PINS_FILE= points at a different file to try a bump without editing
# the tracked one.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PINS_FILE=${PINS_FILE:-$SCRIPT_DIR/windows-pins.sh}
[ -f "$PINS_FILE" ] || {
    echo "ERROR: $PINS_FILE missing -- windows-pins.sh must sit beside this" \
        "script (or set PINS_FILE=)" >&2
    exit 1
}
# shellcheck source=ci/tools/windows-pins.sh
. "$PINS_FILE"
for v in VER_NGINX SHA_NGINX VER_PCRE2 SHA_PCRE2 VER_OPENSSL SHA_OPENSSL \
    VER_ZLIB SHA_ZLIB VER_NASM SHA_NASM VER_ZSTD SHA_ZSTD; do
    [ -n "${!v:-}" ] || {
        echo "ERROR: $PINS_FILE does not set $v" >&2
        exit 1
    }
done

# OpenSSL build options. nginx's own auto/lib/openssl/makefile.msvc
# adds "no-shared no-threads" itself; the pre-build below must configure
# with the same effective set so the library nginx links is the one it
# would have built (duplicates are harmless to OpenSSL's Configure).
OPENSSL_OPT="no-shared no-module no-threads"

# Module refs — pinned by full commit id like everything else, bumped
# deliberately (a floating branch here once handed a tester a module
# checkout without the MSVC support and a mysterious configure
# failure). Overridable so a fix branch can be tested before it lands:
#   REPO_ZSTD_MODULE=<fork url> REF_ZSTD_MODULE=<branch> (fresh clone
#   required when switching repos — the existing clone's origin wins).
#
# The zstd module default resolves to the CURRENT CHECKOUT (this script's
# own repo, HEAD), not a fixed historical commit (audit A30-F3: a static
# commit pin here drifted ~154 commits behind and silently built a stale
# module even though the README presents this script alongside current
# behaviour). REPO_ZSTD_MODULE/REF_ZSTD_MODULE stay fully overridable for
# the deliberate self-pin / fork-testing use case documented above.
#
# WITH_COMPRESSION=1 needs a ref whose tree carries compression/; until
# that lands on master, point the override at a branch that has it. The
# clone step checks and says so rather than failing inside configure.
_zstd_module_repo_root() {
    # SCRIPT_DIR is not assigned yet this early — derive it locally so this
    # default resolves regardless of where DIR_PROJECT/SCRIPT_DIR end up.
    local script_dir
    script_dir=$(cd "$(dirname "$0")" && pwd)
    git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null || true
}
if [ -z "${REPO_ZSTD_MODULE:-}" ] || [ -z "${REF_ZSTD_MODULE:-}" ]; then
    _default_zstd_root="$(_zstd_module_repo_root)"
    if [ -n "$_default_zstd_root" ] && [ -d "$_default_zstd_root/ci/tools" ]; then
        REPO_ZSTD_MODULE=${REPO_ZSTD_MODULE:-$_default_zstd_root}
        REF_ZSTD_MODULE=${REF_ZSTD_MODULE:-$(git -C "$_default_zstd_root" rev-parse HEAD)}
    else
        # Not running from inside a nginx-zstd-module checkout (e.g. a
        # standalone copy of this script) — fall back to the last commit
        # verified to build cleanly under this script, same as before.
        REPO_ZSTD_MODULE=${REPO_ZSTD_MODULE:-https://github.com/myguard-labs/nginx-zstd-module.git}
        REF_ZSTD_MODULE=${REF_ZSTD_MODULE:-37cf9ac6b58284ae2da95620f4905930d1277b54}
    fi
fi
REPO_BROTLI=${REPO_BROTLI:-https://github.com/mreiden/ngx_brotli.git}
REF_BROTLI=${REF_BROTLI:-c0b96d6254f32ff36fbfff96e3995504a3bf5ef3}
REPO_HEADERS_MORE=${REPO_HEADERS_MORE:-https://github.com/openresty/headers-more-nginx-module.git}
REF_HEADERS_MORE=${REF_HEADERS_MORE:-53b0d98d1d57033b90491fd6a3b485ca536edfa7}

########################################################################

# The build workspace is wherever the script is RUN from, not where it
# lives — so a repo checkout can drive a build elsewhere. Patches for
# the cloned modules are applied from the script's own patches/
# directory (bundled: the headers-more MSVC include-order fix, without
# which that module cannot build under the win32 precompiled header)
# and additionally from $DIR_PROJECT/patches/<clone-dir>/*.patch for
# local ones. A standalone copy of this script needs the bundled
# patches directory alongside it (or WITH_HEADERS_MORE=0).
DIR_PROJECT=$(pwd)
DIR_NGINX="$DIR_PROJECT/nginx-$VER_NGINX"

# Every pinned tarball is downloaded into dl/ and verified there (the
# cache survives deleting the nginx tree); extraction happens later at
# each use site. verify() prints both digests on a mismatch, so a stale
# pin is a copy-paste away from fixed and a bad download is
# distinguishable from it.
DIR_DL="$DIR_PROJECT/dl"

verify() { # url sha
    local url=$1 sha=$2 file="$DIR_DL/${1##*/}" src actual
    # A download lands beside the cache slot and is promoted into it only
    # once its digest matches, so neither an interrupted download nor a
    # completed wrong one (a mirror serving other bytes) is ever something
    # a later run trusts. A mismatching download stays as .part for a
    # look; the next run downloads over it.
    if [ -f "$file" ]; then
        src=$file
    else
        src=$file.part
        curl -fsSL -o "$src" "$url"
    fi
    actual=$(sha256sum "$src" | cut -d' ' -f1)
    if [ "$actual" != "$sha" ]; then
        echo "ERROR: sha256 mismatch for ${file##*/}" >&2
        echo "  expected  $sha" >&2
        echo "  actual    $actual" >&2
        echo "  source    $url" >&2
        if [ "$src" = "$file" ]; then
            echo "  (stale pin? update SHA_*; bad cached file? delete $file and rerun)" >&2
        else
            echo "  (stale pin? update SHA_*; bad download? not cached, kept as ${src##*/})" >&2
        fi
        exit 1
    fi
    [ "$src" = "$file" ] || mv "$src" "$file"
    echo "verified ${file##*/}"
}

# Extract a verified tarball into the current directory. Extra args
# narrow the extraction to specific archive members.
extract() { # tarball-name [paths...]
    local file="$DIR_DL/$1"
    shift
    tar xzf "$file" "$@"
}

# Extract into DIR unless a completed extraction is already there. A killed
# or failed tar leaves a partial tree behind, and a directory-exists guard
# would then skip re-extraction and fail later on missing files. The
# marker is written only after tar exits clean, and a tree without one is
# extracted again IN PLACE: tar rewrites every selected member from the
# archive, so the result is complete whatever was there, while what is
# not an archive member (objs/, the OpenSSL pre-build, the module clones
# under objs/lib) is kept. A tree from before the marker existed costs one
# re-extraction, not a rebuild.
extract_complete() { # dir tarball-name [paths...]
    local archive=$2 marker="$1/.extracted"
    shift 2
    if [ ! -f "$marker" ]; then
        extract "$archive" "$@"
        : >"$marker"
    fi
}

# Clone at a pinned ref, applying the script's bundled patches and any
# workspace-local ones from patches/<name>/*.patch, idempotently.
# Submodules are synced AFTER the switch so nested pins (e.g.
# ngx_brotli/deps/brotli) follow the checked-out module commit, not
# whatever the clone's default branch pinned.
clone_module() { # dest repo ref
    local dest=$1 repo=$2 ref=$3 p d
    [ -d "$dest" ] || git clone --recurse-submodules "$repo" "$dest"
    git -C "$dest" fetch --quiet origin 2>/dev/null || true
    git -C "$dest" switch --detach "$ref" 2>/dev/null \
        || git -C "$dest" switch "$ref"
    git -C "$dest" submodule sync --recursive --quiet 2>/dev/null || true
    git -C "$dest" submodule update --init --recursive
    for d in "$SCRIPT_DIR/patches/$dest" "$DIR_PROJECT/patches/$dest"; do
        for p in "$d"/*.patch; do
            [ -f "$p" ] || continue
            if git -C "$dest" apply --check "$p" 2>/dev/null; then
                git -C "$dest" apply "$p"
            elif ! git -C "$dest" apply --reverse --check "$p" 2>/dev/null; then
                echo "ERROR: $p neither applies nor is already applied" >&2
                exit 1
            fi
        done
    done
}

### toolchain sanity ###################################################
command -v cl >/dev/null 2>&1 || {
    echo "ERROR: cl not on PATH — launch from the VS Native Tools" \
        "prompt with MSYS2_PATH_TYPE=inherit (see header)" >&2
    exit 1
}

# OpenSSL needs a NATIVE perl (Strawberry); MSYS perl reports msys as
# its OS and emits paths cl cannot consume.
PERL_BIN=
for d in "${STRAWBERRY_PERL:-}" /c/Strawberry/perl/bin /c/strawberry/perl/bin; do
    [ -n "$d" ] && [ -x "$d/perl.exe" ] && {
        PERL_BIN=$d
        break
    }
done
if [ -z "$PERL_BIN" ] && command -v perl >/dev/null 2>&1 \
    && [ "$(perl -e 'print $^O')" = "MSWin32" ]; then
    PERL_BIN=$(dirname "$(command -v perl)")
fi
[ -n "$PERL_BIN" ] || {
    echo "ERROR: no native (Strawberry) perl found; install it or set" \
        "STRAWBERRY_PERL=/c/path/to/perl/bin" >&2
    exit 1
}

# nasm first for OpenSSL (built under sources below; the entry is
# harmless until then); native perl next; then cl's own directory ahead
# of MSYS /usr/bin so MSVC's link.exe shadows coreutils' link (the
# classic silent breaker of OpenSSL/nginx Windows builds).
PATH="$DIR_PROJECT/nasm-$VER_NASM:$PERL_BIN:$(dirname "$(command -v cl)"):$PATH"

### downloads: every pin verified before any compile ##################
# A stale pin or a bad mirror fails here, in seconds, instead of after
# the OpenSSL build. Cached tarballs are re-verified (a few MB of
# sha256 -- negligible).
mkdir -p "$DIR_DL"
verify "https://nginx.org/download/nginx-$VER_NGINX.tar.gz" "$SHA_NGINX"
verify "https://www.nasm.us/pub/nasm/releasebuilds/$VER_NASM/nasm-$VER_NASM.tar.gz" "$SHA_NASM"
verify "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$VER_PCRE2/pcre2-$VER_PCRE2.tar.gz" "$SHA_PCRE2"
verify "https://github.com/openssl/openssl/releases/download/openssl-$VER_OPENSSL/openssl-$VER_OPENSSL.tar.gz" "$SHA_OPENSSL"
verify "https://zlib.net/zlib-$VER_ZLIB.tar.gz" "$SHA_ZLIB"
[ "$BUILDLIB_ZSTD" = 1 ] \
    && verify "https://github.com/facebook/zstd/releases/download/v$VER_ZSTD/zstd-$VER_ZSTD.tar.gz" "$SHA_ZSTD"

### sources: extract and clone, still before any compile ##############
extract_complete "nginx-$VER_NGINX" "nginx-$VER_NGINX.tar.gz"
mkdir -p "$DIR_NGINX/objs/lib"

# Module clones next, so a bad ref (or a ref without compression/) also
# fails before the first library build. ngx_brotli is cloned whenever
# libbrotli is built, module or not: the library source is its
# deps/brotli submodule.
cd "$DIR_NGINX/objs/lib"

[ "$WITH_HEADERS_MORE" = 1 ] \
    && clone_module headers-more-nginx-module "$REPO_HEADERS_MORE" "$REF_HEADERS_MORE"
if [ "$WITH_BROTLI" = 1 ] || [ "$BUILDLIB_BROTLI" = 1 ]; then
    clone_module ngx_brotli "$REPO_BROTLI" "$REF_BROTLI"
fi
if [ "$WITH_ZSTD" = 1 ] || [ "$WITH_COMPRESSION" = 1 ]; then
    echo "nginx-zstd-module: repo=$REPO_ZSTD_MODULE ref=$REF_ZSTD_MODULE" >&2
    # clone_module runs a real git-clone even when REPO_ZSTD_MODULE resolved
    # to a local checkout path (the default above) -- that only pulls
    # COMMITTED history, so uncommitted working-tree edits in that checkout
    # are not part of this build. Commit (even to a throwaway branch) before
    # building to include local changes.
    clone_module nginx-zstd-module "$REPO_ZSTD_MODULE" "$REF_ZSTD_MODULE"
    if [ "$WITH_COMPRESSION" = 1 ] && [ ! -f nginx-zstd-module/compression/config ]; then
        echo "ERROR: REF_ZSTD_MODULE=$REF_ZSTD_MODULE has no compression/ --" \
            "WITH_COMPRESSION=1 needs a ref whose tree carries it (see the" \
            "header); set REPO_ZSTD_MODULE/REF_ZSTD_MODULE accordingly" >&2
        exit 1
    fi
fi

extract_complete "pcre2-$VER_PCRE2" "pcre2-$VER_PCRE2.tar.gz"
extract_complete "openssl-$VER_OPENSSL" "openssl-$VER_OPENSSL.tar.gz"
extract_complete "zlib-$VER_ZLIB" "zlib-$VER_ZLIB.tar.gz"

cd "$DIR_PROJECT"

### library builds #####################################################
# nasm for OpenSSL's assembly (fast crypto; drop by adding no-asm to
# OPENSSL_OPT and deleting this block). Built first: the OpenSSL
# pre-build below needs it on PATH.
if [ ! -x "nasm-$VER_NASM/nasm" ] && [ ! -x "nasm-$VER_NASM/nasm.exe" ]; then
    extract_complete "nasm-$VER_NASM" "nasm-$VER_NASM.tar.gz"
    (cd "nasm-$VER_NASM" && ./configure >/dev/null && make -j"$(nproc)")
fi

# libzstd, built static with the static CRT (nginx's cl build is /MT;
# CMake's default /MD would conflict at link). Extract only lib/ and
# build/: the tarball's tests/ tree contains symlinks MSYS tar cannot
# create, which would abort the whole extraction — and this build
# needs neither tests nor programs. Extraction is marker-guarded like
# every other tree; the build is guarded on its archive, so an aborted
# cmake self-heals too.
if [ "$BUILDLIB_ZSTD" = 1 ]; then
    extract_complete "zstd-$VER_ZSTD" "zstd-$VER_ZSTD.tar.gz" "zstd-$VER_ZSTD/lib" "zstd-$VER_ZSTD/build"
    if [ ! -f "zstd-$VER_ZSTD/out/lib/zstd_static.lib" ]; then
        cmake -B "zstd-$VER_ZSTD/out" -S "zstd-$VER_ZSTD/build/cmake" \
            -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release \
            -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF \
            -DZSTD_BUILD_TESTS=OFF -DZSTD_USE_STATIC_RUNTIME=ON
        cmake --build "zstd-$VER_ZSTD/out"
    fi
fi

# libbrotli from the ngx_brotli clone's submodule. Static, static CRT,
# same rule as libzstd. Guarded on the archive, so an aborted cmake
# (which leaves out/ present but empty) self-heals.
if [ "$BUILDLIB_BROTLI" = 1 ] && [ ! -f "$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli/out/brotlienc.lib" ]; then
    cmake -B "$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli/out" \
        -S "$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli" \
        -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
        -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
    cmake --build "$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli/out"
fi

cd "$DIR_NGINX"

### OpenSSL, pre-built ##################################################
# nginx would build OpenSSL itself during nmake, but only AFTER
# configure -- too late for the compression module's EVP probe, which
# then settles for portable SHA-256. Building it first, with the exact
# Configure line nginx's makefile.msvc uses (same prefix, same options),
# lets the probe find the installed headers and lets nmake skip its own
# rule (see the touch before nmake). Guarded on a completion marker written
# only after install_sw succeeds: OpenSSL installs headers before libraries,
# so an installed evp.h alone cannot prove an interrupted install completed.
#
# CRT: no-shared makes OpenSSL compile its static libraries with /MT /Zl
# (Configurations/10-main.conf, lib_cflags; the generated makefile's
# LIB_CFLAGS shows it), the same static CRT as nginx's cl build
# (auto/cc/msvc, LIBC="-MT"). enable-static-vcruntime is consulted only
# for shared builds and would change nothing here.
OPENSSL_INSTALL_MARKER="objs/lib/openssl-$VER_OPENSSL/openssl/.install-complete"
if [ ! -f "$OPENSSL_INSTALL_MARKER" ]; then
    # shellcheck disable=SC2086
    (cd "objs/lib/openssl-$VER_OPENSSL" \
        && perl Configure VC-WIN64A $OPENSSL_OPT \
            --prefix="$(cygpath -m "$PWD")/openssl" \
            --openssldir="$(cygpath -m "$PWD")/openssl/ssl" \
        && nmake && nmake install_sw)
    : >"$OPENSSL_INSTALL_MARKER"
fi

### configure ##########################################################
# Groups: paths/core; the modules the nginx.org Windows binary ships;
# the optional third-party modules per the toggles.
#
# --with-http_v3_module is deliberately NOT here: nginx's QUIC needs
# UDP support the win32 event core lacks (see header caveats).
configure_args=(
    --with-cc=cl
    --prefix=
    --conf-path=conf/nginx.conf
    --pid-path=logs/nginx.pid
    --http-log-path=logs/access.log
    --error-log-path=logs/error.log
    --sbin-path=nginx.exe
    --http-client-body-temp-path=temp/client_body_temp
    --http-proxy-temp-path=temp/proxy_temp
    --http-fastcgi-temp-path=temp/fastcgi_temp
    --http-scgi-temp-path=temp/scgi_temp
    --http-uwsgi-temp-path=temp/uwsgi_temp
    --with-cc-opt=-DFD_SETSIZE=1024
    # nginx.org's Windows binary ships with debug logging compiled in;
    # it costs a few hundred kB — the real size lever is the -opt:ref
    # dead-code elimination added below.
    --with-debug
    --with-pcre="objs/lib/pcre2-$VER_PCRE2"
    --with-zlib="objs/lib/zlib-$VER_ZLIB"
    --with-openssl="objs/lib/openssl-$VER_OPENSSL"
    --with-openssl-opt="$OPENSSL_OPT"
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_auth_request_module

    --with-http_addition_module
    --with-http_dav_module
    --with-http_flv_module
    --with-http_gunzip_module
    --with-http_gzip_static_module
    --with-http_mp4_module
    --with-http_random_index_module
    --with-http_realip_module
    --with-http_secure_link_module
    --with-http_slice_module
    --with-http_sub_module
    --with-http_stub_status_module
    --with-mail
    --with-mail_ssl_module
    --with-stream
    --with-stream_ssl_module
)

# Library locations for the module configs. Both the standalone zstd
# pair and the unified module read ZSTD_INC/ZSTD_LIB; the unified module
# also reads BROTLI_INC/BROTLI_LIB (ngx_brotli finds its own submodule).
# An explicit path is a promise to those configs -- set only when the
# library was actually built. A backend switched off is told so
# explicitly rather than left to a failing auto-probe.
if [ "$BUILDLIB_ZSTD" = 1 ]; then
    export ZSTD_INC="$DIR_PROJECT/zstd-$VER_ZSTD/lib"
    export ZSTD_LIB="$DIR_PROJECT/zstd-$VER_ZSTD/out/lib"
fi
if [ "$BUILDLIB_BROTLI" = 1 ]; then
    export BROTLI_INC="$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli/c/include"
    export BROTLI_LIB="$DIR_NGINX/objs/lib/ngx_brotli/deps/brotli/out"
fi
if [ "$WITH_COMPRESSION" = 1 ]; then
    [ "$BUILDLIB_ZSTD" = 1 ] || export NGX_HTTP_COMPRESSION_NO_ZSTD=1
    [ "$BUILDLIB_BROTLI" = 1 ] || export NGX_HTTP_COMPRESSION_NO_BROTLI=1
fi

[ "$WITH_HEADERS_MORE" = 1 ] \
    && configure_args+=(--add-module=objs/lib/headers-more-nginx-module)
[ "$WITH_ZSTD" = 1 ] \
    && configure_args+=(--add-module=objs/lib/nginx-zstd-module)
[ "$WITH_BROTLI" = 1 ] \
    && configure_args+=(--add-module=objs/lib/ngx_brotli)
[ "$WITH_COMPRESSION" = 1 ] \
    && configure_args+=(--add-module=objs/lib/nginx-zstd-module/compression)

./configure "${configure_args[@]}"

# nginx's msvc makefile compiles with -WX (warnings as errors), which
# third-party module trees do not survive under -W4; strip it. Also let
# the linker drop unreferenced sections despite /DEBUG.
sed -i 's/ -WX//; s/-link -verbose:lib -debug/-link -verbose:lib -debug -opt:ref -opt:icf/' objs/Makefile
grep -q -- '-opt:ref' objs/Makefile || echo "WARN: link-opt sed did not match"

# The generated rule is `openssl/include/openssl/ssl.h: objs/Makefile`,
# so the pre-built header must be newer than the FINAL Makefile -- this
# must stay the last thing before nmake, after every edit of
# objs/Makefile above, or nmake rebuilds OpenSSL on every run.
touch "objs/lib/openssl-$VER_OPENSSL/openssl/include/openssl/ssl.h"

nmake

echo
echo "== built: $DIR_NGINX/objs/nginx.exe"
./objs/nginx.exe -V
