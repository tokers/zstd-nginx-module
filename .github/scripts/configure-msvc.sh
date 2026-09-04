#!/bin/bash
# Configure the Windows/MSVC CI build after vcvars64.bat has initialized the
# parent cmd process. Kept in a real bash file because a GitHub custom `cmd`
# shell wraps inline run blocks in a .cmd file, which bash cannot parse.

set -euo pipefail

module_dir=$(cygpath -m "$GITHUB_WORKSPACE")
zstd_root=$(cygpath -m \
    "$VCPKG_INSTALLATION_ROOT/installed/x64-windows-static")

ZSTD_INC="$zstd_root/include" ZSTD_LIB="$zstd_root/lib" \
    ./configure \
    --crossbuild=win32 \
    --with-cc=cl \
    --with-cc-opt='-MT -DFD_SETSIZE=1024' \
    --with-pcre="$module_dir/pcre2-$PCRE2_VERSION" \
    --with-zlib="$module_dir/zlib-$ZLIB_VERSION" \
    --add-module="$module_dir"
