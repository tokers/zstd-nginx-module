#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
source_script=$root/ci/tools/build-windows.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

block=$(awk '
    /^OPENSSL_INSTALL_MARKER=/ { copy = 1 }
    copy { print }
    copy && /^fi$/ { exit }
' "$source_script")
grep -q 'OPENSSL_INSTALL_MARKER=' <<<"$block"
grep -q 'nmake install_sw' <<<"$block"

VER_OPENSSL=fixture
OPENSSL_OPT=no-shared
export VER_OPENSSL OPENSSL_OPT
tree=$tmp/objs/lib/openssl-$VER_OPENSSL
mkdir -p "$tree"
log=$tmp/nmake.log
export log

perl() { :; }
cygpath() { printf '%s\n' "$2"; }
nmake() {
    printf '%s\n' "${1:-build}" >>"$log"
    if [ "${1:-}" = install_sw ]; then
        mkdir -p "$PWD/openssl/include/openssl"
        : >"$PWD/openssl/include/openssl/evp.h"
        if [ "${FAIL_INSTALL:-0}" = 1 ]; then
            return 1
        fi
        mkdir -p "$PWD/openssl/lib"
        : >"$PWD/openssl/lib/libssl.lib"
        : >"$PWD/openssl/lib/libcrypto.lib"
    fi
}
export -f perl cygpath nmake

cd "$tmp"
FAIL_INSTALL=1
export FAIL_INSTALL
set +e
(
    set -e
    eval "$block"
)
status=$?
set -e
if [ "$status" -eq 0 ]; then
    echo 'interrupted OpenSSL install unexpectedly succeeded' >&2
    exit 1
fi
marker=$tree/openssl/.install-complete
[ -f "$tree/openssl/include/openssl/evp.h" ]
[ ! -e "$marker" ]
[ "$(grep -c '^install_sw$' "$log")" -eq 1 ]

FAIL_INSTALL=0
export FAIL_INSTALL
eval "$block"
[ -f "$marker" ]
[ -f "$tree/openssl/lib/libssl.lib" ]
[ -f "$tree/openssl/lib/libcrypto.lib" ]
[ "$(grep -c '^install_sw$' "$log")" -eq 2 ]

# A completed install is restartable and must not invoke nmake again.
eval "$block"
[ "$(grep -c '^install_sw$' "$log")" -eq 2 ]

# Mutation control: the old evp.h guard would accept the partial first
# install and fail to create the completion marker on retry.
unlink "$marker"
mutant=${block/\[ ! -f \"\$OPENSSL_INSTALL_MARKER\" \]/[ ! -f \"objs\/lib\/openssl-\$VER_OPENSSL\/openssl\/include\/openssl\/evp.h\" ]}
eval "$mutant"
if [ -e "$marker" ]; then
    echo 'evp.h-guard mutation unexpectedly repaired the partial install' >&2
    exit 1
fi

echo 'Windows OpenSSL interrupted-install recovery: PASS'
