#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
source_script=$root/ci/tools/build-windows.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

toggle_block=$(awk '
    /^### module toggles/ { copy = 1 }
    /^# OpenSSL build options/ { exit }
    copy { print }
' "$source_script")
grep -q 'BUILDLIB_ZSTD=' <<<"$toggle_block"

pins=$tmp/pins.sh
for name in VER_NGINX SHA_NGINX VER_PCRE2 SHA_PCRE2 VER_OPENSSL SHA_OPENSSL \
    VER_ZLIB SHA_ZLIB VER_NASM SHA_NASM VER_ZSTD SHA_ZSTD; do
    printf '%s=x\n' "$name" >>"$pins"
done

resolve() {
    env -i PATH="$PATH" PINS_FILE="$pins" "$@" bash -c "
set -euo pipefail
$toggle_block
printf '%s %s %s %s %s %s\\n' \"\$WITH_ZSTD\" \"\$WITH_BROTLI\" \
  \"\$WITH_COMPRESSION\" \"\$WITH_HEADERS_MORE\" \
  \"\$BUILDLIB_ZSTD\" \"\$BUILDLIB_BROTLI\"
" "$source_script"
}

[ "$(resolve)" = '1 0 0 1 1 0' ]
[ "$(resolve WITH_ZSTD=0 WITH_COMPRESSION=1 WITH_HEADERS_MORE=0)" = \
    '0 0 1 0 1 1' ]
[ "$(resolve WITH_ZSTD=0 WITH_COMPRESSION=1 BUILDLIB_ZSTD=0 BUILDLIB_BROTLI=0)" = \
    '0 0 1 1 0 0' ]
if resolve WITH_ZSTD=1 BUILDLIB_ZSTD=0 >/dev/null 2>&1; then
    echo 'standalone zstd accepted BUILDLIB_ZSTD=0' >&2
    exit 1
fi
if resolve WITH_ZSTD=maybe >/dev/null 2>&1; then
    echo 'invalid module toggle was accepted' >&2
    exit 1
fi
if PINS_FILE="$tmp/missing" bash -c "set -euo pipefail; $toggle_block" \
    "$source_script" >/dev/null 2>&1; then
    echo 'missing pins file was accepted' >&2
    exit 1
fi

function_block=$(
    sed -n '/^verify() {/,/^}/p' "$source_script"
    sed -n '/^extract() {/,/^}/p' "$source_script"
    sed -n '/^extract_complete() {/,/^}/p' "$source_script"
)
grep -q '^extract_complete()' <<<"$function_block"
eval "$function_block"

DIR_DL=$tmp/dl
mkdir -p "$DIR_DL"
payload=$tmp/payload
printf 'verified payload\n' >"$payload"
payload_sha=$(sha256sum "$payload" | cut -d' ' -f1)
curl_mode=success

curl() {
    local output
    [ "$1" = -fsSL ]
    [ "$2" = -o ]
    output=$3
    if [ "$curl_mode" = wrong ]; then
        printf 'wrong payload\n' >"$output"
    else
        cp "$payload" "$output"
    fi
    [ "$curl_mode" != fail ]
}

export -f curl
export payload curl_mode
verify https://example.invalid/archive.tar.gz "$payload_sha" >/dev/null
[ -f "$DIR_DL/archive.tar.gz" ]
[ ! -e "$DIR_DL/archive.tar.gz.part" ]

# A completed download with the wrong digest remains a partial file. This
# catches promotion before verification; the following good retry recovers.
unlink "$DIR_DL/archive.tar.gz"
curl_mode=wrong
export curl_mode
set +e
(
    set -e
    verify https://example.invalid/archive.tar.gz "$payload_sha"
) \
    >/dev/null 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
    echo 'wrong payload unexpectedly verified' >&2
    exit 1
fi
[ -f "$DIR_DL/archive.tar.gz.part" ]
[ ! -e "$DIR_DL/archive.tar.gz" ]
curl_mode=success
export curl_mode
verify https://example.invalid/archive.tar.gz "$payload_sha" >/dev/null
[ -f "$DIR_DL/archive.tar.gz" ]
[ ! -e "$DIR_DL/archive.tar.gz.part" ]

# A failed transfer is never promoted; a retry overwrites the partial file.
unlink "$DIR_DL/archive.tar.gz"
curl_mode=fail
export curl_mode
set +e
(
    set -e
    verify https://example.invalid/archive.tar.gz "$payload_sha"
) \
    >/dev/null 2>&1
status=$?
set -e
if [ "$status" -eq 0 ]; then
    echo 'failed transfer unexpectedly verified' >&2
    exit 1
fi
[ -f "$DIR_DL/archive.tar.gz.part" ]
[ ! -e "$DIR_DL/archive.tar.gz" ]
curl_mode=success
export curl_mode
verify https://example.invalid/archive.tar.gz "$payload_sha" >/dev/null
[ -f "$DIR_DL/archive.tar.gz" ]
[ ! -e "$DIR_DL/archive.tar.gz.part" ]

# A partial extraction is repaired until the completion marker is present.
archive_root=$tmp/archive-root
mkdir -p "$archive_root/tree"
printf 'complete\n' >"$archive_root/tree/member"
tar -C "$archive_root" -czf "$DIR_DL/tree.tar.gz" tree
cd "$tmp"
mkdir -p tree
printf 'partial\n' >tree/member
printf 'preserve\n' >tree/nonmember
extract_complete tree tree.tar.gz
[ "$(cat tree/member)" = complete ]
[ "$(cat tree/nonmember)" = preserve ]
[ -f tree/.extracted ]
printf 'kept\n' >tree/member
extract_complete tree tree.tar.gz
[ "$(cat tree/member)" = kept ]
unlink tree/.extracted
extract_complete tree tree.tar.gz
[ "$(cat tree/member)" = complete ]
[ "$(cat tree/nonmember)" = preserve ]

echo 'Windows build inputs/cache/extraction policy: PASS'
