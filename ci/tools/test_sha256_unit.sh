#!/bin/bash
# Unit fixture for ngx_http_zstd_sha256.h (issue #100 item 3): the
# portable implementation against NIST vectors, and the EVP-to-portable
# fallback with an injectable fake EVP_Digest. Self-contained — shim
# headers in ci/tools/sha256-unit/ stand in for the ngx types and for
# <openssl/evp.h>, so this needs a C compiler and nothing else.
set -euo pipefail

# ci/tools/ -> ci/ -> repo root: TWO levels since the ci/ move.
cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-sha256-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

"$CC" -Wall -Wextra -Werror -O2 -Ici/tools/sha256-unit \
    -o "$OUT/portable" ci/tools/test_sha256_unit.c
"$OUT/portable"

"$CC" -Wall -Wextra -Werror -O2 -Ici/tools/sha256-unit \
    -DNGX_HTTP_ZSTD_HAVE_LIBCRYPTO=1 \
    -o "$OUT/evp-fallback" ci/tools/test_sha256_unit.c
"$OUT/evp-fallback"

echo "OK: sha256 unit fixture (portable vectors + EVP failure injection)"
