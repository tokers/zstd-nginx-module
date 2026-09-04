#!/bin/bash
# Unit fixture for ngx_http_zstd_static_probe_frame()
# (src/ngx_http_zstd_frame_probe.h, the authoritative copy -- #270).
set -euo pipefail

cd "$(dirname "$0")/../.."

SRC="src/ngx_http_zstd_frame_probe.h"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-static-probe-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

# The TU includes the shipped header directly (#270) -- no extraction
# step. These markers keep the anti-drift property the extraction
# carried: the header must exist and still hold the probe's load-
# bearing branches, or this gate names the real problem instead of a
# confusing compile error.
for marker in \
	'ngx_http_zstd_static_probe_frame(' \
	'NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED' \
	'fhd & 0x08' \
	'NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG'; do
	if ! grep -q "$marker" "$SRC"; then
		echo "FAIL: $SRC lacks marker: $marker" >&2
		exit 1
	fi
done

"$CC" -std=gnu99 -Wall -Wextra -Werror -O1 \
	-I ci/tools \
	-o "$OUT/test_static_probe_unit" \
	ci/tools/test_static_probe_unit.c

"$OUT/test_static_probe_unit"

# The production header is also consumed by C89-era/MSVC-style builds.
# Compile the same behavioral fixture in strict C89 mode so declarations
# introduced inside the byte-decoding fallback cannot regress portability.
"$CC" -std=c89 -pedantic-errors -Wall -Wextra -Werror -O1 \
	-Dngx_inline=__inline -DTEST_BIG_ENDIAN_FALLBACK -I ci/tools \
	-o "$OUT/test_static_probe_unit_c89" \
	ci/tools/test_static_probe_unit.c

"$OUT/test_static_probe_unit_c89"
