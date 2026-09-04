#!/usr/bin/env bash
#
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Slice the verbatim body of ngx_http_zstd_dcz_decode_digest() out of the
# shipped ../../src/ngx_http_zstd_filter_module.c into
# generated_dcz.inc. Same approach as extract_parser.sh (see that file's
# header comment for the full rationale): the fuzz target stays locked to
# production code, no hand-maintained copy to drift.
#
# ngx_http_zstd_dcz_decode_digest() is a pure extract out of
# ngx_http_zstd_dcz_negotiate() -- the base64 length/prefix gate plus
# ngx_decode_base64() -- with zero dependency on ngx_http_request_t or
# config structures, which is what makes it fuzzable at all.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../../src/ngx_http_zstd_filter_module.c"
OUT="$FUZZ_DIR/generated_dcz.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# Same extraction shape as extract_parser.sh: match the two-line
# `static ngx_int_t` / function-name declaration style, then capture
# through the matching closing brace at column 0. The leading sub()
# strips a CR for CRLF checkouts, same reason as extract_parser.sh.
awk '
    { sub(/\r$/, "") }
    /^static (ngx_int_t|u_char \*)$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_zstd_dcz_decode_digest\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" >"$OUT"

if ! grep -q 'ngx_http_zstd_dcz_decode_digest' "$OUT" \
    || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract ngx_http_zstd_dcz_decode_digest() from $SRC" >&2
    echo "  (function signature/layout changed? update extract_dcz.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l <"$OUT")
echo "✓ extracted ngx_http_zstd_dcz_decode_digest() — $LINES lines -> $OUT"
