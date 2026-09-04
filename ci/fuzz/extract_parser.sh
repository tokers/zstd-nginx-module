#!/usr/bin/env bash
#
# Slice the verbatim bodies of the Accept-Encoding parser out of the
# shipped ../../src/ngx_http_zstd_common.h into generated_parser.inc. That
# is ngx_http_zstd_eval_qvalue() (the qvalue evaluator), its
# ngx_http_zstd_parse_q_fraction() digit-walk helper, and its caller
# ngx_http_zstd_coding_weight() and its chain/request-field callers, plus
# ngx_http_zstd_accept_encoding(), in definition order so the .inc compiles
# standalone.
#
# This keeps the fuzz target locked to production code: there is no
# hand-maintained copy of the parser. If the function signature or body
# changes upstream, the next fuzz build picks it up automatically. If a
# function can no longer be found, we fail loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEADER="$FUZZ_DIR/../../src/ngx_http_zstd_common.h"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$HEADER" ]; then
    echo "✗ cannot find $HEADER" >&2
    exit 1
fi

# Extract each function from its return-type line through the matching
# closing brace at column 0 (nginx style: definitions close with a bare
# `}` in col 1). The functions have two distinct return-type lines
# (`static u_char *` for the skip_quoted helper, `static ngx_int_t` for the
# rest, either optionally carrying `ngx_inline`), so match on the following
# definition line. ngx_inline is accepted because
# ngx_http_zstd_accept_encoding() carries it: no module TU calls that
# function any more (the request path evaluates the complete request field via
# ngx_http_zstd_request_coding_weight()), so a plain `static` would trip
# -Werror=unused-function in both TUs that include the header. ci/fuzz/
# ngx_shim.h defines ngx_inline for the sliced build. Capture them in
# source order (skip_quoted, then parse_q_fraction, then eval_qvalue --
# which calls parse_q_fraction, so it must precede eval_qvalue in the
# generated .inc -- then accept_encoding) so the generated .inc compiles
# without forward declarations.
# The leading sub() strips a CR so extraction also works from a Windows
# checkout smudged to CRLF (core.autocrlf=true): the `$0 == "}"`
# terminator and the anchored regexes below otherwise never match and
# the build fails with the "header layout changed?" error misleadingly.
awk '
    { sub(/\r$/, "") }
    /^static (ngx_inline )?(ngx_int_t|u_char \*)$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_zstd_(skip_quoted|parse_q_fraction|eval_qvalue|coding_weight_ex|coding_weight|chain_coding_weight|request_coding_weight|accept_encoding|accepts)\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$HEADER" >"$OUT"

if ! grep -q 'ngx_http_zstd_chain_coding_weight' "$OUT" \
    || ! grep -q 'ngx_http_zstd_request_coding_weight' "$OUT" \
    || ! grep -q 'ngx_http_zstd_skip_quoted' "$OUT" \
    || ! grep -q 'ngx_http_zstd_parse_q_fraction' "$OUT" \
    || ! grep -q 'ngx_http_zstd_eval_qvalue' "$OUT" \
    || ! grep -Eq '^ngx_http_zstd_coding_weight_ex\(' "$OUT" \
    || ! grep -Eq '^ngx_http_zstd_coding_weight\(' "$OUT" \
    || ! grep -q 'ngx_http_zstd_accept_encoding' "$OUT" \
    || ! grep -q 'ngx_http_zstd_accepts' "$OUT" \
    || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract the Accept-Encoding parser from $HEADER" >&2
    echo "  (header layout changed? update extract_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l <"$OUT")
echo "✓ extracted ngx_http_zstd_skip_quoted() + ngx_http_zstd_parse_q_fraction()" \
    "+ ngx_http_zstd_eval_qvalue() + ngx_http_zstd_coding_weight_ex()" \
    "+ ngx_http_zstd_coding_weight()" \
    "+ ngx_http_zstd_chain_coding_weight()" \
    "+ ngx_http_zstd_request_coding_weight() + ngx_http_zstd_accept_encoding()" \
    "+ ngx_http_zstd_accepts() — $LINES lines -> $OUT"
