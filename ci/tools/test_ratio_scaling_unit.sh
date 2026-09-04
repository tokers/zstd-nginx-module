#!/bin/bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Unit fixture for ngx_http_zstd_ratio_parts() -- the overflow-safe
# $zstd_ratio integer/fractional scaling helper.
#
# The helper lives in src/ngx_http_zstd_ratio.h, THE authoritative copy,
# and the fixture includes that header directly (the frame-probe fixture's
# shape): there is no extracted or hand-copied duplicate here to drift from
# production. No nginx tree and no libzstd needed: pure C, self-contained.
set -euo pipefail

# ci/tools/ -> ci/ -> repo root.
cd "$(dirname "$0")/../.."

HDR="src/ngx_http_zstd_ratio.h"
SRC="src/ngx_http_zstd_filter_module.c"
CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-ratio-scaling-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

for marker in 'ngx_http_zstd_ratio_parts(uint64_t bytes_in' \
	'remainder <= UINT64_MAX / 10' 'ratio_int' 'ratio_frac'; do
	if ! grep -q "$marker" "$HDR"; then
		echo "FAIL: $HDR lacks marker: $marker" >&2
		exit 1
	fi
done

# Production must route $zstd_ratio through the header's helper. The
# assertion is bound to the variable HANDLER's body, not the whole file: a
# helper call anywhere else plus inline arithmetic back in the handler
# must still fail. The body is cut from the handler's column-0 signature
# to its closing brace.
if ! grep -Fq '#include "ngx_http_zstd_ratio.h"' "$SRC"; then
	echo "FAIL: $SRC no longer includes $HDR" >&2
	exit 1
fi

handler_body() {
	sed -n '/^ngx_http_zstd_ratio_variable(ngx_http_request_t \*r,$/,/^}/p' "$1"
}

assert_routes_through_helper() {
	local body
	body="$(handler_body "$1")"
	if [ -z "$body" ]; then
		echo "FAIL: could not cut ngx_http_zstd_ratio_variable() out of $1" >&2
		return 1
	fi
	if ! printf '%s\n' "$body" |
		grep -q 'ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out'; then
		echo "FAIL: \$zstd_ratio no longer calls ngx_http_zstd_ratio_parts()" >&2
		return 1
	fi
	# Any multiply or divide on the byte counters inside the handler is
	# inline ratio arithmetic; the helper call carries neither operator and
	# the bytes_out == 0 guard is a comparison.
	if printf '%s\n' "$body" | grep -Eq 'bytes_(in|out)[^;]*[*/]|[*/][^;]*bytes_(in|out)'; then
		echo "FAIL: \$zstd_ratio computes the ratio inline again" >&2
		return 1
	fi
}

assert_routes_through_helper "$SRC"

# Negative control: put the old arithmetic back into the handler (the
# helper call stays elsewhere in the file) and the check must go red.
sed 's|^    ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out, &ratio_int,$|    ratio_int = (ngx_uint_t) (ctx->bytes_in * 1000 / ctx->bytes_out / 1000);|' \
	"$SRC" >"$OUT/mutant.c"
if ! grep -q 'bytes_in \* 1000' "$OUT/mutant.c"; then
	echo "FAIL: mutant did not apply (handler call site moved?)" >&2
	exit 1
fi
if assert_routes_through_helper "$OUT/mutant.c" >/dev/null 2>&1; then
	echo "FAIL: inline-arithmetic mutant passed the routing check" >&2
	exit 1
fi

"$CC" -std=gnu99 -Wall -Wextra -Werror -O2 -I ci/tools \
	-o "$OUT/ratio_scaling_unit" ci/tools/test_ratio_scaling_unit.c
"$OUT/ratio_scaling_unit"

# The header itself must stay C89-clean for the portable build, on its own
# fallback (ngx_inline empty; no -D mask). The fixture's 128-bit oracle and
# ULL literals are gnu99 and stay out of this pass.
printf '#include <stdint.h>\ntypedef uintptr_t ngx_uint_t;\n#include "../../src/ngx_http_zstd_ratio.h"\nint main(void) { ngx_uint_t a, b; ngx_http_zstd_ratio_parts(3, 2, &a, &b); return a == 1 && b == 500 ? 0 : 1; }\n' \
	>"$OUT/c89.c"
"$CC" -std=c89 -pedantic-errors -Wall -Wextra -Werror -O1 \
	-I ci/tools -o "$OUT/ratio_c89" "$OUT/c89.c"
"$OUT/ratio_c89"

echo "OK: ratio scaling unit fixture (against $HDR)"
