#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# Production must consume the authoritative header, not a copy.
grep -Fq '#include "ngx_http_zstd_frame_probe.h"' \
	"$root/src/ngx_http_zstd_static_module.c"

check_definition() {
	expected=$1
	fn=$2
	tree=$3

	if ! defs=$(grep -r -n -h "^$fn(" \
		"$tree/src" "$tree/filter" "$tree/static" "$tree/ci"); then
		echo "probe seam: could not find $fn definitions" >&2
		return 1
	fi

	if ! sites=$(grep -r -l "^$fn(" \
		"$tree/src" "$tree/filter" "$tree/static" "$tree/ci"); then
		echo "probe seam: could not find $fn definition sites" >&2
		return 1
	fi

	count=$(printf '%s\n' "$defs" | wc -l)

	if [ "$count" -ne 1 ] || [ "$sites" != "$expected" ]; then
		echo "probe seam: unexpected definition sites for $fn:" >&2
		echo "$sites" >&2
		echo "probe seam: expected 1 definition, found $count" >&2
		return 1
	fi
}

# Each probe function is defined exactly once in the tree. A second
# column-0 definition anywhere in the module sources is the
# synchronized-copy drift #270 removed coming back -- possible while
# the unit tests keep exercising only the header.
for fn in ngx_http_zstd_static_probe_frame ngx_http_zstd_static_probe_reuse; do
	check_definition "$root/src/ngx_http_zstd_frame_probe.h" "$fn" \
		"$root"
done

# Same seam, second family: the Cache-Control no-transform helpers
# moved to their own authoritative header; production must include it
# and each helper must keep exactly one definition.
grep -Fq '#include "ngx_http_zstd_cache_control.h"' \
	"$root/src/ngx_http_zstd_filter_module.c"

for fn in ngx_http_zstd_cache_control_directive_end \
	ngx_http_zstd_cache_control_value_no_transform \
	ngx_http_zstd_cache_control_no_transform; do
	check_definition "$root/src/ngx_http_zstd_cache_control.h" "$fn" \
		"$root"
done

# Same seam, the ratio helper: production must include its header and
# the split must keep exactly one definition.
grep -Fq '#include "ngx_http_zstd_ratio.h"' \
	"$root/src/ngx_http_zstd_filter_module.c"
check_definition "$root/src/ngx_http_zstd_ratio.h" \
	ngx_http_zstd_ratio_parts "$root"

# Detection control: redirect the real unit fixture to a copied probe
# implementation under ci/. The fixture must stay green while the seam
# check turns red, reproducing the drift this gate exists to catch.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src" "$tmp/filter" "$tmp/static" "$tmp/ci/tools"
cp "$root/src/ngx_http_zstd_frame_probe.h" \
	"$tmp/src/ngx_http_zstd_frame_probe.h"
cp "$root/src/ngx_http_zstd_frame_probe.h" \
	"$tmp/ci/tools/generated_static_probe.inc"
sed 's|#include "../../src/ngx_http_zstd_frame_probe.h"|#include "generated_static_probe.inc"|' \
	"$root/ci/tools/test_static_probe_unit.c" \
	>"$tmp/ci/tools/test_static_probe_unit.c"

if ! grep -Fq '#include "generated_static_probe.inc"' \
	"$tmp/ci/tools/test_static_probe_unit.c"; then
	echo 'probe seam: detection control did not redirect the unit fixture' >&2
	exit 1
fi

cc=${CC:-cc}
"$cc" -std=gnu99 -Wall -Wextra -Werror -O1 \
	-I "$tmp/ci/tools" -o "$tmp/test_static_probe_unit" \
	"$tmp/ci/tools/test_static_probe_unit.c"
"$tmp/test_static_probe_unit" >/dev/null

if check_definition "$tmp/src/ngx_http_zstd_frame_probe.h" \
	ngx_http_zstd_static_probe_frame "$tmp" >/dev/null 2>&1; then
	echo 'probe seam: detection control missed a copied CI implementation' >&2
	exit 1
fi

# Cache-control control: the same staged-drift shape -- the header
# copied back under ci/ (no unit fixture exists for this family, so
# the copy alone is the scenario) -- must turn the definition count
# red.
cp "$root/src/ngx_http_zstd_cache_control.h" \
	"$tmp/src/ngx_http_zstd_cache_control.h"
cp "$root/src/ngx_http_zstd_cache_control.h" \
	"$tmp/ci/tools/copied_cache_control.h"

if check_definition "$tmp/src/ngx_http_zstd_cache_control.h" \
	ngx_http_zstd_cache_control_value_no_transform "$tmp" \
	>/dev/null 2>&1; then
	echo 'probe seam: detection control missed a copied cache-control header' >&2
	exit 1
fi

echo 'probe header seam: PASS'
