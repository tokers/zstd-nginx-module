#!/usr/bin/env bash
set -euo pipefail

module="${1:-objs/ngx_http_zstd_filter_module.so}"

if ! readelf -d "$module" | grep -E 'NEEDED.*libzstd' >/dev/null; then
	echo "FAIL: $module does not declare a libzstd DT_NEEDED entry" >&2
	readelf -d "$module" | grep NEEDED || true
	exit 1
fi

for sym in ZSTD_createCCtxParams ZSTD_CCtxParams_init \
	ZSTD_CCtxParams_setParameter ZSTD_freeCCtxParams \
	ZSTD_estimateCStreamSize_usingCCtxParams ZSTD_createCDict_advanced; do
	if nm -D --undefined-only "$module" | awk '{print $NF}' | grep -qx "$sym"; then
		echo "FAIL: $module imports static-only libzstd symbol $sym" >&2
		exit 1
	fi
done

echo "OK: $module links dynamically without ZSTDLIB_STATIC_API imports"
