#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

SRC="src/ngx_http_zstd_static_module.c"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-probe-log-unit.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

start="$(grep -n '^ngx_http_zstd_static_probe_read_log_level(ssize_t n, ngx_uint_t directio,$' "$SRC" | cut -d: -f1)"
if [ -z "$start" ]; then
    echo "FAIL: could not locate probe read-log helper" >&2
    exit 1
fi
start=$((start - 1))
end_rel="$(tail -n "+$start" "$SRC" | grep -n '^}' | head -1 | cut -d: -f1)"
end=$((start + end_rel - 1))
sed -n "${start},${end}p" "$SRC" >"$OUT/generated_probe_log.inc"

"${CC:-cc}" -std=c99 -Wall -Wextra -Werror -O1 -I"$OUT" \
    -o "$OUT/test_static_probe_log_unit" \
    ci/tools/test_static_probe_log_unit.c
"$OUT/test_static_probe_log_unit"
