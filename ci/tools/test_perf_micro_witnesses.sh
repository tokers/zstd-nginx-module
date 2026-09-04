#!/bin/bash
# Deterministic witnesses for the A33 P7/P9/P10 scan reductions.
#
# The runtime fixture compiles verbatim extracts of the production helpers;
# this script separately pins the source shape that makes P9/P10 single-pass.
# The two checks are complementary: behavior alone cannot observe a redundant
# walk, while source shape alone cannot prove the parser still answers right.
set -euo pipefail

cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-perf-witnesses.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

extract_function() {
    local src=$1 signature=$2 output=$3 sig_line start_line rel_end end_line

    sig_line=$(grep -n -m1 "^${signature}$" "$src" | cut -d: -f1 || true)
    if [ -z "$sig_line" ]; then
        echo "FAIL: could not locate $signature in $src" >&2
        return 1
    fi

    start_line=$((sig_line - 1))
    rel_end=$(awk -v start="$start_line" \
        'NR >= start && /^}$/ { print NR - start + 1; exit }' "$src")
    if [ -z "$rel_end" ]; then
        echo "FAIL: could not find the end of $signature in $src" >&2
        return 1
    fi
    end_line=$((start_line + rel_end - 1))
    sed -n "${start_line},${end_line}p" "$src" >>"$output"
}

extract_function src/ngx_http_zstd_common.h \
    'ngx_http_zstd_vary_find_tokens(ngx_http_request_t \*r,' \
    "$OUT/generated_vary_find_tokens.inc"
extract_function src/ngx_http_zstd_static_module.c \
    'ngx_http_zstd_static_cached_verdict(ngx_str_t \*path, ngx_open_file_info_t \*of,' \
    "$OUT/generated_verdict_cache_work.inc"
extract_function src/ngx_http_zstd_static_module.c \
    'ngx_http_zstd_static_remember(ngx_str_t \*path, ngx_open_file_info_t \*of,' \
    "$OUT/generated_verdict_cache_work.inc"

check_vary_single_scan() {
    local input=$1 count

    count=$(grep -Fc "while (p < end && *p != ',')" "$input" || true)
    if [ "$count" -ne 1 ] || ! grep -Fq 'p = tok_end;' "$input"; then
        echo "FAIL: Vary helper no longer has one comma scan plus cursor reuse" >&2
        return 1
    fi
}

check_cache_control_single_scan() {
    local input=$1 value_body calls

    if ! grep -Fq 'u_char **name_end' "$input"; then
        echo "FAIL: Cache-Control segment helper lost its name-end out parameter" >&2
        return 1
    fi
    value_body=$(sed -n \
        '/^ngx_http_zstd_cache_control_value_no_transform(ngx_table_elt_t \*cc)$/,/^}/p' \
        "$input")
    calls=$(printf '%s\n' "$value_body" \
        | grep -c 'ngx_http_zstd_cache_control_directive_end' || true)
    if [ "$calls" -ne 1 ] || printf '%s\n' "$value_body" \
        | grep -Eq 'while \([^)]*< directive_end'; then
        echo "FAIL: Cache-Control value helper reintroduced a second segment scan" >&2
        return 1
    fi
}

check_vary_single_scan "$OUT/generated_vary_find_tokens.inc"
check_cache_control_single_scan src/ngx_http_zstd_cache_control.h

# Controls for the two structural detectors. Recreate the removed re-walks
# and require each detector to reject its own old-cost shape.
sed "/p = tok_end;/i\\
                while (p < end && *p != ',') { p++; }" \
    "$OUT/generated_vary_find_tokens.inc" >"$OUT/vary-mutant.inc"
if check_vary_single_scan "$OUT/vary-mutant.inc" >/dev/null 2>&1; then
    echo "FAIL: Vary redundant-scan control escaped the source-shape gate" >&2
    exit 1
fi

sed '/        end = name_end;/i\
        while (name_end < directive_end) { name_end++; }' \
    src/ngx_http_zstd_cache_control.h >"$OUT/cache-control-mutant.h"
if check_cache_control_single_scan "$OUT/cache-control-mutant.h" \
    >/dev/null 2>&1; then
    echo "FAIL: Cache-Control redundant-scan control escaped the source-shape gate" >&2
    exit 1
fi

"$CC" -std=c99 -Wall -Wextra -Wshadow -Werror -O2 -I"$OUT" \
    -o "$OUT/test_perf_micro_witnesses" \
    ci/tools/test_perf_micro_witnesses.c
"$OUT/test_perf_micro_witnesses"

# P7 control: compile the same fixture with the old 64-slot loop bound. The
# poison entries beyond count make that redundant walk observable as extra
# ngx_memcmp calls without timing noise.
sed 's/i < ngx_http_zstd_static_verdict_cache_count/i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS/' \
    "$OUT/generated_verdict_cache_work.inc" \
    >"$OUT/generated_verdict_cache_work_mutant.inc"
if ! grep -Fq 'i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS' \
    "$OUT/generated_verdict_cache_work_mutant.inc"; then
    echo "FAIL: verdict-cache loop-bound control did not apply" >&2
    exit 1
fi
"$CC" -std=c99 -Wall -Wextra -Wshadow -Werror -O2 -I"$OUT" \
    -DTEST_VERDICT_CACHE_MUTANT \
    -o "$OUT/test_perf_micro_witnesses_mutant" \
    ci/tools/test_perf_micro_witnesses.c
if "$OUT/test_perf_micro_witnesses_mutant" >/dev/null 2>&1; then
    echo "FAIL: 64-slot verdict-cache mutant passed the call-count witness" >&2
    exit 1
fi

echo 'OK: A33 P7/P9/P10 performance witnesses and controls'
