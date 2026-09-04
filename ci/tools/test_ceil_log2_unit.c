/*
 * Unit fixture for ngx_http_zstd_ceil_log2() — grind-g6-nits owed control.
 *
 * ngx_http_zstd_ceil_log2() is `static` inside
 * src/ngx_http_zstd_filter_module.c (a dcz window-log helper, not a
 * header), so it cannot be linked from outside that TU. Rather than keep
 * a hand-copied duplicate that silently drifts from the shipped code
 * (the repo has exactly this "extraction" precedent for the Accept-Encoding
 * parser fuzz harness), tools/test_ceil_log2_unit.sh extracts the function
 * verbatim by line range and #includes the generated file here — this
 * test always exercises the CURRENT shipped implementation.
 *
 * ngx_http_zstd_ceil_log2() was shipped BROKEN in this PR (inverted
 * power-of-two test: incremented wlog for exact powers of two instead of
 * non-powers) and fixed in c264f4b. This fixture asserts equivalence
 * against a reference LINEAR shift-and-count implementation (independent
 * of __builtin_clzll) over every value 0..2^24 inclusive — covering every
 * exact power of two through 2^23 — and asserts the result always lands
 * in [10, NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG(=23)].
 */

#include <stdio.h>
#include <stdint.h>

typedef uintptr_t  ngx_uint_t;
#define ngx_inline inline

#include "generated_ceil_log2.inc"

#define WLOG_MIN  10
#define WLOG_MAX  23

/* Reference implementation: plain linear shift-and-count, independent of
 * __builtin_clzll, mirroring the portable (#else) branch's algorithm but
 * kept as a SEPARATE hand-written oracle rather than a copy of either
 * branch under test. */
static ngx_uint_t
ref_ceil_log2(size_t x)
{
    ngx_uint_t  wlog;
    size_t      pow2;

    if (x <= 1024) {
        return WLOG_MIN;
    }

    if (x > ((size_t) 1 << WLOG_MAX)) {
        return WLOG_MAX;
    }

    wlog = WLOG_MIN;
    pow2 = 1024;

    while (pow2 < x) {
        pow2 <<= 1;
        wlog++;
    }

    return wlog;
}

int
main(void)
{
    size_t      x;
    ngx_uint_t  got, want;
    long        mismatches = 0;
    long        checked = 0;
    int         k;

    /* Full range 0..2^24, including every power of two through 2^23. */
    for (x = 0; x <= ((size_t) 1 << 24); x++) {
        got = ngx_http_zstd_ceil_log2(x);
        want = ref_ceil_log2(x);
        checked++;

        if (got != want) {
            if (mismatches < 20) {
                printf("FAIL - x=%zu got=%lu want=%lu\n",
                       x, (unsigned long) got, (unsigned long) want);
            }
            mismatches++;
        }

        if (got < WLOG_MIN || got > WLOG_MAX) {
            printf("FAIL - x=%zu out of bounds: got=%lu (want [%d,%d])\n",
                   x, (unsigned long) got, WLOG_MIN, WLOG_MAX);
            mismatches++;
        }
    }

    /* Explicitly re-check every power of two through 2^23 (already inside
     * the swept range above, but named individually so a regression in
     * just the power-of-two branch shows up as a named failure, not a
     * buried count). */
    for (k = 0; k <= 23; k++) {
        size_t  p = (size_t) 1 << k;

        got = ngx_http_zstd_ceil_log2(p);
        want = ref_ceil_log2(p);

        if (got != want) {
            printf("FAIL - power-of-two 2^%d: got=%lu want=%lu\n",
                   k, (unsigned long) got, (unsigned long) want);
            mismatches++;
        }
    }

    printf("checked %ld values (0..2^24) + 24 named powers of two, "
           "%ld mismatch(es)\n", checked, mismatches);

    if (mismatches) {
        printf("FAILED: %ld ceil_log2 mismatch(es) against linear reference\n",
               mismatches);
        return 1;
    }

    printf("OK: ceil_log2 equivalence (0..2^24, bounds [%d,%d])\n",
           WLOG_MIN, WLOG_MAX);
    return 0;
}
