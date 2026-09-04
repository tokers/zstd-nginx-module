/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit oracle for ngx_http_zstd_ratio_parts() -- the $zstd_ratio scaling
 * helper. The previous form computed `bytes_in * 1000 / bytes_out` in one
 * step: for a bytes_in near UINT64_MAX the *1000 multiplication overflows
 * the uint64_t accumulator and wraps, corrupting both the integer and
 * fractional digits reported to the client/log. The fixed form divides
 * first and only scales the (necessarily smaller) remainder, so the
 * multiplication cannot overflow.
 *
 * The function is EXTRACTED VERBATIM from
 * src/ngx_http_zstd_filter_module.c by test_ratio_scaling_unit.sh into
 * generated_ratio_parts.inc -- this file never re-implements the scaling,
 * so it cannot quietly agree with a stale copy of itself.
 *
 * What is asserted, and why:
 *
 *   1. THRESHOLD/BOUNDARY cases at ordinary byte counts (e.g. bytes_in ==
 *      bytes_out, 2x, non-exact ratios) must keep producing the same
 *      integer and fractional digits as before -- rounding/output below
 *      the overflow threshold is a preserved invariant, not something this
 *      row is allowed to change.
 *
 *   2. OVERFLOW NEGATIVE CONTROL: bytes_in near UINT64_MAX with a small
 *      bytes_out must still produce the mathematically correct integer
 *      part (bytes_in / bytes_out, verified via widening arithmetic in the
 *      test itself) rather than a wrapped/corrupted value. This is the
 *      case the old `* 1000` first form got wrong.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

typedef unsigned long  ngx_uint_t;

/* THE authoritative copy, included directly -- no extracted duplicate. */
#include "../../src/ngx_http_zstd_ratio.h"

static long long failures;

static void
fail(const char *what, uint64_t bytes_in, uint64_t bytes_out,
    ngx_uint_t got_int, ngx_uint_t got_frac, ngx_uint_t want_int,
    ngx_uint_t want_frac)
{
    failures++;
    if (failures <= 20) {
        fprintf(stderr,
                "FAIL %s: bytes_in=%" PRIu64 " bytes_out=%" PRIu64
                " -> %lu.%03lu, want %lu.%03lu\n",
                what, bytes_in, bytes_out, got_int, got_frac, want_int,
                want_frac);
    }
}

static void
check(const char *what, uint64_t bytes_in, uint64_t bytes_out,
    ngx_uint_t want_int, ngx_uint_t want_frac)
{
    ngx_uint_t  got_int, got_frac;

    ngx_http_zstd_ratio_parts(bytes_in, bytes_out, &got_int, &got_frac);

    if (got_int != want_int || got_frac != want_frac) {
        fail(what, bytes_in, bytes_out, got_int, got_frac, want_int,
             want_frac);
    }
}

int
main(void)
{
    /* 1. Ordinary threshold/boundary cases -- output must be unchanged. */
    check("equal", 1000, 1000, 1, 0);
    check("2x-exact", 2000, 1000, 2, 0);
    check("half", 500, 1000, 0, 500);
    check("one-third", 1000, 3000, 0, 333);
    check("small-remainder", 1001, 1000, 1, 1);
    check("large-ordinary", 987654321ULL, 123456789ULL, 8, 0);

    /* 2. Overflow negative control: bytes_in near UINT64_MAX. The old
     * `bytes_in * 1000 / bytes_out` form would overflow computing
     * bytes_in * 1000 here and wrap to a wrong (and non-deterministic
     * looking) integer part; the fixed divide-first form must still
     * report the true quotient. */
    {
        uint64_t  bytes_in  = UINT64_MAX - 3;
        uint64_t  bytes_out = 7;
        uint64_t  want_int  = bytes_in / bytes_out;
        uint64_t  remainder = bytes_in % bytes_out;
        uint64_t  want_frac = remainder * 1000 / bytes_out;

        check("near-uint64-max-small-divisor", bytes_in, bytes_out,
              (ngx_uint_t) want_int, (ngx_uint_t) want_frac);
    }
    {
        uint64_t  bytes_in  = UINT64_MAX;
        uint64_t  bytes_out = UINT64_MAX - 1;

        /* bytes_in / bytes_out == 1, remainder == 1, frac == 1000/(MAX-1)
         * which truncates to 0. */
        check("near-uint64-max-both", bytes_in, bytes_out, 1, 0);
    }

    /* 3. Expanding stream: bytes_out > bytes_in, which happens whenever
     * zstd expands incompressible input. This is the case a divide-first
     * form still gets wrong -- the remainder is then bytes_in itself, so
     * scaling it by 1000 in one step overflows exactly as the original
     * single-expression form did. Reported by CodeRabbit against the first
     * version of this fix; the digit-at-a-time long division must report
     * 0.999 rather than wrapping to 0.000. */
    check("large-expanding-stream", UINT64_MAX - 1, UINT64_MAX, 0, 999);
    check("expanding-half", 500, 1000, 0, 500);
    check("expanding-near-max-third", UINT64_MAX / 3, UINT64_MAX, 0, 333);

    /* 4. Differential sweep against an unsigned __int128 oracle over a
     * mix of ordinary and extreme magnitudes. The oracle computes the
     * exact bytes_in*1000/bytes_out in 128-bit, so any wrap or precision
     * loss in the 64-bit implementation shows up as a mismatch rather
     * than needing a hand-picked witness per case. */
    {
        static const uint64_t vals[] = {
            1, 2, 3, 7, 999, 1000, 1001, 65535,
            4294967295ULL, 4294967296ULL,
            987654321987654321ULL,
            UINT64_MAX / 3, UINT64_MAX / 2, UINT64_MAX - 1, UINT64_MAX
        };
        size_t  n = sizeof(vals) / sizeof(vals[0]);
        size_t  i, j;

        for (i = 0; i < n; i++) {
            for (j = 0; j < n; j++) {
                unsigned __int128  scaled;
                uint64_t           bi = vals[i];
                uint64_t           bo = vals[j];
                ngx_uint_t         gi, gf;
                char               name[64];

                scaled = ((unsigned __int128) bi * 1000)
                         / (unsigned __int128) bo;

                ngx_http_zstd_ratio_parts(bi, bo, &gi, &gf);

                if (gi != (ngx_uint_t) (scaled / 1000)
                    || gf != (ngx_uint_t) (scaled % 1000))
                {
                    snprintf(name, sizeof(name), "oracle[%zu][%zu]", i, j);
                    printf("FAIL %s: bytes_in=%llu bytes_out=%llu -> "
                           "%llu.%03llu, want %llu.%03llu\n",
                           name, (unsigned long long) bi,
                           (unsigned long long) bo,
                           (unsigned long long) gi,
                           (unsigned long long) gf,
                           (unsigned long long) (scaled / 1000),
                           (unsigned long long) (scaled % 1000));
                    failures++;
                }
            }
        }
    }

    /* 5. Randomized differential sweep against the same 128-bit oracle,
     * with a fixed seed so a failure is reproducible. Covers magnitude
     * combinations the hand-picked table does not enumerate, including
     * many bytes_out > bytes_in (expanding) pairs. */
    {
        unsigned long long  state = 0x9E3779B97F4A7C15ULL;
        int                 iter;

        for (iter = 0; iter < 200000; iter++) {
            unsigned __int128  scaled;
            uint64_t           bi, bo;
            ngx_uint_t         gi, gf;

            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            bi = state;
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            bo = state;

            /* exercise small magnitudes too, not only full-width values */
            if (iter % 3 == 1) { bi >>= (iter % 63); }
            if (iter % 3 == 2) { bo >>= (iter % 63); }

            if (bo == 0) { bo = 1; }

            scaled = ((unsigned __int128) bi * 1000) / (unsigned __int128) bo;

            ngx_http_zstd_ratio_parts(bi, bo, &gi, &gf);

            if (gi != (ngx_uint_t) (scaled / 1000)
                || gf != (ngx_uint_t) (scaled % 1000))
            {
                printf("FAIL random[%d]: bytes_in=%llu bytes_out=%llu -> "
                       "%llu.%03llu, want %llu.%03llu\n",
                       iter, (unsigned long long) bi,
                       (unsigned long long) bo,
                       (unsigned long long) gi, (unsigned long long) gf,
                       (unsigned long long) (scaled / 1000),
                       (unsigned long long) (scaled % 1000));
                failures++;
                break;
            }
        }
    }

    if (failures) {
        printf("FAILED: %lld assertion(s)\n", failures);
        return 1;
    }

    printf("OK: ratio scaling (ordinary thresholds unchanged, "
           "near-UINT64_MAX overflow-safe)\n");
    return 0;
}
