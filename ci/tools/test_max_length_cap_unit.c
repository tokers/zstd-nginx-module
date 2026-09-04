/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit oracle for ngx_http_zstd_max_length_exceeded() -- the
 * length-independent zstd_max_length cap checked per iteration of the
 * streaming body filter (see ci/t/00-filter.t TEST 42/111/112, which cover
 * the same cap end-to-end through a mock chunked upstream on the native
 * build; this fixture covers the one comparison-width defect those tests
 * cannot reach without a 32-bit off_t).
 *
 * The function is EXTRACTED VERBATIM from
 * src/ngx_http_zstd_filter_module.c by test_max_length_cap_unit.sh into
 * generated_max_length_cap.inc -- this file never re-implements the
 * comparison, so it cannot quietly agree with a stale copy of itself.
 *
 * What is asserted, and why each one matters:
 *
 *   1. NO CAP CONFIGURED (max_length == NGX_CONF_UNSET) never fires,
 *      regardless of bytes_in. zstd_max_length is opt-in; an operator who
 *      never set it must not see requests aborted.
 *
 *   2. AT THE CAP does not fire (bytes_in == max_length): the check is a
 *      strict "exceeded", not "at or above". A body landing exactly on the
 *      configured size must still be allowed to finish compressing --
 *      this is TEST 111's boundary, asserted here directly against the
 *      predicate rather than through a live upstream.
 *
 *   3. ONE BYTE OVER THE CAP fires (bytes_in == max_length + 1): the
 *      complementary boundary to (2), and TEST 112's case.
 *
 *   4. A LARGE bytes_in (well past INT32_MAX, still a legal uint64_t) must
 *      still correctly exceed a small max_length. On a genuine 32-bit
 *      off_t build (plain -m32, no _FILE_OFFSET_BITS override -- the
 *      second pass in test_max_length_cap_unit.sh) off_t is 4 bytes, same
 *      as ssize_t; the historical `(off_t) bytes_in > (off_t) max_length`
 *      form cast the unsigned accumulator through that narrow off_t
 *      instead of comparing unsigned-to-unsigned as this predicate does,
 *      truncating a large bytes_in and losing the comparison. Sweeping
 *      max_length up through and past INT32_MAX in assertions 2 and 3
 *      above, together with this large-bytes_in probe, is what makes this
 *      fixture catch a regression back to that signed-cast form on that
 *      build; an ILP32+LFS build (off_t widened to 64 bits) or a native
 *      64-bit build cannot distinguish the two forms at all.
 *
 * The sweep is exhaustive over the interesting boundary values rather than
 * a handful of hand-picked cases.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/* Minimal nginx shim: the extracted code uses these names only. */
typedef intptr_t  ngx_flag_t;
#define NGX_CONF_UNSET  -1

#include "generated_max_length_cap.inc"

static long long failures;

static void
fail(const char *what, uint64_t bytes_in, ssize_t max_length, int got,
    int want)
{
    failures++;
    if (failures <= 20) {
        fprintf(stderr,
                "FAIL %s: bytes_in=%" PRIu64 " max_length=%zd -> %d, want %d\n",
                what, bytes_in, (ssize_t) max_length, got, want);
    }
}

int
main(void)
{
    /*
     * max_length values spanning the legal ssize_t range: unset, tiny,
     * astride INT32_MAX (the width a truncating/narrowing cast would
     * disagree at), and the largest value ssize_t can hold on this build.
     */
    static const ssize_t max_lengths[] = {
        (ssize_t) NGX_CONF_UNSET,
        0,
        1,
        100,
        4999,
        5000,
        (ssize_t) INT32_MAX - 1,
        (ssize_t) INT32_MAX,
#if SSIZE_MAX > INT32_MAX
        /* Only representable when ssize_t is wider than 32 bits (the
         * native 64-bit build); on ILP32, INT32_MAX is already SSIZE_MAX
         * and one past it is not a legal max_length. */
        (ssize_t) INT32_MAX + 1,
#endif
    };

    size_t     mi;
    long long  swept = 0;

    for (mi = 0; mi < sizeof(max_lengths) / sizeof(max_lengths[0]); mi++) {
        ssize_t  max_length = max_lengths[mi];

        /* 1. no cap configured never fires, at any bytes_in tried below. */
        if (max_length == NGX_CONF_UNSET) {
            static const uint64_t probes[] = {
                0, 1, 5000, (uint64_t) INT32_MAX, (uint64_t) INT32_MAX + 1,
                (uint64_t) UINT32_MAX + 1000,
            };
            size_t  pi;

            for (pi = 0; pi < sizeof(probes) / sizeof(probes[0]); pi++) {
                int  got = ngx_http_zstd_max_length_exceeded(probes[pi],
                                                              max_length);
                swept++;
                if (got) {
                    fail("unset-never-fires", probes[pi], max_length, got, 0);
                }
            }
            continue;
        }

        /* 2. at the cap: must NOT fire. */
        {
            uint64_t  bytes_in = (uint64_t) max_length;
            int       got = ngx_http_zstd_max_length_exceeded(bytes_in,
                                                                max_length);

            swept++;
            if (got) {
                fail("at-cap", bytes_in, max_length, got, 0);
            }
        }

        /* 3. one byte over: must fire. Computed in uint64_t so max_length
         * == SSIZE_MAX (the ILP32 build's INT32_MAX case) cannot overflow
         * the ssize_t addition before widening. */
        {
            uint64_t  bytes_in = (uint64_t) max_length + 1;
            int       got = ngx_http_zstd_max_length_exceeded(bytes_in,
                                                                max_length);

            swept++;
            if (!got) {
                fail("one-over-cap", bytes_in, max_length, got, 1);
            }
        }

        /*
         * 4. bytes_in far past INT32_MAX must still correctly compare
         * against a small max_length -- the 32-bit off_t regression case.
         * Skip when max_length itself is already >= this probe, since then
         * the probe would be at-or-under the cap and the expected answer
         * would flip.
         */
        {
            uint64_t  bytes_in = (uint64_t) INT32_MAX + 1000000;

            if ((uint64_t) max_length < bytes_in) {
                int  got = ngx_http_zstd_max_length_exceeded(bytes_in,
                                                              max_length);

                swept++;
                if (!got) {
                    fail("large-bytes-in-exceeds-small-cap", bytes_in,
                         max_length, got, 1);
                }
            }
        }
    }

    printf("swept %lld combinations\n", swept);

    if (failures) {
        printf("FAILED: %lld assertion(s)\n", failures);
        return 1;
    }

    printf("OK: max_length cap (unset never fires, at-cap allows, "
           "over-cap fires, large bytes_in vs small cap fires)\n");
    return 0;
}
