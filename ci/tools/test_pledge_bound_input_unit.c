/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit oracle for ngx_http_zstd_pledge_to_bound_input() -- the guard that
 * decides whether an upstream-declared (off_t) body length may be handed to
 * ZSTD_compressBound() (a size_t) to size the FIRST output buffer.
 *
 * The function is EXTRACTED VERBATIM from
 * src/ngx_http_zstd_filter_module.c by test_pledge_bound_input_unit.sh into
 * generated_pledge_bound_input.inc. This file never re-implements the
 * arithmetic, so it cannot quietly agree with a stale copy of itself.
 *
 * The defect it guards: on an ILP32 build with large-file support
 * (sizeof(size_t) == 4, sizeof(off_t) == 8 -- the ordinary shape once
 * _FILE_OFFSET_BITS=64 is in effect) a bare `(size_t) pledged_size` cast
 * truncates modulo 2^32. A declared length of 4 GiB + 389 becomes 389,
 * ZSTD_compressBound() returns ~389, and the caller's clamp shrinks the
 * first output buffer to ~389 bytes for a 4 GiB body -- an undersized
 * destination that libzstd is then free to overrun.
 *
 * What is asserted, and why each one matters:
 *
 *   1. ORACLE AGREEMENT over the whole domain. An independent uintmax_t
 *      oracle -- deliberately written in a different shape from the
 *      function, comparing at a width no build narrows -- decides accept
 *      vs decline for every case, and *out is checked to equal the input
 *      exactly whenever the function accepted. The oracle is what catches
 *      a truncation: a wrong accept shows up as *out != input, which is
 *      precisely the heap-corrupting outcome.
 *
 *   2. THE FAST PATH SURVIVES. Every value representable in size_t and
 *      below ZSTD_MAX_INPUT_SIZE must be ACCEPTED. A "fix" that declines
 *      broadly would make the truncation unreachable while silently
 *      disabling the first-buffer sizing the call site exists for; case 2
 *      is the regression guard against exactly that shortcut, and it is
 *      why the sweep includes ordinary small lengths and not only the
 *      pathological ones.
 *
 *   3. THE THREE DECLINE REASONS, each hit by a named case: negative
 *      (unknown length), above SIZE_MAX (ILP32 truncation), and at or
 *      above ZSTD_MAX_INPUT_SIZE (where ZSTD_compressBound() returns 0 --
 *      an error, not a bound; a 0 propagating into the caller's clamp
 *      floors buf_size to 256 bytes, which is WORSE than truncation).
 *
 *   4. BOUNDARIES, exhaustively walked rather than sampled: SIZE_MAX - 1,
 *      SIZE_MAX, SIZE_MAX + 1, ZSTD_MAX_INPUT_SIZE - 1,
 *      ZSTD_MAX_INPUT_SIZE, ZSTD_MAX_INPUT_SIZE + 1, 4 GiB - 1, 4 GiB,
 *      4 GiB + 389 (the item's fixture length), 0, and every power of two
 *      +/- 1 that fits in off_t. Plus a deterministic pseudo-random sweep
 *      so a hand-picked table cannot be the only coverage.
 *
 * ZSTD_COMPRESSBOUND() (the macro) is used rather than ZSTD_compressBound()
 * (the function) deliberately: zstd.h documents them as computing the same
 * value, and the macro needs only the header. That keeps this fixture
 * header-only and linkable under -m32 on a host that has no 32-bit libzstd
 * -- and the ILP32 pass is the only one that can observe the defect, so it
 * must not be the pass that gets skipped for a packaging reason.
 *
 * Case labels are compile-time string literals rather than formatted
 * per-case text: check() already prints the offending pledged value in
 * every failure message, so an snprintf()-built label added nothing but a
 * dynamic format string in a test binary.
 *
 * The interesting width (sizeof(off_t) > sizeof(size_t)) does not exist on
 * an LP64 host, so the .sh driver compiles this file TWICE: natively, and
 * again with -m32 -D_FILE_OFFSET_BITS=64. Only the second run reaches the
 * SIZE_MAX-overflow branch; the native run proves the LP64 behaviour is
 * unchanged. Both are required for this fixture to mean anything.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <zstd.h>

/* Minimal nginx shim: the extracted code uses these names only. */
typedef long           ngx_int_t;
typedef unsigned long  ngx_uint_t;
#define ngx_inline     inline

#include "generated_pledge_bound_input.inc"

static long long  failures;
static long long  accepts;
static long long  declines;

/*
 * Independent oracle. Written against uintmax_t -- at least as wide as both
 * off_t and size_t on every conforming implementation -- so its decision is
 * made at a width nothing here narrows. Deliberately NOT structured like the
 * function under test: it computes the two ceilings first and compares once,
 * rather than short-circuiting through a sizeof() test.
 */
static int
oracle_accepts(off_t pledged, uintmax_t *want_out)
{
    uintmax_t  v, size_ceiling, zstd_ceiling;

    if (pledged < 0) {
        return 0;
    }

    v = (uintmax_t) pledged;
    size_ceiling = (uintmax_t) SIZE_MAX;
    zstd_ceiling = (uintmax_t) ZSTD_MAX_INPUT_SIZE;

    if (v > size_ceiling) {
        return 0;
    }
    if (v >= zstd_ceiling) {
        return 0;
    }

    *want_out = v;
    return 1;
}


static void
check(off_t pledged, const char *label)
{
    size_t     got_out = (size_t) 0xA5A5A5A5u;   /* poison */
    ngx_uint_t got;
    uintmax_t  want_out = 0;
    int        want;

    want = oracle_accepts(pledged, &want_out);
    got = ngx_http_zstd_pledge_to_bound_input(pledged, &got_out);

    if (!!got != !!want) {
        fprintf(stderr,
                "FAIL %s: pledged=%" PRIdMAX " -> accepted=%d, oracle=%d"
                " (sizeof off_t=%zu size_t=%zu)\n",
                label, (intmax_t) pledged, (int) !!got, want,
                sizeof(off_t), sizeof(size_t));
        failures++;
        return;
    }

    if (want) {
        accepts++;
        if ((uintmax_t) got_out != want_out) {
            fprintf(stderr,
                    "FAIL %s: pledged=%" PRIdMAX " accepted but *out=%"
                    PRIuMAX " != %" PRIuMAX " -- NARROWING\n",
                    label, (intmax_t) pledged, (uintmax_t) got_out,
                    want_out);
            failures++;
            return;
        }

        /*
         * The whole point of accepting: ZSTD_compressBound() must return a
         * real bound (non-zero) that is at least the input. A zero here
         * would mean the guard let an over-ceiling value through and the
         * caller would floor buf_size to 256 bytes.
         */
        {
            size_t  bound = ZSTD_COMPRESSBOUND(got_out);

            if (bound == 0 || bound < got_out) {
                fprintf(stderr,
                        "FAIL %s: pledged=%" PRIdMAX " accepted but"
                        " ZSTD_COMPRESSBOUND(%zu)=%zu\n",
                        label, (intmax_t) pledged, got_out, bound);
                failures++;
            }
        }

    } else {
        declines++;
    }
}


/* Deterministic xorshift64* -- no libc RNG, identical on every runner. */
static uint64_t  rng_state = 0x9E3779B97F4A7C15ull;

static uint64_t
rng_next(void)
{
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
}


int
main(void)
{
    uintmax_t  off_max;
    int        i;

    /*
     * The largest positive off_t, computed without overflow: all value bits
     * of the signed type set.
     */
    off_max = ((uintmax_t) 1 << (sizeof(off_t) * 8 - 1)) - 1;

    printf("sizeof(off_t)=%zu sizeof(size_t)=%zu SIZE_MAX=%" PRIuMAX
           " ZSTD_MAX_INPUT_SIZE=%" PRIuMAX " OFF_MAX=%" PRIuMAX "\n",
           sizeof(off_t), sizeof(size_t), (uintmax_t) SIZE_MAX,
           (uintmax_t) ZSTD_MAX_INPUT_SIZE, off_max);

    /* --- 3: negative / unknown length ---------------------------------- */
    check((off_t) -1, "unknown(-1)");
    check((off_t) -2, "negative(-2)");
    check((off_t) (-(intmax_t) off_max - 1), "off_t min");

    /* --- 2: the fast path must survive --------------------------------- */
    check((off_t) 0, "zero");
    check((off_t) 1, "one");
    check((off_t) 389, "389 (the small-body case the sizing exists for)");
    check((off_t) 131072, "default bufs.size");
    check((off_t) (1024 * 1024), "1 MiB");

    /* --- 4: named boundaries ------------------------------------------- */
    {
        static const uintmax_t  interesting[] = {
            0xFFFFFFFFull - 1,          /* 4 GiB - 2 */
            0xFFFFFFFFull,              /* 4 GiB - 1: last 32-bit value */
            0x100000000ull,             /* 4 GiB exactly */
            0x100000185ull,             /* 4 GiB + 389: the item's fixture */
            0x100000000ull + 131072,    /* 4 GiB + a full buffer */
            0xFF00FF00ull - 1,          /* ILP32 ZSTD ceiling - 1 */
            0xFF00FF00ull,              /* ILP32 ZSTD ceiling */
            0xFF00FF00ull + 1,
            0xFF00FF00FF00FF00ull - 1,  /* LP64 ZSTD ceiling - 1 */
            0xFF00FF00FF00FF00ull,      /* LP64 ZSTD ceiling */
            0xFF00FF00FF00FF00ull + 1,
        };
        size_t  n;

        for (n = 0; n < sizeof(interesting) / sizeof(interesting[0]); n++) {
            uintmax_t  v = interesting[n];

            if (v > off_max) {
                continue;   /* not representable as a positive off_t here */
            }
            check((off_t) v, "named boundary");
        }
    }

    /* SIZE_MAX -1 / SIZE_MAX / SIZE_MAX +1, when they fit in off_t. */
    {
        uintmax_t  sm = (uintmax_t) SIZE_MAX;
        int        d;

        for (d = -1; d <= 1; d++) {
            uintmax_t  v;

            if (d < 0 && sm == 0) {
                continue;
            }
            v = sm + (uintmax_t) d;
            if (v > off_max) {
                continue;
            }
            check((off_t) v, "SIZE_MAX neighbourhood");
        }
    }

    /* Every power of two, +/- 1, that fits in off_t. */
    for (i = 0; i < (int) (sizeof(off_t) * 8 - 1); i++) {
        uintmax_t  p = (uintmax_t) 1 << i;
        int        d;

        for (d = -1; d <= 1; d++) {
            uintmax_t  v;

            if (d < 0 && p == 0) {
                continue;
            }
            v = p + (uintmax_t) d;
            if (v > off_max) {
                continue;
            }
            check((off_t) v, "power of two neighbourhood");
        }
    }

    /* --- 1: randomized sweep over the full off_t range ------------------ */
    for (i = 0; i < 200000; i++) {
        uint64_t  r = rng_next();
        off_t     v;

        if (sizeof(off_t) == 4) {
            v = (off_t) (int32_t) (uint32_t) r;
        } else {
            v = (off_t) (int64_t) r;
        }

        check(v, "random");
    }

    if (failures) {
        fprintf(stderr, "FAILED: %lld case(s)\n", failures);
        return 1;
    }

    /*
     * Both outcomes must actually have been exercised. A build where every
     * case declined (or every case accepted) would report a vacuous pass.
     */
    if (accepts == 0 || declines == 0) {
        fprintf(stderr,
                "FAILED: vacuous sweep -- accepts=%lld declines=%lld;"
                " one branch was never reached\n", accepts, declines);
        return 1;
    }

    printf("OK: %lld accepted, %lld declined, oracle agreed on all\n",
           accepts, declines);
    return 0;
}
