/*
 * Microbenchmark for A31b-F2: does ZSTD_CCtx_refPrefix() (the dcz raw-prefix
 * path, ngx_http_zstd_filter_module.c:~3870) pay a per-request dictionary
 * table build that ZSTD_CCtx_refCDict() (the trained zstd_dict_file path,
 * :~3911) amortises once at config load?
 *
 * This is a PROOF/MEASUREMENT tool only -- it does not touch the module. It
 * links libzstd directly (ZSTD_STATIC_LINKING_ONLY, for
 * ZSTD_createCDict_advanced(), exactly as the module itself gates it) and
 * times two code paths at the module's real parameters:
 *
 *   PREFIX path (dcz):   ZSTD_CCtx_reset(session_and_parameters)
 *                         + ZSTD_CCtx_setParameter(level, windowLog)
 *                         + ZSTD_CCtx_refPrefix(dict, dictLen)
 *                         + ZSTD_compress2(body)
 *     -- mirrors init_cctx()'s per-request sequence exactly: reset first
 *        (module :3694), then refPrefix (module :3870/:3874).
 *
 *   CDICT path (hypothetical fix direction): CDict built ONCE outside the
 *   timed loop with ZSTD_createCDict_advanced(..., ZSTD_dct_rawContent, ...)
 *   -- rawContent, not dct_auto, to preserve RFC 9842 raw-prefix wire
 *   semantics (dct_auto risks treating a dictionary-shaped buffer as a
 *   trained dictionary structure instead of raw content) -- then per
 *   request only ZSTD_CCtx_reset() + ZSTD_CCtx_refCDict() + compress2().
 *
 * Sweep: dictionary size x {64 KiB, 1 MiB, 4 MiB, 10 MiB (module's
 * NGX_HTTP_ZSTD_MAX_DICT_SIZE cap)} x body size x {4 KiB (normal dcz shape,
 * body << dict) , 256 KiB (body larger than dict)}.
 *
 * Level fixed at 3 (the module's compiled-in default, module :4143 /
 * NGX_HTTP_ZSTD_LEVEL_UNSET resolves to 3). windowLog is derived the same
 * way ngx_http_zstd_dcz_window_log() derives it for dcz: ceil_log2(dict +
 * body), clamped to [ZSTD_WINDOWLOG_MIN=10, 23] -- see module comment at
 * :270-303.
 *
 * NOISE FLOOR: before trusting any prefix-vs-cdict delta, this program
 * measures identical-vs-identical (prefix path timed against itself, two
 * disjoint sets of iterations) at the same sweep points and reports that
 * delta first. Only a prefix-vs-cdict gap that clearly exceeds the
 * identical-vs-identical noise floor is reported as a real effect.
 *
 * BYTE IDENTITY (A33-F1): a separate, untimed sweep compares the compressed
 * bytes of the two paths across the level axis (1..19) in two content modes.
 *
 * The original version of this check swept only LEVEL 3 and only "disjoint"
 * content -- dictionary and body seeded from different constants, hence
 * statistically unrelated. Under those conditions the compressor finds no
 * cross-matches at all, the dictMatchState search is never exercised, and the
 * two paths agree trivially. That vacuous PASS was then cited as proof that a
 * config-time CDict is a drop-in replacement for the per-request refPrefix.
 *
 * It is not. With overlapping content -- the case a dcz dictionary exists for
 * -- the paths CAN diverge: libzstd loads a prefix with ZSTD_dtlm_fast and a
 * CDict with ZSTD_dtlm_full, and refCDict searches a separate dictMatchState
 * instead of the merged window, so different matches can be selected. Measured
 * 2026-09-03 on libzstd 1.5.7, 9 of 56 overlapping points diverged while all
 * 56 disjoint points agreed. Representative rows (prefix vs cdict bytes):
 *
 *     level 1,  1 MB dictionary,  256 KB body: 213164 vs 206183
 *     level 3,  4 MB dictionary,  256 KB body: 182892 vs 181012
 *     level 3,  10 MB dictionary, 256 KB body: 249102 vs 248040
 *     level 15, 64 KB dictionary, 256 KB body:    983 vs   1192
 *
 * Three of the nine sit at level 3, this module's default, so the divergence
 * is reachable in a stock deployment rather than only at operator-raised
 * levels. It also runs both ways: at level 15 the CDict path emits MORE bytes,
 * so this is not "one path simply compresses better".
 *
 * The 9-of-56 rate characterises THIS corpus, not a general frequency: how
 * often the paths diverge depends on how much the dictionary matches the body.
 * The finding is that divergence exists at all, not that it is rare.
 *
 * Consequence: hoisting dcz refPrefix to a config-time CDict changes dcz wire
 * output for some inputs. It is a product decision about output stability, not
 * a transparent performance refactor.
 *
 * EXIT STATUS: an OVERLAP mismatch is the documented finding above and is
 * reported without failing (exit 0). A DISJOINT mismatch, in either sweep, is
 * a wire-format regression and exits 1. The two are counted separately on
 * purpose: sharing one counter would let a regression print under the
 * "this is expected" banner and exit 0.
 *
 * Runtime: bounded, single-process, a few seconds total. No server, no
 * soak, no fuzzing.
 *
 * Build: cc -Wall -Wextra -O2 -DZSTD_STATIC_LINKING_ONLY \
 *           dcz_refprefix_cost_bench.c -lzstd -o dcz_refprefix_cost_bench
 * Run:   ./dcz_refprefix_cost_bench
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define LEVEL            3
#define WLOG_MIN         10
#define WLOG_CAP         23
#define WARMUP_ITERS     10
#define TIMED_ITERS      120
#define NOISE_ITERS      120

static const size_t dict_sizes[] = {
    64 * 1024,
    1 * 1024 * 1024,
    4 * 1024 * 1024,
    10 * 1024 * 1024,   /* NGX_HTTP_ZSTD_MAX_DICT_SIZE */
};

static const size_t body_sizes[] = {
    4 * 1024,           /* normal dcz shape: body << dictionary */
    256 * 1024,         /* body larger than the smallest dictionaries */
};

/* Levels swept by the byte-identity check (A33-F1). The timing sweep above
 * stays pinned at LEVEL because its purpose is a per-request cost number at
 * the module's default; identity is a wire-format contract and must hold at
 * every level an operator can configure via zstd_comp_level. */
static const int identity_levels[] = { 1, 3, 6, 9, 12, 15, 19 };

static unsigned
ceil_log2_clamped(size_t v)
{
    unsigned log = 0;
    size_t   x = 1;

    while (x < v && log < 63) {
        x <<= 1;
        log++;
    }
    if (log < WLOG_MIN) {
        log = WLOG_MIN;
    }
    if (log > WLOG_CAP) {
        log = WLOG_CAP;
    }
    return log;
}

/* Deterministic pseudo-content: reproducible across runs, and NOT trivially
 * compressible to zero-length (a real dictionary/body has structure). */
static void
fill_buf(unsigned char *buf, size_t len, uint32_t seed)
{
    size_t   i;
    uint32_t state = seed;

    for (i = 0; i < len; i++) {
        state = state * 1103515245u + 12345u;
        /* bias toward repeats every 37 bytes so the buffer is compressible,
         * like real HTTP bodies/dictionaries, rather than incompressible
         * random noise that would mask table-build cost inside i/o-bound
         * entropy coding. */
        buf[i] = (unsigned char) ((i % 37 == 0) ? (state >> 24) : (state >> 16));
    }
}

static double
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6;
}

static void
check_zstd(size_t rc, const char *operation)
{
    if (ZSTD_isError(rc)) {
        fprintf(stderr, "%s failed: %s\n", operation, ZSTD_getErrorName(rc));
        exit(1);
    }
}

/* Runs the dcz-style refPrefix path `iters` times; returns total ms and
 * (via *out_csize) the compressed size of the LAST iteration, for the
 * byte-identity check. *out_dst receives that last iteration's bytes
 * (caller-owned buffer, at least dstCap). */
static double
bench_prefix(ZSTD_CCtx *cctx, const unsigned char *dict, size_t dictLen,
    const unsigned char *body, size_t bodyLen, unsigned wlog, int iters,
    unsigned char *dst, size_t dstCap, size_t *out_csize)
{
    int      i;
    double   t0, t1;
    size_t   rc = 0;

    if (iters <= 0) {
        fprintf(stderr, "bench_prefix: iters must be positive\n");
        exit(1);
    }

    t0 = now_ms();
    for (i = 0; i < iters; i++) {
        check_zstd(ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters),
                   "CCtx_reset(prefix)");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
                                          LEVEL),
                   "setParameter(prefix level)");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog,
                                          (int) wlog),
                   "setParameter(prefix windowLog)");
        rc = ZSTD_CCtx_refPrefix(cctx, dict, dictLen);
        check_zstd(rc, "refPrefix");
        rc = ZSTD_compress2(cctx, dst, dstCap, body, bodyLen);
        check_zstd(rc, "compress2(prefix)");
    }
    t1 = now_ms();
    *out_csize = rc;
    return t1 - t0;
}

/* Runs the CDict path `iters` times against a CDict built ONCE by the
 * caller (outside this function, outside the timed region) -- that is the
 * entire point of the comparison. */
static double
bench_cdict(ZSTD_CCtx *cctx, ZSTD_CDict *cdict, const unsigned char *body,
    size_t bodyLen, int iters, unsigned char *dst, size_t dstCap,
    size_t *out_csize)
{
    int      i;
    double   t0, t1;
    size_t   rc = 0;

    if (iters <= 0) {
        fprintf(stderr, "bench_cdict: iters must be positive\n");
        exit(1);
    }

    t0 = now_ms();
    for (i = 0; i < iters; i++) {
        check_zstd(ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters),
                   "CCtx_reset(cdict)");
        rc = ZSTD_CCtx_refCDict(cctx, cdict);
        check_zstd(rc, "refCDict");
        rc = ZSTD_compress2(cctx, dst, dstCap, body, bodyLen);
        check_zstd(rc, "compress2(cdict)");
    }
    t1 = now_ms();
    *out_csize = rc;
    return t1 - t0;
}

/* Noise floor: prefix path timed against itself, two disjoint iteration
 * sets. Establishes the threshold a real prefix-vs-cdict effect must clear
 * before it can be trusted. Returns 0 on success, 1 on allocation failure. */
static int
run_noise_floor(ZSTD_CCtx *cctx, unsigned char *scratch, size_t dstCap)
{
    size_t  di;

    printf("== noise floor (identical prefix path, two disjoint iter sets) ==\n");
    printf("%-10s %-10s %10s %10s %8s\n",
           "dict", "body", "run_a_ms", "run_b_ms", "delta%");

    for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]); di++) {
        size_t          dictLen = dict_sizes[di];
        size_t          bodyLen = body_sizes[0];
        unsigned        wlog = ceil_log2_clamped(dictLen + bodyLen);
        double          ms_a, ms_b, delta_pct;
        size_t          csz;
        unsigned char  *dict, *body;
        int             w;

        dict = malloc(dictLen);
        body = malloc(bodyLen);
        if (dict == NULL || body == NULL) {
            fprintf(stderr, "alloc failed (dictLen=%zu bodyLen=%zu)\n",
                    dictLen, bodyLen);
            free(dict);
            free(body);
            return 1;
        }
        fill_buf(dict, dictLen, 0xD1C7);
        fill_buf(body, bodyLen, 0xB0D7);

        for (w = 0; w < WARMUP_ITERS; w++) {
            check_zstd(ZSTD_CCtx_reset(cctx,
                                       ZSTD_reset_session_and_parameters),
                       "CCtx_reset(noise warmup)");
            check_zstd(ZSTD_CCtx_setParameter(cctx,
                                              ZSTD_c_compressionLevel,
                                              LEVEL),
                       "setParameter(noise level)");
            check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog,
                                              (int) wlog),
                       "setParameter(noise windowLog)");
            check_zstd(ZSTD_CCtx_refPrefix(cctx, dict, dictLen),
                       "refPrefix(noise warmup)");
            check_zstd(ZSTD_compress2(cctx, scratch, dstCap, body, bodyLen),
                       "compress2(noise warmup)");
        }

        ms_a = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                             NOISE_ITERS, scratch, dstCap, &csz);
        ms_b = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                             NOISE_ITERS, scratch, dstCap, &csz);
        delta_pct = 100.0 * (ms_b - ms_a) / ms_a;

        printf("%-10zu %-10zu %10.3f %10.3f %+7.1f%%\n",
               dictLen, bodyLen, ms_a, ms_b, delta_pct);

        free(dict);
        free(body);
    }

    return 0;
}

/* One sweep point: measure the prefix path and the cdict path at the same
 * (dictLen, bodyLen), and check the compressed bytes match. Returns 1 if
 * the two paths mismatched (byte-identity failure), 0 if they matched;
 * exits the process on allocation/library failure. */
static int
run_sweep_point(ZSTD_CCtx *cctx, size_t dictLen, size_t bodyLen,
    uint32_t seed_salt, unsigned char *dst_a, unsigned char *dst_b,
    size_t dstCap)
{
    unsigned                     wlog = ceil_log2_clamped(dictLen + bodyLen);
    double                       ms_prefix, ms_cdict, per_op_prefix,
                                 per_op_cdict;
    size_t                       csz_prefix, csz_cdict;
    unsigned char               *dict, *body;
    ZSTD_CDict                  *cdict;
    ZSTD_compressionParameters   cparams;
    int                          identical, w;

    dict = malloc(dictLen);
    body = malloc(bodyLen);
    if (dict == NULL || body == NULL) {
        fprintf(stderr, "alloc failed (dictLen=%zu bodyLen=%zu)\n",
                dictLen, bodyLen);
        exit(1);
    }
    fill_buf(dict, dictLen, 0xD1C7 + seed_salt);
    fill_buf(body, bodyLen, 0xB0D7 + seed_salt);

    for (w = 0; w < WARMUP_ITERS; w++) {
        check_zstd(ZSTD_CCtx_reset(cctx,
                                   ZSTD_reset_session_and_parameters),
                   "CCtx_reset(prefix warmup)");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
                                          LEVEL),
                   "setParameter(prefix warmup level)");
        check_zstd(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog,
                                          (int) wlog),
                   "setParameter(prefix warmup windowLog)");
        check_zstd(ZSTD_CCtx_refPrefix(cctx, dict, dictLen),
                   "refPrefix(warmup)");
        check_zstd(ZSTD_compress2(cctx, dst_a, dstCap, body, bodyLen),
                   "compress2(prefix warmup)");
    }

    ms_prefix = bench_prefix(cctx, dict, dictLen, body, bodyLen, wlog,
                              TIMED_ITERS, dst_a, dstCap, &csz_prefix);

    /* Build the CDict ONCE, outside the timed region -- this is the
     * amortisation the fix direction proposes. dct_rawContent preserves
     * RFC 9842 raw-prefix wire semantics (module comment near
     * ZSTD_CCtx_refPrefix's call site). */
    cparams = ZSTD_getCParams(LEVEL, (unsigned long long) bodyLen, dictLen);
    cparams.windowLog = wlog;
    cdict = ZSTD_createCDict_advanced(dict, dictLen, ZSTD_dlm_byRef,
                                       ZSTD_dct_rawContent, cparams,
                                       ZSTD_defaultCMem);
    if (cdict == NULL) {
        fprintf(stderr, "ZSTD_createCDict_advanced failed\n");
        exit(1);
    }

    for (w = 0; w < WARMUP_ITERS; w++) {
        check_zstd(ZSTD_CCtx_reset(cctx,
                                   ZSTD_reset_session_and_parameters),
                   "CCtx_reset(cdict warmup)");
        check_zstd(ZSTD_CCtx_refCDict(cctx, cdict),
                   "refCDict(warmup)");
        check_zstd(ZSTD_compress2(cctx, dst_b, dstCap, body, bodyLen),
                   "compress2(cdict warmup)");
    }

    ms_cdict = bench_cdict(cctx, cdict, body, bodyLen, TIMED_ITERS, dst_b,
                            dstCap, &csz_cdict);

    per_op_prefix = ms_prefix / TIMED_ITERS;
    per_op_cdict = ms_cdict / TIMED_ITERS;

    identical = (csz_prefix == csz_cdict)
                && (memcmp(dst_a, dst_b, csz_prefix) == 0);

    printf("%-10zu %-10zu %5u %12.4f %12.4f %10.4f %10s\n",
           dictLen, bodyLen, wlog, per_op_prefix, per_op_cdict,
           per_op_prefix - per_op_cdict, identical ? "yes" : "NO -- MISMATCH");

    ZSTD_freeCDict(cdict);
    free(dict);
    free(body);

    return identical ? 0 : 1;
}

/* Builds a body out of slices of the dictionary, so the dictionary actually
 * MATCHES the content. The timing sweep's fill_buf() seeds dictionary and body
 * from two different constants, which makes them statistically unrelated: the
 * compressor finds no cross-matches, never exercises the dictMatchState search
 * path, and so the two code paths agree trivially. A real dcz dictionary is
 * chosen precisely because it resembles the response, so identity has to be
 * checked against overlapping content or it is checked against nothing. */
static void
fill_buf_overlapping(unsigned char *body, size_t bodyLen,
    const unsigned char *dict, size_t dictLen)
{
    size_t   off = 0, chunk, src, step = 0;

    /* Vary the slice length across iterations. Deriving it from `off` alone
     * self-stabilises (off advances by exactly the chunk it produced, so the
     * modulo pins to one value after the first step); stepping a counter
     * keeps the lengths moving. */
    while (off < bodyLen) {
        chunk = 512 + (step % 1024);
        step += 397;

        if (chunk > bodyLen - off) {
            chunk = bodyLen - off;
        }

        /* Every dict_sizes[] entry is >= 64 KB and chunk <= 1535, so the
         * else-branch is unreachable today; it keeps the copy in bounds if a
         * smaller dictionary is ever added to the sweep. */
        src = (dictLen > chunk) ? (off * 7919) % (dictLen - chunk) : 0;

        memcpy(body + off, dict + src, chunk);
        off += chunk;
    }
}

/* One byte-identity point: compress the same body twice at the same level and
 * windowLog, once via the dcz per-request refPrefix path and once via the
 * hoisted refCDict(dct_rawContent) path the A33-F1 fix direction proposes.
 * Both paths receive the same fully specified compression parameters, so a
 * mismatch isolates dictionary-loading behavior rather than parameter
 * derivation. Returns 1 on mismatch. Untimed: this is a correctness oracle,
 * not a bench. */
static int
run_identity_point(ZSTD_CCtx *cctx, int level, size_t dictLen, size_t bodyLen,
    int overlap, unsigned char *dst_a, unsigned char *dst_b, size_t dstCap)
{
    unsigned                     wlog = ceil_log2_clamped(dictLen + bodyLen);
    size_t                       csz_a, csz_b;
    unsigned char               *dict, *body;
    ZSTD_CDict                  *cdict;
    ZSTD_compressionParameters   cparams;
    int                          identical;

    dict = malloc(dictLen);
    body = malloc(bodyLen);
    if (dict == NULL || body == NULL) {
        fprintf(stderr, "alloc failed (dictLen=%zu bodyLen=%zu)\n",
                dictLen, bodyLen);
        exit(1);
    }

    fill_buf(dict, dictLen, 0xD1C7);
    if (overlap) {
        fill_buf_overlapping(body, bodyLen, dict, dictLen);
    } else {
        fill_buf(body, bodyLen, 0xB0D7);
    }

    cparams = ZSTD_getCParams(level, (unsigned long long) bodyLen, dictLen);
    cparams.windowLog = wlog;

    check_zstd(ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters),
               "CCtx_reset(identity prefix)");
    check_zstd(ZSTD_CCtx_setCParams(cctx, cparams),
               "setCParams(identity prefix)");
    check_zstd(ZSTD_CCtx_refPrefix(cctx, dict, dictLen),
               "refPrefix(identity)");
    csz_a = ZSTD_compress2(cctx, dst_a, dstCap, body, bodyLen);
    check_zstd(csz_a, "compress2(identity prefix)");

    cdict = ZSTD_createCDict_advanced(dict, dictLen, ZSTD_dlm_byRef,
                                       ZSTD_dct_rawContent, cparams,
                                       ZSTD_defaultCMem);
    if (cdict == NULL) {
        fprintf(stderr, "ZSTD_createCDict_advanced failed\n");
        exit(1);
    }

    check_zstd(ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters),
               "CCtx_reset(identity cdict)");
    check_zstd(ZSTD_CCtx_refCDict(cctx, cdict), "refCDict(identity)");
    csz_b = ZSTD_compress2(cctx, dst_b, dstCap, body, bodyLen);
    check_zstd(csz_b, "compress2(identity cdict)");

    identical = (csz_a == csz_b) && (memcmp(dst_a, dst_b, csz_a) == 0);

    printf("%-9s %-5d %-10zu %-10zu %5u %10zu %10zu %14s\n",
           overlap ? "overlap" : "disjoint", level, dictLen, bodyLen, wlog,
           csz_a, csz_b, identical ? "identical" : "MISMATCH");

    ZSTD_freeCDict(cdict);
    free(dict);
    free(body);

    return identical ? 0 : 1;
}

/* Sweeps byte identity across the level axis in both content modes.
 *
 * The two modes are counted SEPARATELY, into *disjoint_out and *overlap_out.
 * They mean opposite things: disjoint content must agree (a mismatch there is
 * a wire-format regression), while overlapping content is where divergence is
 * the documented finding. Folding them into one number lets a regression be
 * reported as the expected finding and exit 0. */
static void
run_identity_sweep(ZSTD_CCtx *cctx, unsigned char *dst_a, unsigned char *dst_b,
    size_t dstCap, int *disjoint_out, int *overlap_out)
{
    size_t   li, di, bi;
    int      overlap, mismatch;

    *disjoint_out = 0;
    *overlap_out = 0;

    printf("\n== byte identity: refPrefix vs refCDict(dct_rawContent), "
           "level axis, both content modes ==\n");
    printf("%-9s %-5s %-10s %-10s %5s %10s %10s %14s\n",
           "content", "level", "dict", "body", "wlog", "prefix_sz",
           "cdict_sz", "identical");

    for (overlap = 0; overlap < 2; overlap++) {
        for (li = 0;
             li < sizeof(identity_levels) / sizeof(identity_levels[0]);
             li++)
        {
            for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]);
                 di++)
            {
                for (bi = 0;
                     bi < sizeof(body_sizes) / sizeof(body_sizes[0]);
                     bi++)
                {
                    mismatch = run_identity_point(cctx,
                                                  identity_levels[li],
                                                  dict_sizes[di],
                                                  body_sizes[bi],
                                                  overlap, dst_a, dst_b,
                                                  dstCap);
                    if (overlap) {
                        *overlap_out += mismatch;
                    } else {
                        *disjoint_out += mismatch;
                    }
                }
            }
        }
    }
}

int
main(void)
{
    size_t          di, bi;
    unsigned char  *dst_a, *dst_b, *dst_noise;
    size_t          dstCap;
    ZSTD_CCtx      *cctx;
    int             timing_mismatches = 0;
    int             identity_disjoint_mismatches = 0;
    int             identity_overlap_mismatches = 0;
    int             disjoint_mismatches;

    printf("A31b-F2 dcz refPrefix per-request cost -- microbenchmark\n");
    printf("libzstd %s, level %d, %d warmup + %d timed iters per point\n\n",
           ZSTD_versionString(), LEVEL, WARMUP_ITERS, TIMED_ITERS);

    cctx = ZSTD_createCCtx();
    if (cctx == NULL) {
        fprintf(stderr, "ZSTD_createCCtx failed\n");
        return 1;
    }

    dstCap = ZSTD_compressBound(10 * 1024 * 1024 + 256 * 1024);
    dst_a = malloc(dstCap);
    dst_b = malloc(dstCap);
    dst_noise = malloc(dstCap);
    if (dst_a == NULL || dst_b == NULL || dst_noise == NULL) {
        fprintf(stderr, "alloc failed\n");
        free(dst_a);
        free(dst_b);
        free(dst_noise);
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    if (run_noise_floor(cctx, dst_noise, dstCap) != 0) {
        free(dst_a);
        free(dst_b);
        free(dst_noise);
        ZSTD_freeCCtx(cctx);
        return 1;
    }

    printf("\n== prefix vs cdict sweep (per-op ms; refPrefix/refCDict setup only,\n");
    printf("   CDict itself built ONCE outside the timed loop) ==\n");
    printf("%-10s %-10s %5s %12s %12s %10s %10s\n",
           "dict", "body", "wlog", "prefix_ms/op", "cdict_ms/op",
           "delta_ms/op", "identical");

    for (di = 0; di < sizeof(dict_sizes) / sizeof(dict_sizes[0]); di++) {
        for (bi = 0; bi < sizeof(body_sizes) / sizeof(body_sizes[0]); bi++) {
            timing_mismatches += run_sweep_point(cctx, dict_sizes[di],
                                          body_sizes[bi], (uint32_t) (di * 8U + bi),
                                          dst_a, dst_b, dstCap);
        }
    }

    run_identity_sweep(cctx, dst_a, dst_b, dstCap,
                       &identity_disjoint_mismatches,
                       &identity_overlap_mismatches);

    /* Every disjoint-content point, in either sweep, must agree. */
    disjoint_mismatches = timing_mismatches + identity_disjoint_mismatches;

    ZSTD_freeCCtx(cctx);
    free(dst_a);
    free(dst_b);
    free(dst_noise);

    printf("\n");

    /* The two sweeps mean opposite things, so they must not share a verdict.
     *
     * The timing sweep runs disjoint content only, where both paths are
     * expected to agree. A mismatch there is a genuine wire-format
     * regression and still fails the program.
     *
     * The identity sweep deliberately includes overlapping content, where
     * divergence is the documented finding rather than a fault, so a
     * mismatch there is reported and the program still exits 0. */

    if (identity_overlap_mismatches > 0) {
        printf("BYTE IDENTITY: NOT UNIVERSAL -- %d overlapping-content "
               "point(s) produced different compressed bytes between "
               "refPrefix and refCDict(dct_rawContent).\n\n"
               "This is the documented finding, not a failure. Hoisting the "
               "dcz per-request refPrefix() to a config-time CDict is a\n"
               "WIRE-FORMAT CHANGE, not a transparent optimisation: libzstd "
               "loads a prefix with ZSTD_dtlm_fast and a CDict with\n"
               "ZSTD_dtlm_full, and refCDict searches a separate "
               "dictMatchState rather than the merged window, so the two\n"
               "paths can select different matches whenever the dictionary "
               "actually matches the body. Such a change needs an explicit\n"
               "product decision about dcz output stability.\n",
               identity_overlap_mismatches);
    } else {
        printf("BYTE IDENTITY: no mismatch observed in this sweep. That is "
               "NOT a general guarantee -- identity is sensitive to how much "
               "the dictionary actually matches the body.\n");
    }

    if (disjoint_mismatches > 0) {
        printf("\nDISJOINT IDENTITY: FAILED -- %d point(s) diverged on "
               "unrelated dictionary and body content, where both paths must "
               "agree (%d in the timing sweep, %d in the identity sweep).\n"
               "That is a wire-format regression, not the overlap finding "
               "above.\n",
               disjoint_mismatches, timing_mismatches,
               identity_disjoint_mismatches);
        return 1;
    }

    return 0;
}
