
/*
 * Copyright (C) Alex Zhang
 * Copyright (C) 2026 Thijs Eilander
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>

#include <limits.h>  /* INT_MAX — config-load bound on (int)-narrowed sizes */
#include <stdint.h>  /* SIZE_MAX — saturating dcz window-log arithmetic */

#include "ngx_http_zstd_common.h"
#include "ngx_http_zstd_cache_control.h"
#include "ngx_http_zstd_sha256.h"
#include "ngx_http_zstd_version.h"
#include "ngx_http_zstd_ratio.h"

#ifdef NGX_TEST_HARNESS
#include "ngx_http_zstd_probe_hooks.h"
#endif


/*
 * Pool-allocation wrappers for the per-REQUEST allocation sites in this
 * file (the ones reached while serving a compressed response). They exist
 * solely so a test can fail one chosen allocation and assert that the
 * branch handling it is correct; see ngx_http_zstd_probe_hooks.h's
 * fault_palloc block for the arming contract and the counting rules.
 *
 * COST IN A PACKAGED BUILD IS EXACTLY ZERO -- not "one predictable
 * branch", zero. Without NGX_TEST_HARNESS each macro expands to the bare
 * allocator call it wraps, so the preprocessor leaves the identical token
 * sequence the code had before the wrappers existed and the compiler sees
 * no fault site at all. That is why these are macros and not functions
 * with an internal guard: a function would still be a call the optimizer
 * has to reason about, and the hot path must not pay for a test feature.
 *
 * CONFIG-TIME sites (cf->pool) are deliberately NOT wrapped. They run once
 * at startup, their failure mode is "nginx refuses to start" rather than a
 * mid-request branch, and arming a fault that fires during configuration
 * would break the probe endpoint itself before any test could use it.
 */
#ifdef NGX_TEST_HARNESS

#define ngx_http_zstd_palloc(pool, size)                                     \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_palloc(pool, size))

#define ngx_http_zstd_pnalloc(pool, size)                                    \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_pnalloc(pool, size))

#define ngx_http_zstd_pcalloc(pool, size)                                    \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_pcalloc(pool, size))

#define ngx_http_zstd_alloc_chain_link(pool)                                 \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_alloc_chain_link(pool))

#define ngx_http_zstd_list_push(list)                                        \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_list_push(list))

#define ngx_http_zstd_pool_cleanup_add(pool, size)                           \
    (ngx_http_zstd_probe_palloc_should_fail()                                \
        ? NULL : ngx_pool_cleanup_add(pool, size))

#else

#define ngx_http_zstd_palloc(pool, size)          ngx_palloc(pool, size)
#define ngx_http_zstd_pnalloc(pool, size)         ngx_pnalloc(pool, size)
#define ngx_http_zstd_pcalloc(pool, size)         ngx_pcalloc(pool, size)
#define ngx_http_zstd_alloc_chain_link(pool)      ngx_alloc_chain_link(pool)
#define ngx_http_zstd_list_push(list)             ngx_list_push(list)
#define ngx_http_zstd_pool_cleanup_add(pool, size)                            \
    ngx_pool_cleanup_add(pool, size)

#endif


/*
 * Compute the ceiling of log₂(x) for a size_t value: the minimum k such that
 * 2^k >= x. Used for window-log sizing in dcz frame setup, where we must fit
 * a dictionary and expected content within a power-of-two decompression window.
 *
 * Portable implementation: handles all size_t values, including edge cases.
 * For x <= 2^10: returns 10 (ZSTD_WINDOWLOG_MIN). For x >= 2^23: caps at 23
 * (RFC 9842 client-guarantee limit).
 *
 * On platforms with __builtin_clzll (GCC, Clang), uses the compiler builtin
 * for O(1) bit-position lookup. On other platforms (MSVC, others), falls back
 * to a linear shift-and-count loop (at most 13 iterations in range).
 *
 * Result: 10 <= returned wlog <= 23 always (respects min and cap).
 */
static ngx_inline ngx_uint_t
ngx_http_zstd_ceil_log2(size_t x)
{
    ngx_uint_t  wlog;

#if (defined(__GNUC__) || defined(__clang__)) \
    && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    unsigned long long  ull;
    int                 leading_zeros;
#else
    size_t              pow2;
#endif

    if (x <= 1024) {  /* 2^10 */
        return 10;
    }

    if (x > ((size_t) 1 << 23)) {
        return 23;  /* RFC 9842 cap */
    }

#if (defined(__GNUC__) || defined(__clang__)) \
    && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    /* Use compiler builtin for count-leading-zeros on 64-bit. GCC and Clang
     * both provide __builtin_clzll; __builtin_clz is 32-bit but we require
     * 64-bit size_t here. The bit length (64 - leading_zeros) is exactly
     * ceil-log2 for non-powers-of-two, and one too many for exact powers of
     * two -- so the only correction needed is a decrement in that case. */
    ull = (unsigned long long) x;
    leading_zeros = __builtin_clzll(ull);
    wlog = 64 - leading_zeros;

    if ((ull & (ull - 1)) == 0) {
        /* Exact power of two: bit length is one too many. */
        wlog--;
    }

    return wlog;
#else
    /* Fallback: linear shift-and-count to find the highest set bit position.
     * At most 13 iterations for size_t values in our range (1025 to 2^23).
     * Its declarations stay at function scope for C89/MSVC compatibility. */
    wlog = 10;
    pow2 = 1024;  /* 2^10 */

    while (pow2 < x && wlog < 23) {
        pow2 <<= 1;
        wlog++;
    }

    return wlog;
#endif
}


static ngx_inline u_char
ngx_http_zstd_hex_nibble(u_char c)
{
    u_char  lower;

    if (c >= '0' && c <= '9') {
        return (u_char) (c - '0');
    }

    lower = (u_char) (c | 0x20);

    if (lower >= 'a' && lower <= 'f') {
        return (u_char) (lower - 'a' + 10);
    }

    return 0xff;
}


/*
 * The ONLY sanctioned way to hash a dcz dictionary at config load: the
 * $zstd_dcz_dicts_hashed accounting is inseparable from the operation.
 * An increment sitting beside a call site counts that line running, not
 * a dictionary being hashed — a restored unconditional bare call in
 * front of the supplied-hash branch slid past the counter tests
 * untouched (review of #103, demonstrated on a planted build). The bare
 * identifier is poisoned below, so reintroducing a direct call is a
 * compile error rather than a silent under-count.
 */
static ngx_inline void
ngx_http_zstd_dcz_dict_hash(const u_char *data, size_t len,
    u_char digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN], ngx_uint_t *hashed,
    void *evp_md_ctx)
{
    ngx_http_zstd_sha256(data, len, digest, evp_md_ctx);
    (*hashed)++;
}

#if defined(__GNUC__)
#pragma GCC poison ngx_http_zstd_sha256
#endif


#define NGX_HTTP_ZSTD_MAX_DICT_SIZE  (10 * 1024 * 1024)  /* 10 MB limit */

/*
 * Stand-in body size when the response length is unknown, used only to size
 * the CCtx window estimate -- see the ring-key discussion below.
 */
#define NGX_HTTP_ZSTD_UNKNOWN_SIZE_GUESS  (1024 * 1024)

/*
 * ZSTD_compressBound() covers the compressed payload only; pad it by
 * _FRAME_SLACK for libzstd's frame and block headers, and never size an
 * output buffer below _MIN so a tiny or empty body still gets a buffer the
 * frame overhead fits inside.
 */
#define NGX_HTTP_ZSTD_BOUND_FRAME_SLACK  64
#define NGX_HTTP_ZSTD_BOUND_MIN          256

/*
 * Highest response status the filter will encode. 3xx and above carry no
 * body worth encoding, except the 403/404 error pages excluded separately.
 */
#define NGX_HTTP_ZSTD_MAX_ELIGIBLE_STATUS  299

/*
 * RFC 9842 §2.2 dcz framing: an 8-byte zstd skippable-frame header
 * (magic 0x184D2A5E and frame-size 32, both little-endian on the wire)
 * followed by the 32-byte SHA-256 of the dictionary, prepended to an
 * ordinary zstd frame. Existing zstd decoders skip it by design, so
 * `zstd -d -D <dict>` decodes a dcz body as-is.
 */
#define NGX_HTTP_ZSTD_DCZ_HEADER_LEN  (8 + NGX_HTTP_ZSTD_SHA256_DIGEST_LEN)

/*
 * ngx_http_zstd_dcz_decode_digest()'s scratch/output buffer size. Must
 * stay >= 48: an Available-Dictionary byte-sequence up to the 44-char
 * length ceiling can carry unpadded base64 that decodes to 33 bytes
 * (one past NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) before the post-decode
 * length check runs, so the destination buffer must have that headroom.
 */
#define NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN  48

/* Padded standard-base64 length of a 32-byte SHA-256 (43 unpadded). */
#define NGX_HTTP_ZSTD_DCZ_DIGEST_B64_LEN  44

/*
 * RFC 9842 §2.2.2: a dcz client guarantees a decode window of at least
 * max(8 MB, 1.25 x dictionary size). Never exceeding 2^23 (8 MB) keeps
 * every emitted frame inside the guarantee for any dictionary size, so
 * the module does not need to reason about the 1.25x branch.
 */
#define NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG  23

/*
 * ZSTD_WINDOWLOG_MIN, spelled without the libzstd macro: that name lives in
 * the experimental (ZSTD_STATIC_LINKING_ONLY) section, and this floor has to
 * hold on the non-static build too. ngx_http_zstd_ceil_log2() already
 * returns nothing below it; the constant exists so the clamps cannot go
 * under it either.
 */
#define NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG  10

/*
 * Threshold for switching the per-request dcz negotiation lookup from a
 * linear ngx_memcmp scan to a binary search over zlcf->dcz_dicts (sorted
 * once, at merge-config time, by ngx_http_zstd_dcz_dict_cmp()).
 *
 * Small arrays retain the simple contiguous linear scan; larger arrays
 * use O(log n) comparisons. The threshold is deliberately conservative
 * and is guarded by the differential fixture.
 */
#define NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD  16


/*
 * The effective ZSTD_c_windowLog for a dcz (RFC 9842 dictionary-compressed)
 * response. Pure arithmetic, no libzstd and no request state, because the
 * SAME value has to be computed in two places that must never disagree:
 *
 *   1. ngx_http_zstd_acquire_cctx(), BEFORE the CCtx ring key is packed --
 *      the slot a request borrows is keyed on the window it will actually
 *      use, not on zstd_window_log alone. Keying on the unset directive let
 *      a dcz request borrow a slot vetted for the default window and then
 *      permanently raise that slot's retained workspace (ZSTD_sizeof_CCtx()
 *      does not shrink on reset), so every later plain request mapped to the
 *      same key inherited the dcz floor -- exactly the contamination the
 *      three-field key documented at the ring exists to prevent.
 *
 *   2. ngx_http_zstd_filter_init_cctx(), where the value is pushed into
 *      libzstd.
 *
 * The window sizing itself: the window must reach back across the whole
 * prefix from the end of the content or the far end of the dictionary stops
 * matching, so it is sized to dictionary + expected content (a 1 MB guess
 * when the length is unknown), rounded up to a power of two and capped by
 * ngx_http_zstd_ceil_log2() at NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG.
 *
 * Two operator ceilings clamp it back down, and both are ceilings of the
 * SAME class -- a memory bound the operator asked for, which a dictionary
 * must not silently void (that was audit C2/R1's lesson with the CDict
 * path):
 *
 *   - "zstd_window_log" (conf_window_log > 0): the pre-existing clamp,
 *     unchanged.
 *   - "zstd_max_cctx_memory" (budget_window_cap > 0): the largest window log
 *     whose estimated CCtx memory still fits the budget, computed ONCE at
 *     config load by ngx_http_zstd_dcz_window_cap(). Without this the
 *     nginx -t gate vets a figure the dcz path then exceeds at request time
 *     (measured, libzstd 1.5.7, level 3: 3 663 393 B at the default window
 *     vs 9 954 849 B at wlog 23 -- 2.72x).
 *
 * Both ceilings are OPT-IN. With neither directive set -- the default
 * configuration -- no clamp applies and the dcz window is exactly what it
 * was before this function existed. That scoping is deliberate: the fix
 * changes dcz wire bytes only for operators who explicitly asked for a
 * memory bound.
 *
 * The result is always in [10, 23] -- ZSTD_WINDOWLOG_MIN to
 * NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG -- so it is always inside
 * ngx_http_zstd_profile_pack()'s 6-bit window_log field and never trips
 * that packer's domain assert.
 */
static ngx_inline ngx_int_t
ngx_http_zstd_dcz_window_log(size_t dict_len, off_t pledged_size,
    ngx_int_t conf_window_log, ngx_int_t budget_window_cap)
{
    size_t     required, pledged_contribution;
    ngx_int_t  wlog;

    /*
     * pledged_size is upstream-controlled (r->headers_out.content_length_n,
     * an off_t that can exceed SIZE_MAX on an ILP32 build, and can be large
     * enough on any build to overflow the addition below). ceil_log2()
     * already saturates any size_t at NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG, so
     * saturating the cast and the sum here -- rather than letting either
     * wrap -- is enough to keep a hostile content-length from producing a
     * small "required" and hence a wrong (too small) window log and ring
     * key. Saturating at SIZE_MAX is deliberately coarse: ceil_log2() caps
     * everything above 2^23 the same way, so no finer clamp is needed.
     */
    if (pledged_size < 0) {
        pledged_contribution = NGX_HTTP_ZSTD_UNKNOWN_SIZE_GUESS;

    } else if (sizeof(off_t) > sizeof(size_t)
               && (uintmax_t) pledged_size > (uintmax_t) SIZE_MAX)
    {
        /* off_t wider than size_t (ILP32): a cast down would truncate. */
        pledged_contribution = SIZE_MAX;

    } else {
        pledged_contribution = (size_t) pledged_size;
    }

    required = dict_len + pledged_contribution;
    if (required < dict_len) {
        required = SIZE_MAX;
    }

    wlog = (ngx_int_t) ngx_http_zstd_ceil_log2(required);

    if (conf_window_log > 0 && conf_window_log < wlog) {
        wlog = conf_window_log;
    }

    if (budget_window_cap > 0 && budget_window_cap < wlog) {
        wlog = budget_window_cap;
    }

    /*
     * Floor, as defence in depth. Both ceilings are already constrained to
     * >= 10 by their producers -- zstd_window_log is validated against
     * ZSTD_cParam_getBounds(ZSTD_c_windowLog), whose lowerBound is
     * ZSTD_WINDOWLOG_MIN, and ngx_http_zstd_dcz_window_cap()'s search is
     * bounded below by the same constant -- so this cannot fire today. It
     * is here because the [10, 23] postcondition is what keeps the value
     * inside ngx_http_zstd_profile_pack()'s window_log field, and that
     * guarantee should rest on this function rather than on two validators
     * in other files staying correct. A future bound change that let a
     * smaller ceiling through would otherwise push an invalid windowLog
     * into libzstd and a domain-refused key into the ring.
     */
    if (wlog < NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG) {
        wlog = NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG;
    }

    return wlog;
}


/*
 * ZSTD_MAX_INPUT_SIZE is not declared by every libzstd this module
 * supports -- it postdates the 1.4.x floor, and the "libzstd 1.4.x --
 * fallback paths" CI leg builds against a header without it. Define
 * exactly what upstream zstd.h defines, and only when the header did not,
 * so a newer libzstd's own definition always wins: the width-dependent
 * input ceiling at or above which ZSTD_compressBound() returns 0 rather
 * than a bound.
 */
#ifndef ZSTD_MAX_INPUT_SIZE
#define ZSTD_MAX_INPUT_SIZE \
    ((sizeof(size_t) == 8) ? 0xFF00FF00FF00FF00ULL : 0xFF00FF00U)
#endif


/*
 * Is a pledged (upstream-declared) body length usable, at FULL off_t width,
 * as the ZSTD_compressBound() input that sizes the first output buffer?
 *
 * ctx->pledged_size is r->headers_out.content_length_n -- an off_t, and
 * upstream-controlled. ZSTD_compressBound() takes a size_t. On an ILP32
 * build with large-file support (32-bit size_t, 64-bit off_t, the usual
 * shape once _FILE_OFFSET_BITS=64 is in effect) a bare `(size_t)` cast is
 * a TRUNCATION: a pledge of 4 GiB + 389 narrows to 389, ZSTD_compressBound()
 * returns a bound around 389, the clamp below accepts it as smaller than
 * the configured buffer size, and the first output buffer is allocated
 * three orders of magnitude too small for the body it was sized for. That
 * is a heap overflow waiting on libzstd's next write, not a missed
 * optimization.
 *
 * Two independent reasons to decline, checked at full width so neither can
 * be lost to the very narrowing it is guarding:
 *
 *   1. NOT REPRESENTABLE. sizeof(off_t) > sizeof(size_t) and the value
 *      exceeds SIZE_MAX. Compared through uintmax_t, which is at least as
 *      wide as both, after the caller has established pledged_size >= 0.
 *      The sizeof() test is a compile-time constant, so on an LP64 build
 *      the whole comparison folds away and this costs nothing.
 *
 *   2. ABOVE ZSTD's OWN INPUT CEILING. ZSTD_compressBound() returns 0 --
 *      an error, not a bound -- for srcSize >= ZSTD_MAX_INPUT_SIZE. A 0
 *      propagating into the clamp would be *worse* than truncation: it
 *      floors to NGX_HTTP_ZSTD_BOUND_MIN and pins the buffer at 256 bytes.
 *      ZSTD_MAX_INPUT_SIZE is itself width-dependent (0xFF00FF00 when
 *      size_t is 32-bit, 0xFF00FF00FF00FF00 when it is 64-bit), which is
 *      exactly why this must be asked of the real constant rather than of
 *      a hardcoded 64-bit literal.
 *
 * Declining is always SAFE, never merely conservative: the caller's only
 * use of the bound is to SHRINK buf_size below the configured
 * zlcf->bufs.size. Declining leaves the configured size in place, i.e. the
 * exact geometry every non-first buffer and every unknown-length response
 * already uses. It costs one over-allocation on a response whose declared
 * length is at least 4 GiB -- and it must not be reached for any smaller
 * one, or it would disable the first-buffer optimization that is the whole
 * point of the call site.
 *
 * On success *out receives the full-width value, losslessly narrowed.
 */
static ngx_inline ngx_uint_t
ngx_http_zstd_pledge_to_bound_input(off_t pledged_size, size_t *out)
{
    if (pledged_size < 0) {
        return 0;
    }

    if (sizeof(off_t) > sizeof(size_t)
        && (uintmax_t) pledged_size > (uintmax_t) SIZE_MAX)
    {
        return 0;
    }

    /*
     * Now known representable, so the cast is lossless and the remaining
     * comparison can be made in size_t against zstd's real ceiling.
     */
    if ((size_t) pledged_size >= (size_t) ZSTD_MAX_INPUT_SIZE) {
        return 0;
    }

    *out = (size_t) pledged_size;
    return 1;
}


typedef struct {
    ngx_str_t                    dict_file;
    /* explicit opt-in for the non-RFC-9842 dict mode; S1/RFC1 */
    ngx_flag_t                   dict_unsafe;

    /*
     * Trust policy for both dictionary loaders (zstd_dict_file and
     * zstd_dcz_dict_file). Default off preserves existing deployments
     * that point at a release symlink (a legitimate, common layout);
     * "on" opens with O_NOFOLLOW and rejects a target writable by group
     * or other, on the theory that a root master reloading on a timer
     * should not snapshot bytes a less-privileged local writer can
     * still influence. See ngx_http_zstd_open_dict_file().
     */
    ngx_flag_t                   dict_strict_path;

    /*
     * Set by ngx_http_zstd_dcz_dict_file() the first time it loads a
     * dcz dictionary while dict_strict_path still reads as anything
     * other than the explicit "on" (1) at that moment in the parse --
     * i.e. every load that ran BEFORE a LATER "zstd_dict_strict_path
     * on;" line could apply to it. ngx_conf_parse() runs top-to-bottom,
     * so this is exactly the ordering hazard: nginx directives are
     * conventionally order-independent, so an operator has no cue that
     * this one must precede zstd_dcz_dict_file. Silently treating that
     * dictionary as "strict passed" would fail OPEN -- confirmed live:
     * a world-writable dictionary loaded with zstd_dict_strict_path on
     * declared AFTER the dcz directive passed with no error. Rather
     * than defer the strict-mode fstat() checks to init_main_conf()
     * (which would mean re-opening every dcz dictionary by path a
     * second time there, reintroducing exactly the TOCTOU window this
     * helper exists to close), init_main_conf() rejects the ordering
     * outright when it turns out to matter: see the check there.
     */
    ngx_flag_t                   dcz_dict_loaded_before_strict_on;

    /* First such path, for the ordering-rejection error message. */
    ngx_str_t                    dcz_dict_loaded_before_strict_on_file;

    /*
     * zstd_dcz_dict_trust_hashes: opt OUT of verifying a supplied
     * hash literal against the file's bytes and use it verbatim as
     * the negotiation key, skipping the load-time SHA-256 entirely.
     * Default off = the verify-always behaviour: a mismatch is a
     * config error, which protects a pipeline whose config generation
     * and file placement are decoupled (config stamped with file A's
     * hash, a later stage ships file B).
     *
     * The opt-in exists because the hashing pass IS the config-load
     * cost at scale: measured on a production config with 737
     * dictionary lines, nginx -t runs 5.10s with the verify pass
     * (4.26s user -- the SHA-256 alone) against 0.87s with trusted
     * literals (0.03s user); sys time is identical because the file
     * is read either way. A content-addressed deployment whose
     * pipeline derives the literal from the file it ships has nothing
     * for the verify pass to catch -- any skew that could fool it
     * breaks far more than dictionaries -- so the operator may take
     * the ~4s per nginx -t/reload back and own the stated risk: a
     * stale or mistyped literal is then advertised verbatim, and
     * clients holding the advertised dictionary receive responses
     * they may fail to decode. Lines WITHOUT a literal are hashed as
     * always; trust changes only what a supplied literal means.
     */
    ngx_flag_t                   dcz_dict_trust_hashes;

    /*
     * Ordering record, same trap and same remedy as
     * dcz_dict_loaded_before_strict_on above: a supplied literal that
     * was VERIFIED (hashed) because zstd_dcz_dict_trust_hashes did
     * not yet read as the explicit "on" at that point in the parse.
     * Harmless to correctness -- the verified key equals the literal
     * -- but the operator asked for the zero-hashing path and
     * silently paid the full pass anyway, which at hundreds of
     * dictionaries is the entire cost the directive exists to remove.
     * init_main_conf() rejects the ordering when the final value is
     * "on" so the directive's effect is never position-dependent.
     */
    ngx_flag_t                   dcz_dict_verified_before_trust_on;

    /* First such path, for the ordering-rejection error message. */
    ngx_str_t                    dcz_dict_verified_before_trust_on_file;

    /*
     * Load-time SHA-256 computations over dcz dictionaries in THIS
     * configuration ($zstd_dcz_dicts_hashed). Cycle-owned on purpose:
     * a process-global static is reset and incremented while parsing a
     * CANDIDATE config, so a rejected reload would leave the refused
     * config's count behind for respawned workers to report (review of
     * #103, reproduced live). Here a rejected cycle takes its count
     * down with its pool, and the variable handler reads the request's
     * active cycle's conf. pcalloc zeroes it — no reset hook needed.
     */
    ngx_uint_t                   dcz_dicts_hashed;

    /* Reused only while this candidate configuration is parsed. */
    void                        *dcz_evp_md_ctx;
    ngx_flag_t                   dcz_evp_md_ctx_attempted;

    /*
     * Preformatted decimal representation of dcz_dicts_hashed,
     * allocated during main-conf init. The variable handler returns
     * this immutable buffer directly instead of allocating and calling
     * ngx_sprintf on every request.
     */
    ngx_str_t                    dcz_dicts_hashed_str;

    /*
     * ZSTD_CStreamOutSize() result, computed once at init and cached
     * in main conf. The constant-returning libzstd function is called
     * once here instead of on every location merge.
     */
    size_t                       stream_out_size;

    /*
     * Cycle-wide trained-dictionary registry for zstd_dict_file (dcz is
     * unaffected — see ngx_http_zstd_dcz_dict_file() below, out of
     * scope here).
     *
     * dict_file's raw bytes are read from disk exactly ONCE per cycle
     * into dict_buf/dict_buf_size, on the first enabled location that
     * needs a CDict at all (ngx_http_zstd_merge_loc_conf() below). Every
     * later location — sibling or distinct-profile — reuses this same
     * buffer instead of re-opening and re-reading the file.
     *
     * dict_registry then de-duplicates the CDict BUILD itself, keyed on
     * the complete set of parameters that ZSTD_createCDict_advanced()
     * bakes into a CDict's compression parameters: (level, window_log).
     * Those two are the only inputs to cparams in the merge function
     * (ZSTD_getCParams(level, ...) then an optional windowLog override) —
     * long_mode/zstd_long is a separate CCtx frame parameter applied at
     * request time via init_cctx and does NOT flow through refCDict, so
     * it is correctly excluded from the key (see the "Long-distance
     * matching" note at the CDict-build site). Two locations that agree
     * on (level, window_log) always produce byte-identical CDicts from
     * the same dict_buf, so sharing one is exact, not an approximation.
     *
     * Both dict_buf and every ZSTD_CDict entry are allocated outside
     * cf->pool (raw bytes: ngx_palloc against cf->pool same as before;
     * CDicts: libzstd's own allocator) but are freed exactly once at
     * cycle teardown via ngx_pool_cleanup_t handlers registered against
     * cf->pool the first time each is created — never per-location. This
     * array itself lives in cf->pool alongside the main conf, so it is
     * torn down with the same pool that owns every CDict's cleanup
     * handler.
     *
     * On the static-linking build (ZSTD_dlm_byRef, see the CDict-build
     * site) every CDict entry REFERENCES dict_buf directly rather than
     * copying it — libzstd reads dict_buf for the entire lifetime of
     * each CDict, not just at construction. This is safe only because
     * dict_buf and every CDict built from it share the same cf->pool
     * lifetime and teardown order: ngx_destroy_pool() runs every
     * registered cleanup handler (including each ZSTD_freeCDict() below)
     * BEFORE releasing pool allocations, so dict_buf is still mapped for
     * every ZSTD_freeCDict() call, and it is never freed while any CDict
     * that references it is still alive. Across a reload, old worker
     * processes keep the entire old cycle (and its pool) alive until
     * they exit, so an old CDict's reference into the old cycle's
     * dict_buf is never dangling. On the public-API fallback build
     * (plain ZSTD_createCDict(), #else branch below) the CDict still
     * copies the bytes, so dict_buf is not read again there after the
     * last build on that path.
     */
    u_char                      *dict_buf;
    size_t                       dict_buf_size;
    ngx_array_t                 *dict_registry;  /* dict_entry_t entries */

    /*
     * Conservative "could this cycle possibly serve a compressed
     * response" latch for ngx_http_zstd_filter_init() (TODO row: skip
     * installing the header/body filter hooks when the module is off
     * everywhere). Set at DIRECTIVE PARSE TIME by
     * ngx_http_zstd_set_enable_slot() whenever a "zstd on;" (or
     * anything other than an explicit "zstd off;") is parsed ANYWHERE
     * in the config -- main, srv, loc, or an NGX_HTTP_LIF_CONF location
     * conf created for a rewrite-phase "if" block. Latching at parse
     * time rather than during the location-conf merge walk sidesteps
     * having to prove every "if" loc conf is reachable from that walk;
     * a false positive here (installing the hooks when every merged
     * location actually stays disabled) only costs the two no-op calls
     * this row is about, while a false negative would silently drop
     * compression for a live location. Never read at request time and
     * never influences $zstd_ratio/$zstd_bytes_* (those stay wired
     * unconditionally in ngx_http_zstd_add_variables(), each setting its
     * own per-call no_cacheable flag -- see that function's comment).
     */
    ngx_flag_t                   any_enabled;
    ngx_flag_t                   any_negative_level;
    ngx_flag_t                   any_target_cblock_size;
} ngx_http_zstd_main_conf_t;


/*
 * One entry in ngx_http_zstd_main_conf_t.dict_registry: a built CDict
 * plus the complete key of parameters that affect its contents. See the
 * registry field's comment above for why (level, window_log) is the
 * complete key.
 */
typedef struct {
    ngx_int_t                    level;
    ngx_int_t                    window_log;
    ZSTD_CDict                  *dict;
} ngx_http_zstd_dict_entry_t;


/*
 * One RFC 9842 dictionary, loaded at config parse. `bytes` is the raw
 * file content in cf->pool (worker-lifetime; old workers keep their
 * forked copy across a reload until they drain), referenced per request
 * via ZSTD_CCtx_refPrefix() — RFC 9842 type=raw semantics exactly. The
 * SHA-256 is the negotiation key: it is what a client's
 * Available-Dictionary header carries and what the dcz frame header
 * must embed.
 */
typedef struct {
    ngx_str_t                    file;    /* resolved path, for logs */
    ngx_str_t                    bytes;   /* raw dictionary contents */
    u_char                       hash[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];

    /*
     * The full 40-byte dcz skippable-frame prefix (magic + declared
     * content size + this dictionary's hash), assembled once here at
     * config load instead of on every negotiated request. emit_dcz_header
     * previously built it per-request from two separate ngx_cpymem calls
     * (a constant array plus the hash); this is the same bytes, computed
     * once and copied whole.
     */
    u_char                       frame_header[NGX_HTTP_ZSTD_DCZ_HEADER_LEN];
} ngx_http_zstd_dcz_dict_t;


typedef struct {
    ngx_flag_t                   enable;
    ngx_int_t                    level;
    ssize_t                      min_length;
    ssize_t                      max_length;
    /* Issue #38: ZSTD_c_targetCBlockSize */
    ssize_t                      target_cblock_size;
    /* ZSTD_c_windowLog: bounds per-request memory */
    ngx_int_t                    window_log;
    /* ZSTD_c_enableLongDistanceMatching */
    ngx_flag_t                   long_mode;
    /* config-load assert: per-request CCtx memory budget */
    ssize_t                      max_cctx_memory;
    /*
     * Largest window log whose estimated CCtx memory still fits
     * "zstd_max_cctx_memory", computed ONCE at config load by
     * ngx_http_zstd_dcz_window_cap(). 0 means "no cap": either the
     * operator set no budget, or the build cannot compute an estimate
     * (no ZSTD_STATIC_LINKING_ONLY / libzstd < 1.4.0, in which case an
     * explicit budget is already rejected at config load). Only the dcz
     * path consults it -- see ngx_http_zstd_dcz_window_log().
     */
    ngx_int_t                    dcz_window_cap;

    /* ngx_http_complex_value_t: per-request bypass */
    ngx_array_t                 *bypass;
    /* extra Vary field for header/cookie-driven bypass; see S1 */
    ngx_str_t                    bypass_vary;

    ngx_hash_t                   types;

    ngx_bufs_t                   bufs;

    /*
     * Acknowledgement for an aggregate "zstd_buffers number * size"
     * above NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES. Mirrors
     * "zstd_dict_file_unsafe" and "zstd_max_cctx_memory 0": the operator
     * has to say, explicitly and in words, that a total this large is
     * intentional -- the check does not just log and move on.
     */
    ngx_flag_t                   bufs_unsafe;

    ngx_array_t                 *types_keys;

    ZSTD_CDict                  *dict;

    ngx_array_t                 *dcz_dicts;  /* ngx_http_zstd_dcz_dict_t */

    /*
     * RFC 9842 secure-context escape hatch. dcz is only offered on a
     * TLS connection (r->connection->ssl != NULL). Behind a
     * TLS-terminating proxy nginx sees plaintext and that test fails,
     * so an operator who terminates TLS in front of this nginx sets
     * zstd_dcz_assume_secure_transport on to assert the hop the client
     * actually spoke was secure. Never inferred from a request header:
     * X-Forwarded-Proto is client-settable on a direct connection.
     */
    ngx_flag_t                   dcz_assume_secure;
} ngx_http_zstd_loc_conf_t;


/* PR #49: Action state machine for compression lifecycle */
typedef enum {
    NGX_HTTP_ZSTD_FILTER_COMPRESS = 0,
    NGX_HTTP_ZSTD_FILTER_FLUSH    = 1,
    NGX_HTTP_ZSTD_FILTER_END      = 2,
} ngx_http_zstd_action_t;


typedef struct {
    ngx_chain_t                 *in;
    ngx_chain_t                **last_in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;
    ngx_chain_t                 *out;
    ngx_chain_t                **last_out;

    ngx_buf_t                   *in_buf;
    ngx_buf_t                   *out_buf;
    ngx_int_t                    bufs;

    ZSTD_inBuffer                buffer_in;
    ZSTD_outBuffer               buffer_out;

    ZSTD_CCtx                   *cctx;

    /* dictionary negotiated for this response via Available-Dictionary;
     * NULL means plain zstd. Points into the loc conf's dcz_dicts array
     * (config-pool lifetime, outlives the request). */
    ngx_http_zstd_dcz_dict_t    *dcz_dict;

    uint64_t                     bytes_in;
    uint64_t                     bytes_out;

    /*
     * Original response body length captured in the header filter BEFORE
     * ngx_http_clear_content_length() wipes r->headers_out.content_length_n.
     * -1 when unknown (chunked/streaming). Used to pledge the source size to
     * libzstd in init_cctx for a more compact frame header; see P1.
     */
    off_t                        pledged_size;

    /*
     * Memoised ngx_http_zstd_dcz_window_log() result for this request.
     * acquire_cctx() and init_cctx() must derive the IDENTICAL window log --
     * a request that borrows a CCtx ring slot keyed on one window and then
     * compresses at another contaminates that slot's retained workspace for
     * every later borrower. Computing it twice risked exactly that drift if
     * either call site's inputs ever diverged; this field makes the two
     * reads provably the same value by construction instead of relying on
     * both call sites staying in lockstep. 0 means "not yet computed" -- the
     * helper's documented range is [10, 23]
     * (ZSTD_WINDOWLOG_MIN..NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG), so 0 can never
     * be a real result. Meaningless when ctx->dcz_dict == NULL.
     */
    ngx_int_t                    dcz_window_log_cache;

    unsigned                     last:1;
    unsigned                     redo:1;
    unsigned                     flush:1;
    unsigned                     done:1;
    /* A failed stream is terminal but must not look complete to log vars. */
    unsigned                     aborted:1;
    unsigned                     nomem:1;

    /* the 40-byte dcz frame header has been queued on the out chain.
     * Kept even though cctx_ready below now makes init single-shot: the
     * prefix must never be duplicated regardless of init bookkeeping. */
    unsigned                     dcz_header_sent:1;

    /*
     * First-body-data latch for init_cctx. This used to be inferred from
     * `ctx->buffer_in.src == NULL`, but buffer_in.src is data state, not
     * lifecycle state: add_data reloads it from every incoming buffer, and
     * a data-less carrier buffer (ngx_buf_special() — e.g. the sync bufs
     * the sub filter emits while a match candidate spans input buffers)
     * has pos == NULL, which re-armed the check. The next invocation then
     * re-ran ZSTD_CCtx_reset() mid-stream, silently discarding everything
     * libzstd had buffered but not yet flushed: the response still ended
     * in ONE well-formed frame (200 + valid zstd), just with the reset-
     * window content missing. Observed in production as truncated HTML on
     * sub_filter-rewritten pages fed by a small-buffer upstream (the
     * dcz_header_sent guard above was an earlier symptom of the same
     * re-run, without the data-loss diagnosis).
     */
    unsigned                     cctx_ready:1;

    /* PR #49: Action state machine (COMPRESS, FLUSH, or END) */
    ngx_http_zstd_action_t       action;
} ngx_http_zstd_ctx_t;


/*
 * zstd_comp_level cannot use NGX_CONF_UNSET as its "not configured"
 * marker: NGX_CONF_UNSET is -1, and -1 is itself a valid, documented
 * compression level (ZSTD_minCLevel()..-1, see README). With the shared
 * sentinel, "zstd_comp_level -1;" was indistinguishable from an absent
 * directive, so the merge below silently replaced it with the inherited
 * value or the default 3 -- and the duplicate-directive guard in
 * ngx_http_zstd_set_num_slot_with_negatives() could never fire for it.
 * The value is out of band for every libzstd: ZSTD_minCLevel() is
 * -131072 at its most extreme, far above the type minimum. nginx defines
 * NGX_MAX_INT_T_VALUE but no signed minimum, so derive it.
 */
#define NGX_HTTP_ZSTD_LEVEL_UNSET  (-NGX_MAX_INT_T_VALUE - 1)


/*
 * libzstd's documented defaults for the long-distance-matching
 * sub-parameters (see the ZSTD_c_ldm* comments in zstd.h). They are
 * derived lazily inside compression setup, so a ZSTD_CCtx_params that
 * has only had ZSTD_c_enableLongDistanceMatching set still carries
 * zeroes -- which makes ZSTD_estimateCStreamSize_usingCCtxParams()
 * divide by zero. The config-load budget check seeds them explicitly.
 *
 * NGX_HTTP_ZSTD_LDM_WINDOWLOG is the window (128 MB) libzstd itself
 * switches to when LDM is enabled without an explicit ZSTD_c_windowLog.
 */
#define NGX_HTTP_ZSTD_LDM_WINDOWLOG      27
#define NGX_HTTP_ZSTD_LDM_MINMATCH       64
/* libzstd's own default: hash log trails the window log by 7. */
#define NGX_HTTP_ZSTD_LDM_HASHLOG_OFFSET 7
#define NGX_HTTP_ZSTD_LDM_BUCKETSIZELOG  3


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;

static ngx_str_t  ngx_http_zstd_ratio = ngx_string("zstd_ratio");

/*
 * $zstd_dcz_dicts_hashed serves two audiences: operators checking that
 * trusted supplied hashes skipped the hashing pass (the value is 0 when
 * trust_hashes is on and every dictionary carried a literal), and the
 * regression suite, which asserts exactly that — the trusted-literal
 * skip is otherwise unobservable when the literal matches the file. The
 * count itself lives in ngx_http_zstd_main_conf_t (see there for why),
 * fed by ngx_http_zstd_dcz_dict_hash() (see there for why).
 */
static ngx_str_t  ngx_http_zstd_dcz_dicts_hashed_name =
    ngx_string("zstd_dcz_dicts_hashed");
static ngx_str_t  ngx_http_zstd_bytes_in = ngx_string("zstd_bytes_in");
static ngx_str_t  ngx_http_zstd_bytes_out = ngx_string("zstd_bytes_out");

/*
 * Sensible web-content defaults when zstd_types is omitted. Keep the
 * directive parser's post value as ngx_http_html_default_types below: an
 * explicitly configured zstd_types list retains nginx's long-standing
 * "text/html plus the configured types" behaviour.
 */
static ngx_str_t  ngx_http_zstd_default_types[] = {
    ngx_string("text/html"),
    ngx_string("text/plain"),
    ngx_string("text/css"),
    ngx_string("text/csv"),
    ngx_string("application/json"),
    ngx_string("application/x-ndjson"),
    ngx_string("application/json-seq"),
    ngx_string("application/javascript"),
    ngx_string("text/xml"),
    ngx_string("application/xml"),
    ngx_string("application/xml+rss"),
    ngx_string("text/javascript"),
    ngx_string("image/svg+xml"),
    ngx_string("application/atom+xml"),
    ngx_string("application/ld+json"),
    ngx_string("application/manifest+json"),
    ngx_string("application/problem+json"),
    ngx_string("application/rss+xml"),
    ngx_string("application/vnd.api+json"),
    ngx_string("application/xhtml+xml"),
    ngx_string("application/wasm"),
    ngx_string("text/wgsl"),
    ngx_null_string
};


/*
 * Forward declarations below cover the module-table entry points and the
 * handlers referenced across the file. They are not a full index of this
 * TU: the remaining file-static helpers (dcz_decode_digest, profile_pack /
 * profile_unpack, cctx_profiles_match, open_dict_strict,
 * build_cctx_params_profile, estimate_cctx_memory, dcz_window_cap,
 * predicate_is_direct_header_or_cookie, int_max_bound,
 * validate_field_name_token) are each defined before their first use and
 * need no declaration here.
 */
static ngx_int_t ngx_http_zstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_zstd_filter_copy_input(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_chain_t *in);
static ngx_int_t ngx_http_zstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_chain_t **in);
static ngx_int_t ngx_http_zstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx,
    ngx_http_zstd_loc_conf_t *zlcf);
static ngx_buf_t *ngx_http_zstd_create_temp_buf(ngx_pool_t *pool, size_t size);
static ngx_int_t ngx_http_zstd_set_param(ngx_http_request_t *r,
    ZSTD_CCtx *cctx, ZSTD_cParameter param, int value, const char *name);
static ngx_int_t ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_http_zstd_loc_conf_t *zlcf);
static ngx_int_t ngx_http_zstd_filter_compress(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_uint_t no_more_input);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);
static void * ngx_http_zstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_zstd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_zstd_init_module(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_zstd_dcz_dicts_hashed_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static ngx_int_t ngx_http_zstd_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static char *ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_zstd_check_size_int_max(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_zstd_check_num_int_max(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_zstd_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_zstd_check_bufs_product(ngx_conf_t *cf,
    const ngx_bufs_t *bufs, ngx_flag_t unsafe, const char *ctx,
    ngx_flag_t advise);
static char *ngx_http_zstd_set_bypass_vary(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_zstd_set_enable_slot(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void ngx_http_zstd_cleanup_dict(void *data);
static void ngx_http_zstd_cleanup_cctx(void *data);
#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
static void ngx_http_zstd_cleanup_evp_md_ctx(void *data);
static void ngx_http_zstd_init_evp_md_ctx(ngx_conf_t *cf,
    ngx_http_zstd_main_conf_t *zmcf);
#endif
static void ngx_http_zstd_release_cctx(void *data);
static ngx_int_t ngx_http_zstd_acquire_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_http_zstd_loc_conf_t *zlcf);
static void ngx_http_zstd_exit_process(ngx_cycle_t *cycle);
static char *ngx_http_zstd_dcz_dict_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_fd_t ngx_http_zstd_open_dict_file(ngx_conf_t *cf,
    ngx_str_t *path, ngx_flag_t strict, ngx_file_info_t *info);
static ngx_int_t ngx_http_zstd_read_dict_file(ngx_conf_t *cf, ngx_fd_t fd,
    ngx_str_t *path, u_char *buf, size_t size);
static void ngx_http_zstd_collect_dcz_headers(ngx_http_request_t *r,
    ngx_table_elt_t **avail_dict_h, ngx_uint_t *avail_dict_count,
    ngx_table_elt_t **sec_fetch_site_h, ngx_uint_t *sec_fetch_site_count);
static ngx_http_zstd_dcz_dict_t *ngx_http_zstd_dcz_negotiate(
    ngx_http_request_t *r, ngx_http_zstd_loc_conf_t *zlcf);
static int ngx_libc_cdecl ngx_http_zstd_dcz_dict_cmp(const void *one,
    const void *two);
static void ngx_http_zstd_dcz_dict_sort(ngx_array_t *dcz_dicts);
static ngx_http_zstd_dcz_dict_t *ngx_http_zstd_dcz_dict_lookup(
    ngx_array_t *dcz_dicts, u_char buf[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN]);


/*
 * Worker-lifetime CCtx cache.
 *
 * ZSTD_createCCtx() plus the first-use workspace allocation is 34-75% of the
 * per-response libzstd CPU on typical body sizes (measured, libzstd 1.5.7:
 * ~1.6us of 3.1us at level 6 / 8 KB; ~10.8us of 15.0us at level 6 / 64 KB).
 * Since ngx_http_zstd_filter_init_cctx() already does a full
 * ZSTD_reset_session_and_parameters() and re-applies every parameter on each
 * request, a context carried across requests is byte-for-byte equivalent on
 * the wire to a freshly created one -- the creation is pure overhead.
 *
 * Why this does NOT reintroduce the shared-context bug 774b4a5 fixed: that
 * commit's defect was a context shared between CONCURRENT requests (interleaved
 * compression state). Here the cache lends the context to exactly one
 * request at a time -- `busy` is set on loan and cleared by the request
 * pool's cleanup handler -- so any second concurrent claimant (a subrequest
 * compressing while the main request is mid-stream) transparently gets its
 * own per-request context instead. The per-request ownership model is
 * preserved; only the allocation is amortised.
 *
 * Why there is no runtime memory cap: ZSTD_sizeof_CCtx() does not shrink on
 * reset, so an unbounded cache would pin each worker's RSS at its
 * largest-ever footprint. Each slot is therefore keyed on the set of
 * parameters that drive the workspace size: zstd_comp_level, zstd_long and
 * the effective window log. zstd_target_cblock_size is omitted because
 * init_cctx re-applies it per request; it governs block splitting within
 * the workspace, not the workspace size itself.
 *
 * The first two are fixed at config load. The window log is the EFFECTIVE
 * one, which for an ordinary request is zstd_window_log but for a dcz
 * (RFC 9842) request is derived per request from the negotiated dictionary
 * -- see ngx_http_zstd_cctx_profile_from_conf_wlog(). Keying dcz requests on
 * the unset directive instead was a real contamination path, not a
 * hypothetical one: they borrowed slots vetted for a small window and raised
 * those slots' floors permanently.
 *
 * An earlier revision keyed on the level alone, on a measurement that said
 * windowLog did not move ZSTD_sizeof_CCtx() at a fixed level. That
 * measurement was taken with a known pledged source size, which clamps the
 * window to the input; it does not hold on this module's path, where the
 * body length is generally unknown to libzstd. Re-measured on libzstd 1.5.7
 * with a streaming, unknown-size compression at level 6:
 *
 *     zstd_long  zstd_window_log   ZSTD_sizeof_CCtx()
 *     off        (unset)                    5 498 401
 *     off        20                         4 449 825
 *     off        27                       137 618 977
 *     on         (unset)                  154 551 841
 *     on         20                         4 606 497
 *     on         27                       154 551 841
 *
 * So both zstd_long and zstd_window_log move the retained workspace by more
 * than thirty times at one level, and the growth is permanent: walking a
 * context through the 154 MB profile and back to the 4 MB one leaves
 * ZSTD_sizeof_CCtx() at 154 MB. Lending one cached context across locations
 * with differing profiles would raise that context's floor to the largest
 * profile ever served and silently defeat a lower location's
 * zstd_max_cctx_memory budget, which is computed from exactly these three
 * values at config load.
 *
 * Keying on all three keeps a cached context's high-water mark equal to
 * the figure config load already vetted for that profile. A location whose
 * profile matches no slot does not reuse a cached context; it seeds a free
 * slot, or takes the per-request path -- the pre-existing safe behaviour.
 *
 * Ring of per-profile slots, rather than the one slot this cache shipped
 * with. Each slot carries its OWN profile triple, so the keying invariant
 * documented above is per slot, not per worker: a slot's retained workspace
 * high-water mark stays equal to the figure config load vetted for that
 * slot's profile. A slot is never re-parameterised -- a request whose
 * profile matches no slot either seeds a free slot or takes the per-request
 * path, exactly as before.
 *
 * Two consequences the single-slot version did not have, both deliberate:
 *
 *  - Concurrent borrowing is now actually reachable. Previously the second
 *    overlapping request on a worker always fell through to a per-request
 *    context because the one slot was busy. Isolation is preserved by the
 *    same rule as before, applied per slot: `busy` is set on loan and
 *    cleared only by the borrowing request's pool cleanup, so a slot is
 *    lent to at most one request at a time and two concurrent requests
 *    always land on different slots (or on the per-request path).
 *
 *  - Locations with DIFFERENT profiles no longer evict each other. With one
 *    slot, two locations differing only in zstd_window_log or zstd_long
 *    meant whichever seeded the cache first served its own requests and
 *    every request of the other took the per-request path forever.
 *
 * The ring size bounds retained memory: up to NGX_HTTP_ZSTD_CCTX_SLOTS
 * workspaces per worker, each at its own profile's vetted figure. It is a
 * compile-time constant rather than a directive so the bound is auditable
 * from the source and cannot be raised by configuration.
 *
 * Seeding is first-fit with no eviction, so with MORE distinct profiles than
 * slots the ring is filled in arrival order and then frozen for the worker's
 * life: the first profiles seen win, even if a later one turns out busier.
 * That is deliberate -- never re-parameterising a slot is what keeps each
 * slot's high-water mark at its own vetted figure -- but it does mean cache
 * effectiveness past NGX_HTTP_ZSTD_CCTX_SLOTS profiles depends on startup
 * traffic order. A profile that finds no slot is served correctly on the
 * per-request path, the pre-existing safe behaviour.
 *
 * "Per-profile" bounds what a slot may SERVE, not how many slots a profile
 * may occupy. The search skips a busy slot before comparing its profile, so
 * a request arriving while a matching slot is on loan seeds a further slot
 * with that same profile. That is not an accident -- it is what makes the
 * ring help under concurrency at all, since overlapping requests on one
 * location would otherwise still serialise onto a single slot. The memory
 * bound is unaffected: the ring retains at most NGX_HTTP_ZSTD_CCTX_SLOTS
 * workspaces whatever the mix, and duplicates of one profile are all at that
 * profile's config-vetted figure. Do not read the ring as one slot per
 * configured profile when budgeting worker RSS -- read it as the constant.
 */
#ifndef NGX_HTTP_ZSTD_CCTX_SLOTS
#define NGX_HTTP_ZSTD_CCTX_SLOTS  4
#endif

typedef struct {
    uint64_t key;
} ngx_http_zstd_cctx_profile_t;

typedef struct {
    ZSTD_CCtx                       *cctx;
    ngx_http_zstd_cctx_profile_t     profile;
    ngx_uint_t                       busy;
} ngx_http_zstd_cctx_slot_t;

static ngx_http_zstd_cctx_slot_t
    ngx_http_zstd_worker_cctx_slots[NGX_HTTP_ZSTD_CCTX_SLOTS];


/*
 * Pack/unpack the CCtx profile into a single 64-bit key, so matching a
 * candidate slot is one load and one integer compare instead of three field
 * compares. Layout:
 *
 *   bits  0-17: level + NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS  (18 bits)
 *   bits 18-23: window_log                                 (6 bits)
 *   bit     24: long_mode                                  (1 bit)
 *   bits 25-63: reserved, always zero
 *
 * The key is COLLISION-FREE and REVERSIBLE by construction, not by hashing:
 * each field occupies its own disjoint bit range wide enough for its whole
 * accepted domain, so distinct tuples always differ in at least one bit and
 * _unpack() recovers the exact inputs. Diagnostics and tests rely on that.
 *
 * Why each field fits, with the arithmetic:
 *
 *  - level is validated at config load against ZSTD_minCLevel()..
 *    ZSTD_maxCLevel(). It is legitimately NEGATIVE for libzstd's fast levels,
 *    so it is biased into an unsigned range before shifting: right-shifting a
 *    negative signed integer is implementation-defined in C, and a bare cast
 *    of a negative value would sign-extend across the other fields. The bias
 *    is 1 << 17 = 131072, and ZSTD_minCLevel() is -131072 on every libzstd
 *    that defines it, so biased level lands in [0, 131094] -- inside 18 bits
 *    (max 262143).
 *
 *  - window_log is 0 ("unset", keep zstd's level-derived default) or a value
 *    ngx_http_zstd_check_num_int_max() has already accepted against
 *    ZSTD_cParam_getBounds(ZSTD_c_windowLog). That upper bound is 31 on
 *    64-bit libzstd today, but it is a LIBRARY value, not a constant this
 *    module owns, so the field is given 6 bits (0..63) and the packer
 *    asserts the value fits rather than masking it. Masking would silently
 *    alias an out-of-domain window onto another profile and make two
 *    different compression settings share one CCtx -- a wire-bytes change
 *    with no diagnostic.
 *
 *  - long_mode is an ngx_flag_t already merged to 0 or 1.
 *
 * NGX_HTTP_ZSTD_PROFILE_INVALID is returned when a value is out of domain.
 * It has bit 63 set, which no in-domain key ever has, so it can never be
 * confused with a real profile.
 */
#define NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS   131072
#define NGX_HTTP_ZSTD_PROFILE_LEVEL_BITS   18
#define NGX_HTTP_ZSTD_PROFILE_WLOG_BITS    6
#define NGX_HTTP_ZSTD_PROFILE_LEVEL_MAX \
    ((1ULL << NGX_HTTP_ZSTD_PROFILE_LEVEL_BITS) - 1)
#define NGX_HTTP_ZSTD_PROFILE_WLOG_MAX \
    ((1ULL << NGX_HTTP_ZSTD_PROFILE_WLOG_BITS) - 1)
#define NGX_HTTP_ZSTD_PROFILE_WLOG_SHIFT   NGX_HTTP_ZSTD_PROFILE_LEVEL_BITS
#define NGX_HTTP_ZSTD_PROFILE_LONG_SHIFT \
    (NGX_HTTP_ZSTD_PROFILE_LEVEL_BITS + NGX_HTTP_ZSTD_PROFILE_WLOG_BITS)
#define NGX_HTTP_ZSTD_PROFILE_INVALID      ((uint64_t) 1 << 63)

static uint64_t
ngx_http_zstd_profile_pack(ngx_int_t level, ngx_flag_t long_mode,
    ngx_int_t window_log)
{
    uint64_t  biased, wlog;

    /*
     * Refuse rather than mask. Every caller feeds config-validated values, so
     * this is a structural guard: if a future directive change widens a
     * domain past its field, profiles start comparing unequal (a redundant
     * CCtx, harmless) instead of silently aliasing (a shared CCtx with the
     * wrong parameters, which changes bytes on the wire).
     */
    if (level < -NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS) {
        return NGX_HTTP_ZSTD_PROFILE_INVALID;
    }

    biased = (uint64_t) (level + NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS);

    if (biased > NGX_HTTP_ZSTD_PROFILE_LEVEL_MAX) {
        return NGX_HTTP_ZSTD_PROFILE_INVALID;
    }

    if (window_log < 0) {
        return NGX_HTTP_ZSTD_PROFILE_INVALID;
    }

    wlog = (uint64_t) window_log;

    if (wlog > NGX_HTTP_ZSTD_PROFILE_WLOG_MAX) {
        return NGX_HTTP_ZSTD_PROFILE_INVALID;
    }

    return biased
        | (wlog << NGX_HTTP_ZSTD_PROFILE_WLOG_SHIFT)
        | ((uint64_t) (long_mode ? 1 : 0) << NGX_HTTP_ZSTD_PROFILE_LONG_SHIFT);
}


/*
 * Inverse of ngx_http_zstd_profile_pack() for diagnostics and tests. Kept
 * adjacent to the packer on purpose: the two encode one layout, and splitting
 * them is how a pack/unpack pair drifts.
 *
 * Its only in-tree caller is the cctx-reuse debug log in
 * ngx_http_zstd_acquire_cctx(), which is itself #if (NGX_DEBUG); without the
 * same guard here a release build trips -Werror=unused-function. The
 * standalone unit in ci/tools/test_cctx_profile_pack.sh extracts the
 * "static void" line through the closing brace, so this #if stays outside
 * that range on purpose -- do not fold it into the signature.
 */
#if (NGX_DEBUG)
static void
ngx_http_zstd_profile_unpack(uint64_t key, ngx_int_t *level,
    ngx_flag_t *long_mode, ngx_int_t *window_log)
{
    *level = (ngx_int_t) (key & NGX_HTTP_ZSTD_PROFILE_LEVEL_MAX)
             - NGX_HTTP_ZSTD_PROFILE_LEVEL_BIAS;
    *window_log = (ngx_int_t) ((key >> NGX_HTTP_ZSTD_PROFILE_WLOG_SHIFT)
                               & NGX_HTTP_ZSTD_PROFILE_WLOG_MAX);
    *long_mode = (ngx_flag_t) ((key >> NGX_HTTP_ZSTD_PROFILE_LONG_SHIFT) & 1);
}
#endif


/*
 * Build a profile key from a location's config and the window log the
 * request will ACTUALLY compress at.
 *
 * The window is a parameter rather than being read from zlcf because a dcz
 * (RFC 9842) request does not use zlcf->window_log: it computes its own
 * window from the negotiated dictionary. Keying such a request on
 * zlcf->window_log let it borrow a slot vetted for a different -- typically
 * much smaller -- window and permanently raise that slot's retained
 * workspace, since ZSTD_sizeof_CCtx() never shrinks on reset. Every later
 * plain request matching the same key then reused a context whose floor was
 * the dcz figure: precisely the cross-profile contamination the three-field
 * key exists to prevent, arriving through the one field that was not
 * effective.
 *
 * The keyed window is therefore the effective one, and dcz requests
 * naturally partition into their own slots.
 */
static void
ngx_http_zstd_cctx_profile_from_conf_wlog(
    ngx_http_zstd_cctx_profile_t *profile, ngx_http_zstd_loc_conf_t *zlcf,
    ngx_int_t window_log)
{
    profile->key = ngx_http_zstd_profile_pack(zlcf->level, zlcf->long_mode,
        window_log);
}


static ngx_int_t
ngx_http_zstd_cctx_profiles_match(
    const ngx_http_zstd_cctx_profile_t *a,
    const ngx_http_zstd_cctx_profile_t *b)
{
    return a->key == b->key;
}


static ngx_conf_post_t  ngx_http_zstd_comp_level_bounds = {
    ngx_http_zstd_comp_level
};


/*
 * Config-load bound for the two directives whose parsed value is later
 * narrowed with an (int) cast before being handed to libzstd
 * (zstd_target_cblock_size -> ssize_t, zstd_window_log -> ngx_int_t).
 * On a 64-bit platform a configured value above INT_MAX would silently
 * truncate (and possibly wrap negative) in that cast, bypassing zstd's
 * own range check with a meaningless value. Reject it at config load
 * with a clear error instead of a confusing runtime failure. Separate
 * handlers because set_size_slot stores ssize_t and set_num_slot
 * stores ngx_int_t; both defer to the same INT_MAX comparison.
 */
static ngx_conf_post_t  ngx_http_zstd_check_size_int_max_post = {
    ngx_http_zstd_check_size_int_max
};

static ngx_conf_post_t  ngx_http_zstd_check_num_int_max_post = {
    ngx_http_zstd_check_num_int_max
};


static ngx_command_t  ngx_http_zstd_filter_commands[] = {

    { ngx_string("zstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
      |NGX_CONF_FLAG,
      ngx_http_zstd_set_enable_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, enable),
      NULL },

    { ngx_string("zstd_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_zstd_set_num_slot_with_negatives,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, level),
      &ngx_http_zstd_comp_level_bounds },

    { ngx_string("zstd_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("zstd_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_http_zstd_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bufs),
      NULL },

    { ngx_string("zstd_buffers_unsafe"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bufs_unsafe),
      NULL },

    { ngx_string("zstd_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, min_length),
      NULL },

    { ngx_string("zstd_max_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, max_length),
      NULL },

    { ngx_string("zstd_target_cblock_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, target_cblock_size),
      &ngx_http_zstd_check_size_int_max_post },

    { ngx_string("zstd_window_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, window_log),
      &ngx_http_zstd_check_num_int_max_post },

    { ngx_string("zstd_long"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, long_mode),
      NULL },

    { ngx_string("zstd_max_cctx_memory"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, max_cctx_memory),
      NULL },

    { ngx_string("zstd_bypass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_set_predicate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bypass),
      NULL },

    { ngx_string("zstd_bypass_vary"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_zstd_set_bypass_vary,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bypass_vary),
      NULL },

    { ngx_string("zstd_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_file),
      NULL },

    { ngx_string("zstd_dict_file_unsafe"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_unsafe),
      NULL },

    /*
     * Off by default: a standard release-symlink deployment (current ->
     * /srv/releases/<n>/dict.bin) is a legitimate, common layout and
     * must keep working with no directive at all. Applies to both
     * zstd_dict_file and zstd_dcz_dict_file — see
     * ngx_http_zstd_open_dict_file().
     */
    { ngx_string("zstd_dict_strict_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_strict_path),
      NULL },

    /*
     * MAIN_CONF like zstd_dict_strict_path, and for the same reason:
     * what a supplied hash literal MEANS is a property of the whole
     * load's trust model, not of one location. Must precede every
     * zstd_dcz_dict_file it applies to (enforced in init_main_conf).
     */
    { ngx_string("zstd_dcz_dict_trust_hashes"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dcz_dict_trust_hashes),
      NULL },

    { ngx_string("zstd_dcz_assume_secure_transport"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, dcz_assume_secure),
      NULL },

    { ngx_string("zstd_dcz_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_zstd_dcz_dict_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#ifdef NGX_TEST_HARNESS
    { ngx_string("zstd_probe"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_zstd_probe_directive,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
#endif

    ngx_null_command
};


static ngx_http_module_t  ngx_http_zstd_filter_module_ctx = {
    ngx_http_zstd_add_variables,            /* preconfiguration */
    ngx_http_zstd_filter_init,              /* postconfiguration */

    ngx_http_zstd_create_main_conf,         /* create main configuration */
    ngx_http_zstd_init_main_conf,           /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_zstd_create_loc_conf,          /* create location configuration */
    ngx_http_zstd_merge_loc_conf,           /* merge location configuration */
};


ngx_module_t  ngx_http_zstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_zstd_filter_module_ctx,       /* module context */
    ngx_http_zstd_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    ngx_http_zstd_init_module,              /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_http_zstd_exit_process,             /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_zstd_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t           *h;
    ngx_http_zstd_loc_conf_t  *zlcf;
    ngx_http_zstd_ctx_t       *ctx;
    ngx_http_zstd_dcz_dict_t  *dcz;

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    /*
     * Eligibility gate. This is the original single 9-term disjunction
     * split into one early return per reason: behaviour is identical
     * (|| short-circuits and every term led to the same next-filter
     * return), but each rejection cause is now individually visible and
     * greppable. Order is preserved so short-circuit semantics — e.g.
     * not dereferencing content_encoding before the cheaper checks — are
     * unchanged.
     */

    /* zstd disabled for this location */
    if (!zlcf->enable) {
        return ngx_http_next_header_filter(r);
    }

    /* subrequest: both negotiators below reject r != r->main
     * unconditionally (ngx_http_zstd_accepts() in common.h,
     * ngx_http_zstd_dcz_negotiate()), so a subrequest can never be
     * encoded here. Returning now skips the eligibility gates, the
     * zstd-owned Vary pushes and zstd_bypass predicate evaluation,
     * all of which are dead work on a response this filter will
     * decline regardless. */
    if (r != r->main) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, subrequest");
        return ngx_http_next_header_filter(r);
    }

    /* status not eligible: < 200, bodyless 204/205, 206 Partial Content,
     * or any > 299 except 403/404 (which carry compressible error bodies).
     *
     * 206 is excluded (matching nginx's gzip filter): an upstream 206 has a
     * Content-Range computed against its selected representation. Applying a
     * new content coding here would invalidate that Content-Range (RFC 9110
     * §14.1.2 requires ranges for an encoded representation to be computed
     * against the encoded byte sequence), and the filter only clears
     * Accept-Ranges, not Content-Range. See RFC4. */
    if (r->headers_out.status < NGX_HTTP_OK
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || r->headers_out.status == 205   /* 205 Reset Content: no core macro */
        || r->headers_out.status == NGX_HTTP_PARTIAL_CONTENT
        || (r->headers_out.status > NGX_HTTP_ZSTD_MAX_ELIGIBLE_STATUS
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, status %ui not eligible",
                       r->headers_out.status);
        return ngx_http_next_header_filter(r);
    }

    /* already encoded (e.g. upstream gzip/br) — do not double-compress */
    if (r->headers_out.content_encoding
        && r->headers_out.content_encoding->value.len)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, already encoded as \"%V\"",
                       &r->headers_out.content_encoding->value);
        return ngx_http_next_header_filter(r);
    }

    /* known body smaller than zstd_min_length — not worth a frame */
    if (r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n < zlcf->min_length)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, body %O < zstd_min_length %z",
                       r->headers_out.content_length_n, zlcf->min_length);
        return ngx_http_next_header_filter(r);
    }

    /* known body larger than zstd_max_length cap */
    if (zlcf->max_length != NGX_CONF_UNSET
        && r->headers_out.content_length_n != -1
        && r->headers_out.content_length_n > zlcf->max_length)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, body %O > zstd_max_length %O",
                       r->headers_out.content_length_n,
                       (off_t) zlcf->max_length);
        return ngx_http_next_header_filter(r);
    }

    /* header-only response: no body to compress */
    if (r->header_only) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, header-only response");
        return ngx_http_next_header_filter(r);
    }

    /* content type not in zstd_types */
    if (ngx_http_test_content_type(r, &zlcf->types) == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, content type \"%V\" not in zstd_types",
                       &r->headers_out.content_type);
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_zstd_cache_control_no_transform(r)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, Cache-Control no-transform");
        return ngx_http_next_header_filter(r);
    }

    /*
     * Cache-correctness for request-header / cookie-driven bypass. When the
     * decision to compress varies on a request header (e.g.
     * "zstd_bypass $http_x_no_compression"), a shared cache must key on that
     * header or it will serve a stored identity response to a normal client
     * (or a compressed one to a bypass client). The module cannot infer which
     * header drove the predicate, so the operator names it via
     * zstd_bypass_vary; we append it to Vary on BOTH the bypassed identity
     * response and the compressed one (this runs before the bypass return
     * below). A second Vary header line is fine — caches union all Vary
     * fields. See S1.
     */
    if (zlcf->bypass_vary.len) {
        ngx_table_elt_t  *v;

        v = ngx_http_zstd_list_push(&r->headers_out.headers);
        if (v == NULL) {
            return NGX_ERROR;
        }

        v->hash = 1;
#if (nginx_version >= 1023000)
        v->next = NULL;
#endif
        ngx_str_set(&v->key, "Vary");
        v->value = zlcf->bypass_vary;
    }

    /*
     * Vary: Accept-Encoding, emitted by this module rather than merely
     * requested via r->gzip_vary and left to the operator's
     * "gzip_vary" directive. Everything below this point negotiates on
     * Accept-Encoding, so the response is a content-coding variant and
     * must say so or a shared cache will hand the zstd body to a
     * client that cannot decode it. Duplicate-safe in both gzip_vary
     * states; see ngx_http_zstd_vary_accept_encoding().
     *
     * This sits ABOVE the zstd_bypass return below, not next to the
     * Content-Encoding push, for the same reason the dcz Vary push
     * does: the bypassed IDENTITY response is not Accept-Encoding-
     * invariant. The very same URI in the very same location serves
     * zstd to a request that does not trip the bypass predicate, so a
     * shared cache that stored the bypassed identity body without
     * Accept-Encoding in its key would keep serving it to clients that
     * should have been compressed — and, filled the other way round,
     * would serve the zstd body to the bypassed client. Every return
     * ABOVE this point declines for a reason invariant in
     * Accept-Encoding (wrong status, wrong content type, header-only,
     * already encoded), so this is the earliest correct place for it.
     *
     * NOT fused with the Available-Dictionary/Sec-Fetch-Site push below:
     * that push runs only after the zstd_bypass predicate return further
     * down, so a bypassed identity response gets Accept-Encoding in Vary
     * but not the dcz tokens -- the bypass predicate is Available-
     * Dictionary-invariant, so omitting those tokens there is correct,
     * not an oversight. Fusing the two walks here would start adding
     * dcz Vary tokens to bypassed responses, which is a behaviour
     * change, not an optimisation. This call site keeps the two separate
     * walks; the static_module.c dict_bypass site (which wants both
     * unconditionally, with no intervening early return) uses the fused
     * ngx_http_zstd_vary_ae_dcz() helper.
     */
    if (ngx_http_zstd_vary_accept_encoding(r) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Per-request bypass. If any zstd_bypass predicate variable resolves
     * to a non-empty value other than "0", skip compression for this
     * request. This is the operator lever for serving identity on
     * endpoints that must not be compressed — e.g. responses that mix a
     * secret (CSRF token, session data) with attacker-influenced
     * reflected input (a BREACH-style exposure), or already-compressed
     * dynamic payloads — without splitting the location.
     */
    if (zlcf->bypass != NULL
        && ngx_http_test_predicates(r, zlcf->bypass) != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: bypassed by zstd_bypass predicate");
        return ngx_http_next_header_filter(r);
    }

    /*
     * With dictionaries configured, WHICH encoding this location serves
     * depends on the request's Available-Dictionary header — the dcz
     * variant obviously, the plain zstd variant a dictionary-less client
     * receives, and equally the identity fallback: a client sending
     * "Accept-Encoding: dcz" (no zstd) with a hash we do not hold gets
     * identity NOW, but the same client holding a dictionary we DO hold
     * would get dcz — so a shared cache must key that identity variant
     * on Available-Dictionary too, or it can keep serving it after the
     * client acquires the dictionary (a silent compression loss). That
     * is why this push sits ABOVE the acceptance gate below rather than
     * next to the Content-Encoding push: every return before this point
     * declines for reasons invariant in Available-Dictionary; the two
     * paths after it are not invariant. Accept-Encoding itself is
     * already covered by gzip_vary above; caches union all Vary lines.
     *
     * Sec-Fetch-Site rides in the SAME header for exactly the same
     * reason. ngx_http_zstd_dcz_negotiate() below refuses dcz for any
     * Sec-Fetch-Site other than absent / "same-origin" / "none", which
     * makes that request header a response-selection input: without it
     * in Vary, a shared cache filled by a same-origin request hands the
     * dcz representation to a cross-site request and bypasses the
     * origin gate entirely, while the reverse fill order suppresses dcz
     * for a legitimate same-origin client. It is pushed unconditionally
     * in a dcz-configured location, not only on the paths that consult
     * it: every return above is Sec-Fetch-Site-invariant, and the
     * identity/plain-zstd fallbacks below are precisely the variants a
     * cache must not reuse across the gate. Security decision inputs
     * stay in Vary — a later optimisation that conditionalises the
     * Available-Dictionary token must not drop this one.
     */
    if (zlcf->dcz_dicts != NULL && zlcf->dcz_dicts->nelts > 0) {
        if (ngx_http_zstd_vary_dcz(r) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /*
     * RFC 9842 dcz negotiation first: a client that advertises a
     * dictionary we hold (Available-Dictionary hash match) and accepts
     * the dcz coding gets dictionary compression; everything else falls
     * through to the plain zstd path unchanged.
     */
    dcz = ngx_http_zstd_dcz_negotiate(r, zlcf);

    if (dcz != NULL) {
        /*
         * Latch gzip off exactly as ngx_http_zstd_ok() does on the plain
         * path: the commitment to encode is made immediately below, so a
         * later gzip filter must not double-compress.
         */
        r->gzip_tested = 1;
        r->gzip_ok = 0;

    } else if (ngx_http_zstd_ok(r) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: skip, client did not accept zstd encoding");
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_zstd_pcalloc(r->pool, sizeof(ngx_http_zstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    ctx->last_out = &ctx->out;
    ctx->last_in  = &ctx->in;
    ctx->dcz_dict = dcz;

    h = ngx_http_zstd_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
#if (nginx_version >= 1023000)
    h->next = NULL;
#endif
    ngx_str_set(&h->key, "Content-Encoding");
    if (dcz != NULL) {
        ngx_str_set(&h->value, "dcz");
    } else {
        ngx_str_set(&h->value, "zstd");
    }
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    /*
     * Capture the known body length before clearing it. ngx_http_clear_
     * content_length() sets content_length_n to -1, so the init_cctx pledge
     * (which runs after the first body data) would otherwise always see -1
     * and never call ZSTD_CCtx_setPledgedSrcSize(). -1 here means unknown.
     */
    ctx->pledged_size = r->headers_out.content_length_n;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd: compressing response (content-length %O)",
                   r->headers_out.content_length_n);

    return ngx_http_next_header_filter(r);
}


/*
 * Collect two headers (Available-Dictionary and Sec-Fetch-Site) in a single
 * header-list traversal. Both headers appear at most once and only on
 * dictionary-aware requests; collecting them together avoids a second walk
 * through what can be a long header list.
 *
 * Neither header appears in nginx's ngx_http_headers_in table, so neither
 * gets ngx_http_process_unique_header_line's duplicate rejection: a request
 * may legitimately reach a module carrying two of them. Both are single-valued
 * by their specifications and a browser never sends either twice, so the
 * duplicate count for each allows the caller to fail closed on more than one
 * occurrence — for Sec-Fetch-Site that check is the RFC 9842 SS8.3
 * cross-origin partitioning gate, and a proxy that merges or forwards a
 * client-supplied duplicate, or a request-smuggling desync, must not be able
 * to turn it off by prepending an agreeable value.
 *
 * Returns the found-status of each header (NULL if not present) and the
 * duplicate count for each via output pointers. The caller must evaluate
 * both in the order they appear in the code (Available-Dictionary first,
 * then Sec-Fetch-Site) to preserve the existing debug log message sequence.
 *
 * The name match is a case-SENSITIVE ngx_memcmp against lowercase literals,
 * because h[i].lowcase_key is already folded by nginx on every protocol and
 * is never NULL for a header that reached a module:
 *
 *   HTTP/1  ngx_http_request.c:1527  allocates it and ngx_strlow()s the name
 *                                    (or memcpy's the parser's lowcase_header)
 *   HTTP/2  ngx_http_v2.c:1857       aliases key.data, which is safe because
 *                                    :3273 rejects any 'A'-'Z' in a field name
 *   HTTP/3  ngx_http_v3_request.c:685 aliases key.data likewise
 *
 * Folding again through ngx_strncasecmp() would re-do work nginx has already
 * done, once per header per request. If a future protocol module populates
 * lowcase_key without folding, these two comparisons are what breaks.
 */
static void
ngx_http_zstd_collect_dcz_headers(ngx_http_request_t *r,
    ngx_table_elt_t **avail_dict_h, ngx_uint_t *avail_dict_count,
    ngx_table_elt_t **sec_fetch_site_h, ngx_uint_t *sec_fetch_site_count)
{
    ngx_uint_t              i;
    const ngx_list_part_t  *part;
    ngx_table_elt_t        *h;

    part = &r->headers_in.headers.part;
    h = part->elts;
    *avail_dict_h = NULL;
    *sec_fetch_site_h = NULL;
    *avail_dict_count = 0;
    *sec_fetch_site_count = 0;

    for (i = 0; ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == sizeof("available-dictionary") - 1
            && ngx_memcmp(h[i].lowcase_key, "available-dictionary",
                          sizeof("available-dictionary") - 1) == 0)
        {
            (*avail_dict_count)++;
            if (*avail_dict_h == NULL) {
                *avail_dict_h = &h[i];
            }

        } else if (h[i].key.len == sizeof("sec-fetch-site") - 1
                   && ngx_memcmp(h[i].lowcase_key, "sec-fetch-site",
                                 sizeof("sec-fetch-site") - 1) == 0)
        {
            (*sec_fetch_site_count)++;
            if (*sec_fetch_site_h == NULL) {
                *sec_fetch_site_h = &h[i];
            }
        }
    }
}


/*
 * RFC 9842 dcz negotiation. Returns the configured dictionary this
 * response must be compressed against, or NULL for the plain zstd path.
 * Every requirement is a hard gate — on any miss the response falls back
 * to ordinary content negotiation, never to a broken dcz:
 *
 *   - the location has zstd_dcz_dict_file dictionaries;
 *   - the connection is a secure context (RFC 9842 section 8): TLS at
 *     this nginx, or zstd_dcz_assume_secure_transport on for a
 *     TLS-terminating proxy in front;
 *   - the request carries Available-Dictionary, a structured-field byte
 *     sequence (":base64:") decoding to exactly 32 bytes (the SHA-256 of
 *     the client's cached dictionary), and it matches one of ours;
 *   - Accept-Encoding lists dcz explicitly with q>0. The "*" wildcard
 *     deliberately does NOT match: only a client that actually holds the
 *     dictionary can decode dcz, so a blanket wildcard must not turn it
 *     on (see ngx_http_zstd_coding_weight);
 *   - Sec-Fetch-Site, when present, is "same-origin" or "none" (§8.3:
 *     dictionaries are same-origin-partitioned secrets; a cross-site
 *     response compressed against one leaks it). Browsers always send
 *     the header; its absence means a non-browser client, where the
 *     cross-origin read model does not apply.
 *
 * Dictionary-ID is intentionally not parsed: it only matters when the
 * operator sets id= in Use-As-Dictionary, and the hash alone is a
 * complete, collision-resistant key for the lookup below. (SHA-256 is
 * collision-RESISTANT, not collision-free -- the distinction does not
 * weaken the lookup, which indexes public dictionary identities, but the
 * stronger claim is not one SHA-256 makes.)
 */
/*
 * Decode an RFC 8941 byte-sequence Available-Dictionary header value
 * (":base64:") into a fixed-size digest buffer.
 *
 * Pulled out of ngx_http_zstd_dcz_negotiate() below as a pure function of
 * its inputs: no ngx_http_request_t, no connection log, no config
 * structures. That is deliberate -- it is the exact slice of the
 * negotiation logic that parses attacker-controlled bytes (the base64
 * length/prefix gate plus ngx_decode_base64() itself), and the
 * request/config entanglement in the caller is what previously made it
 * impossible to fuzz in isolation.
 *
 * `raw` is the full header value including the wrapping colons, exactly
 * as ngx_http_zstd_dcz_negotiate() receives it in h->value. `out` must
 * point at a buffer of at least NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN (48)
 * bytes -- NOT just NGX_HTTP_ZSTD_SHA256_DIGEST_LEN (32) -- and receives
 * the decoded digest on success. The larger size is load-bearing: the
 * length gate below only bounds the base64 *text* to 44 characters, and
 * an unpadded 44-character input (no trailing "=") decodes to 33 bytes,
 * one past a tight 32-byte buffer, before the post-decode length check
 * ever runs. A caller-supplied buffer smaller than
 * NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN reintroduces that overflow.
 *
 * Returns NGX_OK when raw is a well-formed byte-sequence decoding to
 * exactly NGX_HTTP_ZSTD_SHA256_DIGEST_LEN bytes (written to *out*),
 * NGX_DECLINED on malformed byte-sequence framing (bad length, or a
 * missing leading/trailing colon) -- detected before decoding, so *out*
 * is untouched -- and NGX_ERROR when the framing is well-formed but the
 * payload is not a 32-byte base64 value (undecodable, or decoding to a
 * length other than 32). On NGX_ERROR *out* may have been partially
 * written by ngx_decode_base64() and its contents are unspecified; the
 * caller must not read it unless NGX_OK was returned.
 *
 * The two failure values exist so ngx_http_zstd_dcz_negotiate() can log
 * which half rejected the header; both are equally fail-closed.
 */
static ngx_int_t
ngx_http_zstd_dcz_decode_digest(ngx_str_t raw,
    u_char out[NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN])
{
    ngx_str_t   b64, decoded;

    /*
     * RFC 8941 byte sequence: colon-delimited standard base64. 32 bytes
     * encode to 44 characters with padding (43 without); anything longer
     * cannot be a SHA-256 and is rejected before decoding.
     */
    if (raw.len < 2
        || raw.data[0] != ':'
        || raw.data[raw.len - 1] != ':'
        || raw.len - 2 > NGX_HTTP_ZSTD_DCZ_DIGEST_B64_LEN)
    {
        return NGX_DECLINED;
    }

    b64.data = raw.data + 1;
    b64.len = raw.len - 2;

    decoded.data = out;

    if (ngx_decode_base64(&decoded, &b64) != NGX_OK
        || decoded.len != NGX_HTTP_ZSTD_SHA256_DIGEST_LEN)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Orders zlcf->dcz_dicts by hash so the per-request negotiation lookup
 * can binary-search it once nelts crosses
 * NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD. Called once, at merge-config
 * time, after every zstd_dcz_dict_file push for this location is done
 * (see the ngx_conf_merge_ptr_value(conf->dcz_dicts, ...) call site) --
 * never at request time, so it cannot race a lookup and never runs
 * against a still-growing array. The merge-time duplicate-hash check
 * that runs before each push (see the "has the same hash as" error
 * above) already guarantees no two entries compare equal, so the sort
 * order is total and unambiguous.
 */
static int ngx_libc_cdecl
ngx_http_zstd_dcz_dict_cmp(const void *one, const void *two)
{
    const ngx_http_zstd_dcz_dict_t  *first, *second;

    first = one;
    second = two;

    return ngx_memcmp(first->hash, second->hash,
                       NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
}


static void
ngx_http_zstd_dcz_dict_sort(ngx_array_t *dcz_dicts)
{
    if (dcz_dicts->nelts > 1) {
        ngx_qsort(dcz_dicts->elts, (size_t) dcz_dicts->nelts,
                  sizeof(ngx_http_zstd_dcz_dict_t),
                  ngx_http_zstd_dcz_dict_cmp);
    }
}


/*
 * Finds the configured dcz dictionary whose SHA-256 equals the 32 bytes
 * at `buf`, or NULL if none matches. Pulled out of
 * ngx_http_zstd_dcz_negotiate() as a pure, log-free, allocation-free
 * function of (dcz_dicts, buf) so it can be extracted and unit-tested
 * standalone (see ci/tools/test_dcz_dict_lookup_unit.sh) against a
 * reference brute-force oracle -- this is the function the
 * NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD tradeoff lives in.
 *
 * Below the threshold a linear scan of 32-byte ngx_memcmp calls beats a
 * bsearch on this array size (see the threshold constant's comment for
 * the measurements); above it, dcz_dicts is sorted by hash at
 * merge-config time (ngx_http_zstd_dcz_dict_cmp()) and a binary search
 * wins. Both branches return a pointer INTO dcz_dicts->elts, never a
 * copy, and neither mutates the array.
 */
static ngx_http_zstd_dcz_dict_t *
ngx_http_zstd_dcz_dict_lookup(ngx_array_t *dcz_dicts,
    u_char buf[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN])
{
    ngx_uint_t                 i;
    ngx_http_zstd_dcz_dict_t  *dicts;

    dicts = dcz_dicts->elts;

    if (dcz_dicts->nelts > NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD) {
        ngx_int_t  lo, hi, mid;

        lo = 0;
        hi = (ngx_int_t) dcz_dicts->nelts - 1;

        while (lo <= hi) {
            ngx_int_t  c;

            mid = (lo + hi) / 2;
            c = ngx_memcmp(dicts[mid].hash, buf,
                           NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);

            if (c == 0) {
                return &dicts[mid];

            } else if (c < 0) {
                lo = mid + 1;

            } else {
                hi = mid - 1;
            }
        }

        return NULL;
    }

    for (i = 0; i < dcz_dicts->nelts; i++) {
        if (ngx_memcmp(dicts[i].hash, buf,
                       NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) == 0)
        {
            return &dicts[i];
        }
    }

    return NULL;
}


static ngx_http_zstd_dcz_dict_t *
ngx_http_zstd_dcz_negotiate(ngx_http_request_t *r,
    ngx_http_zstd_loc_conf_t *zlcf)
{
    u_char                     buf[NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN];
    ngx_int_t                  rc;
    ngx_uint_t                 secure;
    ngx_uint_t                 avail_dict_count, sec_fetch_site_count;
    ngx_table_elt_t           *avail_dict_h, *sec_fetch_site_h;
    ngx_http_zstd_dcz_dict_t  *dict;

    if (zlcf->dcz_dicts == NULL || zlcf->dcz_dicts->nelts == 0) {
        return NULL;
    }

    if (r != r->main) {
        return NULL;
    }

    /*
     * RFC 9842 section 8: compression dictionary transport MUST only be
     * used in a secure context. Dictionary-compressed responses leak
     * plaintext length information about content the dictionary already
     * describes, which is exactly the oracle a network attacker on a
     * cleartext hop wants. Fail closed: plain HTTP falls back to
     * ordinary zstd.
     *
     * r->connection->ssl is NULL when a proxy in front of nginx
     * terminated TLS. That deployment is supported only by an explicit
     * operator acknowledgement (zstd_dcz_assume_secure_transport on),
     * never by trusting a request header: X-Forwarded-Proto and friends
     * are client-supplied on a directly reachable listener, so
     * inferring "https" from one would let any client re-enable dcz
     * over cleartext by asking for it.
     *
     * The guard mirrors ngx_connection_t's own condition for the ssl
     * member (ngx_connection.h: `#if (NGX_SSL || NGX_COMPAT)`), not
     * NGX_SSL alone: this module is built --with-compat, where the
     * field exists (and is always NULL) without an SSL-capable nginx.
     * Testing a narrower macro would compile the read out of exactly
     * the build the module ships in.
     */
#if (NGX_SSL || NGX_COMPAT)
    secure = (r->connection->ssl != NULL);
#else
    secure = 0;
#endif

    if (!secure && !zlcf->dcz_assume_secure) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, not a secure context (RFC 9842 "
                       "section 8); set "
                       "\"zstd_dcz_assume_secure_transport on\" if TLS is "
                       "terminated upstream");
        return NULL;
    }

    /*
     * Accept-Encoding is in nginx's headers_in table. nginx >= 1.23 chains
     * duplicate lines while older supported nginx leaves them in the list;
     * EVERY line is
     * evaluated, not just the first: RFC 9110 section 5.3 makes a
     * repeated list-valued field identical to the single comma-joined
     * field, so a client that split "zstd, dcz" across two lines
     * advertises dcz exactly as much as one that sent it on one.
     *
     * This deliberately shares ngx_http_zstd_request_coding_weight() with
     * the plain-zstd path in ngx_http_zstd_accepts(). The two used to
     * carry independent copies of the first-line-only assumption, which
     * is how one negotiation contract turned into two -- the shared
     * helper is what stops them drifting again. allow_wildcard stays 0
     * here for the reason the gate list above gives: only a client that
     * actually holds the dictionary can decode dcz, so "*" must not turn
     * it on. The duplicate-coding rule (an explicit q=0 anywhere is
     * final) is documented on the helper.
     */
    /*
     * Cheapest gate first: reject before paying for the header-list walk
     * or the base64 decode below. No client sends "dcz" in Accept-Encoding
     * unless it already holds a dictionary, so this rejects essentially
     * all real traffic -- the two calls it now guards
     * (ngx_http_zstd_collect_dcz_headers() and
     * ngx_http_zstd_dcz_decode_digest()) are provably wasted work on that
     * path. All gates below are pure predicates that only return NULL, so
     * reordering is behaviour-preserving for the accept/reject decision --
     * EXCEPT for which debug log line fires for a request that fails both
     * this gate and one of the gates below: this one now wins and its
     * message is emitted instead of theirs. See t/03-dcz.t for a test
     * pinning that order.
     */
    if (ngx_http_zstd_request_coding_weight(r, "dcz",
                                          sizeof("dcz") - 1, 0) <= 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, no explicit dcz in Accept-Encoding");
        return NULL;
    }

    /*
     * Collect both dcz-negotiation headers in a single header-list walk.
     * This eliminates a second traversal over what can be a long list.
     */
    ngx_http_zstd_collect_dcz_headers(r, &avail_dict_h,
                                       &avail_dict_count,
                                       &sec_fetch_site_h,
                                       &sec_fetch_site_count);

    if (avail_dict_h == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, no Available-Dictionary header");
        return NULL;
    }

    if (avail_dict_count > 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, %ui Available-Dictionary headers",
                       avail_dict_count);
        return NULL;
    }

    /* RFC 8941 byte sequence validation — see dcz_decode_digest() */
    rc = ngx_http_zstd_dcz_decode_digest(avail_dict_h->value, buf);

    if (rc == NGX_DECLINED) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: malformed Available-Dictionary (%uz bytes)",
                       avail_dict_h->value.len);
        return NULL;
    }

    if (rc != NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: Available-Dictionary (%uz bytes) is not a "
                       "valid base64 SHA-256", avail_dict_h->value.len);
        return NULL;
    }

    /*
     * More than one Sec-Fetch-Site is never a browser and cannot be
     * evaluated: fail closed rather than trust the first line.
     */
    if (sec_fetch_site_count > 1) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, %ui Sec-Fetch-Site headers",
                       sec_fetch_site_count);
        return NULL;
    }

    if (sec_fetch_site_h != NULL
        && !(sec_fetch_site_h->value.len == sizeof("same-origin") - 1
             && ngx_strncasecmp(sec_fetch_site_h->value.data,
                                (u_char *) "same-origin",
                                sizeof("same-origin") - 1) == 0)
        && !(sec_fetch_site_h->value.len == sizeof("none") - 1
             && ngx_strncasecmp(sec_fetch_site_h->value.data,
                                (u_char *) "none",
                                sizeof("none") - 1) == 0))
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: skip, Sec-Fetch-Site (%uz bytes, "
                       "not same-origin or none)", sec_fetch_site_h->value.len);
        return NULL;
    }

    dict = ngx_http_zstd_dcz_dict_lookup(zlcf->dcz_dicts, buf);

    if (dict != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd dcz: dictionary \"%V\" negotiated",
                       &dict->file);
        return dict;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd dcz: skip, no configured dictionary matches "
                   "Available-Dictionary");
    return NULL;
}


#ifdef NGX_TEST_HARNESS
/*
 * Snapshot this request's free-chain length and out_buf state for the
 * probe endpoint. Called from ngx_http_zstd_body_filter() at both return
 * points of its main loop -- see the call sites. Kept here (not in
 * ngx_http_zstd_probe_hooks.c) because it reads ngx_http_zstd_ctx_t, a
 * typedef local to this translation unit; the probe file receives only
 * the already-derived scalars via ngx_http_zstd_probe_note_ctx_state(),
 * never the ctx pointer itself.
 */
static void
ngx_http_zstd_probe_snapshot_ctx(ngx_http_zstd_ctx_t *ctx)
{
    ngx_chain_t  *cl;
    ngx_uint_t    free_links;

    free_links = 0;

    for (cl = ctx->free; cl; cl = cl->next) {
        free_links++;
    }

    ngx_http_zstd_probe_note_ctx_state(free_links,
        ctx->out_buf != NULL,
        ctx->out_buf != NULL
            ? (size_t) (ctx->out_buf->end - ctx->out_buf->start) : 0);
}
#endif


/*
 * Length-independent input cap check, split out of ngx_http_zstd_body_filter
 * so a unit fixture (ci/tools/test_max_length_cap_unit.sh) can extract it
 * verbatim and drive it against ctx->bytes_in > INT32_MAX on a genuine
 * 32-bit off_t build (plain -m32, no _FILE_OFFSET_BITS override) -- the one
 * shape where the signed-cast form this replaced (comparing the uint64_t
 * accumulator against zlcf->max_length via an (off_t) cast) could produce a
 * wrong answer, by truncating bytes_in through a narrower off_t. nginx
 * normally builds with largefile support, which widens off_t to 64 bits
 * even on a 32-bit platform, so this is 32-bit-off_t hardening rather than
 * a gap reachable from a stock build: bytes_in is unsigned and max_length
 * is ssize_t, and the check fires once bytes_in exceeds max_length, treating
 * NGX_CONF_UNSET (-1) as "no cap configured". max_length itself can never
 * be negative at this point in practice (ngx_conf_set_size_slot rejects a
 * negative literal upstream), but the >= 0 guard is kept as defence against
 * sentinel drift in this field, not against user input.
 */
static ngx_flag_t
ngx_http_zstd_max_length_exceeded(uint64_t bytes_in, ssize_t max_length)
{
    return max_length != NGX_CONF_UNSET
           && max_length >= 0
           && bytes_in > (uint64_t) max_length;
}


/*
 * Retain only input that this body-filter invocation could not consume.
 * Incoming chain links belong to the caller and are safe to walk only while
 * its callback is active.  The buffers themselves have request lifetime, as
 * with ngx_chain_add_copy(); only the link wrappers need pool-owned copies.
 *
 * Append through last_in because an earlier callback's retained links may
 * still be queued under downstream backpressure.  A partial allocation
 * failure deliberately leaves any links already copied on ctx->in: the
 * caller routes the failure through the terminal error path, so those copies
 * are never resumed and no caller-owned link is retained or reused.
 */
static ngx_int_t
ngx_http_zstd_filter_copy_input(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_chain_t  *link;

    while (in) {
        link = ngx_http_zstd_alloc_chain_link(r->pool);
        if (link == NULL) {
            return NGX_ERROR;
        }

        link->buf = in->buf;
        link->next = NULL;

        *ctx->last_in = link;
        ctx->last_in = &link->next;

#ifdef NGX_TEST_HARNESS
        ngx_http_zstd_probe_note_chain_link();
#endif

        in = in->next;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                  flush, rc;
    ngx_chain_t               *cl;
    ngx_http_zstd_ctx_t       *ctx;
    ngx_http_zstd_loc_conf_t  *zlcf;


    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http zstd filter");

    /*
     * A no-op initial callback: no CCtx yet, no incoming data, nothing
     * already queued or in flight downstream. There is no compressed or
     * downstream state to flush, so initializing the CCtx (and, for dcz,
     * queuing the 40-byte prefix) here would only be undone by whatever
     * later call actually carries data or the end-of-stream signal.
     */
    if (!ctx->cctx_ready && in == NULL && ctx->in == NULL
        && ctx->busy == NULL)
    {
        return NGX_OK;
    }

    /*
     * Fetch the location conf once. It cannot change for the lifetime of
     * a request, so resolving it only past the no-op early return avoids
     * module-index indirection on paths that do not need it.
     */
    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (!ctx->cctx_ready) {
        /*
         * First call: configure the CCtx for this request. Latched by an
         * explicit flag — do NOT infer this from buffer_in.src == NULL;
         * see the cctx_ready comment in ngx_http_zstd_ctx_t.
         */
        if (ngx_http_zstd_filter_init_cctx(r, ctx, zlcf) != NGX_OK) {
            goto failed;
        }

        /*
         * dcz responses start with the fixed 40-byte frame header (RFC
         * 9842 §2.2). It is no longer queued here as its own buffer/chain
         * link: ngx_http_zstd_filter_get_buf() reserves and fills the
         * first 40 bytes of the first compressor output buffer with it
         * (ctx->dcz_header_sent still guards against duplicating it, and
         * is now set there instead of here). Nothing to do on this path.
         */

        ctx->cctx_ready = 1;
    }

    if (in) {
        /* The caller-owned chain is consumed through the local cursor below. */
        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        /*
         * Same reason as the invalidation after the other
         * ngx_chain_update_chains() below: the buffer ctx->out_buf points
         * at may have just been recycled onto the free chain. Reaching
         * here with a stale non-NULL out_buf is currently unreachable --
         * it would need get_buf's top guard to fail, which requires a
         * memzero'd buffer_out -- but that argument spans three functions
         * and a future edit should not have to re-derive it to stay safe.
         */
        ctx->out_buf = NULL;

        flush = 0;
        ctx->nomem = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            rc = ngx_http_zstd_filter_add_data(r, ctx, &in);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            /*
             * Length-independent input cap. The header filter rejects
             * responses whose advertised Content-Length exceeds
             * zstd_max_length, but that gate only sees the *declared* length:
             * a chunked/streaming response carries none, and a misbehaving
             * known-length upstream can stream more bytes than it declared.
             * Either way an abusive or runaway upstream could feed the
             * compressor unbounded input (worker CPU/memory exhaustion).
             * Enforce the limit against the running input total here,
             * regardless of whether a Content-Length was advertised.
             * Compression has already started and the client is receiving a
             * Content-Encoding: zstd stream, so the only safe action is to
             * fail the request — protecting the worker is preferred over
             * completing one runaway response.
             */
            if (ngx_http_zstd_max_length_exceeded(ctx->bytes_in,
                                                   zlcf->max_length))
            {
                if (ctx->pledged_size >= 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "zstd: input exceeded zstd_max_length (%O) "
                                  "after %uL bytes on a response with declared "
                                  "Content-Length %O; aborting to protect the "
                                  "worker", (off_t) zlcf->max_length,
                                  ctx->bytes_in,
                                  ctx->pledged_size);
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "zstd: input exceeded zstd_max_length (%O) "
                                  "after %uL bytes on a response with no "
                                  "Content-Length; aborting to protect the "
                                  "worker", (off_t) zlcf->max_length,
                                  ctx->bytes_in);
                }
                goto failed;
            }

            rc = ngx_http_zstd_filter_get_buf(r, ctx, zlcf);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DECLINED) {
                break;
            }

            rc = ngx_http_zstd_filter_compress(r, ctx,
                                               ctx->in == NULL && in == NULL);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_OK) {
                break;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            if (in != NULL
                && ngx_http_zstd_filter_copy_input(r, ctx, in) != NGX_OK)
            {
                goto failed;
            }

#ifdef NGX_TEST_HARNESS
            ngx_http_zstd_probe_snapshot_ctx(ctx);
#endif
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        /* After chain update, buffers may have been recycled or reassigned.
         * Invalidate ctx->out_buf to force fresh buffer allocation/validation
         * on next compression iteration to prevent
         * use-after-free of recycled buffers. */
        ctx->out_buf = NULL;

        ctx->last_out = &ctx->out;
        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
#ifdef NGX_TEST_HARNESS
            ngx_http_zstd_probe_snapshot_ctx(ctx);
#endif
            return rc;
        }
    }

failed:

    ctx->aborted = 1;
    ctx->done = 1;

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zstd_filter_compress(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx,
    ngx_uint_t no_more_input)
{
    size_t            zrc, pos_in, pos_out;  /* zrc: ZSTD_compressStream2
                                              * bytes-remaining hint, not an
                                              * NGX_* code */
    ngx_uint_t        last;
    ZSTD_EndDirective directive;
    ngx_chain_t      *cl;
    ngx_buf_t        *b;
    ZSTD_CCtx        *cctx;

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress in: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    pos_in  = ctx->buffer_in.pos;
    pos_out = ctx->buffer_out.pos;

    /* Determine the compression directive. */
    if (ctx->action == NGX_HTTP_ZSTD_FILTER_END
        || (ctx->last && no_more_input))
    {
        /*
         * END wins, and it is selected as soon as this is provably the
         * final call's input rather than one iteration later.
         *
         * `ctx->last && no_more_input` is the state machine's own
         * COMPRESS->END transition predicate (below) minus its
         * "buffer_in fully drained" clause. That clause is what forced a
         * separate ZSTD_e_continue call first: the transition could only
         * fire once libzstd had already eaten the buffer, so the frame
         * was closed by a SECOND call carrying no new input. libzstd does
         * not need that. ZSTD_e_end accepts pending input, consumes what
         * it can and closes the frame in the same call, returning
         * non-zero while the epilogue still has bytes to write -- which
         * the existing `zrc > 0 -> ctx->redo = 1` arm below already
         * re-drives, unchanged. Dropping the clause therefore removes one
         * ZSTD_compressStream2() call from every completed response and
         * lets libzstd take its documented first-call ZSTD_e_end fast
         * path (ZSTD_compress2()) when the whole body and enough output
         * space are present.
         *
         * no_more_input is load-bearing: it proves neither a pool-owned link
         * retained from an earlier callback nor a caller-owned link on this
         * callback's local cursor is queued behind this buffer. Selecting
         * END with input still queued would close the frame early and
         * truncate the body -- the 131072-byte truncation PR #49's transition
         * predicate was written to prevent.
         *
         * Compressed bytes are allowed to differ from the two-call
         * sequence (a frame is a few bytes smaller when libzstd sees the
         * whole input at once). Frame VALIDITY and byte-identical
         * decoded plaintext are the contract; the exact compressed byte
         * stream is deliberately not one.
         */
        directive = ZSTD_e_end;

    } else if (ctx->action == NGX_HTTP_ZSTD_FILTER_FLUSH || ctx->flush) {
        /*
         * A pending flush (ctx->flush) must map to ZSTD_e_flush even while
         * the action state machine is still COMPRESS: that machine only
         * transitions COMPRESS->FLUSH *after* a call that returned rc > 0
         * (zstd already had output to drain). Under `proxy_buffering off`
         * the upstream forces a flush around a chunk that zstd
         * consumes/buffers internally with rc == 0; if the directive stayed
         * ZSTD_e_continue there, libzstd is never told to flush and holds
         * those bytes indefinitely. Mapping ctx->flush -> ZSTD_e_flush
         * forces libzstd to disgorge whatever it has buffered, exactly as
         * the stock nginx gzip/brotli body filters issue a sync flush on a
         * pending flush.
         */
        directive = ZSTD_e_flush;
    } else {
        directive = ZSTD_e_continue;
    }

    cctx = ctx->cctx;
    if (cctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: request CCtx not initialized");
        return NGX_ERROR;
    }

#ifdef NGX_TEST_HARNESS
    {
        /*
         * Codec fault injection (CI harness builds only; this whole block
         * does not exist in a packaged build -- see filter/config for the
         * two switches, and ngx_http_zstd_probe_hooks.h for the outcome
         * encoding).
         *
         * Site selection is exactly the testkit's split: the ZSTD_e_end
         * call is the end-of-frame site (CODEC_END), every other directive
         * is the streaming site (CODEC). `directive` is already final here
         * -- it is computed above and nothing between reassigns it.
         *
         * The check is placed BEFORE the real call and SUBSTITUTES for it
         * rather than corrupting its result afterwards, because both
         * outcomes have to be indistinguishable from libzstd having
         * behaved that way: an injected error must not leave the encoder
         * half-advanced, and the zero-output outcome must leave
         * buffer_in/buffer_out untouched, which is only true if the real
         * call never ran.
         */
        switch (ngx_http_zstd_probe_codec_fault(directive == ZSTD_e_end)) {

        case NGX_HTTP_ZSTD_PROBE_CODEC_ERROR:
            /*
             * A value ZSTD_isError() reports true for.
             *
             * (size_t) -1 and not a named ZSTD_error_* enumerator:
             * ZSTD_ErrorCode and its enumerators live in zstd_errors.h /
             * the ZSTD_STATIC_LINKING_ONLY section, which this module only
             * conditionally has (see the ZSTD_VERSION_NUMBER >= 10400
             * guards elsewhere in this file), whereas ZSTD_isError() is
             * stable API always available. ZSTD_isError() tests
             * `result > (size_t) -ZSTD_error_maxCode`, and (size_t) -1 is
             * the largest representable size_t, so it is above maxCode for
             * every libzstd that has ever shipped -- the one value that
             * cannot stop being an error when the enum grows.
             *
             * Falls straight into the existing ZSTD_isError arm below, so
             * there is no second error path to keep in sync; the request
             * fails exactly as it would on a real codec failure, including
             * the [crit]-level log line (which is why fault-injection tests
             * must set PROBER_ALLOW_LOG).
             */
            zrc = (size_t) -1;
            break;

        case NGX_HTTP_ZSTD_PROBE_CODEC_ZERO:
            /*
             * Success with zero output: the encoder accepted nothing and
             * produced nothing. buffer_in.pos and buffer_out.pos are left
             * exactly as they were, so the deltas computed below are both
             * 0 and ctx->out_buf keeps whatever it already held.
             *
             * zrc MUST be 0, not a positive remainder. 0 means "fully
             * flushed" and is what drives the two arms this outcome exists
             * to reach: with a non-END directive and ctx->last set it takes
             * the END-transition arm, sees a zero output delta and returns
             * NGX_AGAIN so a real ZSTD_e_end call still follows; with
             * ZSTD_e_end it makes `last` true, which is what lets the
             * empty-out_buf suppression arm below be evaluated at all.
             * A positive zrc would instead set ctx->redo and, on the END
             * site, spin forever producing no output -- a live-lock, not a
             * fault injection.
             */
            zrc = 0;
            break;

        case NGX_HTTP_ZSTD_PROBE_CODEC_NONE:
        default:
            zrc = ZSTD_compressStream2(cctx, &ctx->buffer_out,
                                       &ctx->buffer_in, directive);
            break;
        }
    }
#else
    zrc = ZSTD_compressStream2(cctx, &ctx->buffer_out, &ctx->buffer_in,
                               directive);
#endif

    if (ZSTD_isError(zrc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_compressStream2() failed: %s",
                      ZSTD_getErrorName(zrc));
        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress out: src:%p pos:%uz size:%uz "
                   "dst:%p pos:%uz size:%uz",
                   ctx->buffer_in.src,  ctx->buffer_in.pos,
                   ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    /*
     * Guard the zero-delta case instead of unconditionally adding: when the
     * dequeued link is a data-less carrier (last_buf/flush, pos == NULL —
     * see add_data), buffer_in still describes the previous, fully-drained
     * buffer, so the delta is provably 0 — but `NULL + 0` is still undefined
     * pointer arithmetic. gcc's UBSan lets it pass; clang's aborts with
     * "applying zero offset to null pointer".
     */
    if (ctx->buffer_in.pos != pos_in) {
        ctx->in_buf->pos += ctx->buffer_in.pos - pos_in;
    }

    /*
     * Same zero-delta guard as the input side above. Here ctx->out_buf and
     * ctx->out_buf->last are both provably non-NULL -- get_buf() returns
     * NGX_OK only after the explicit NULL check, and compress() has the
     * single caller in the body-filter loop -- so this is defensive
     * symmetry, not a reachable fix. It keeps the `NULL + 0` UB out of the
     * expression if ->last ever becomes NULL-able the way in_buf->pos is.
     * Note it does NOT guard a NULL ctx->out_buf: that would fault on the
     * dereference regardless of the delta.
     */
    if (ctx->buffer_out.pos != pos_out) {
        ctx->out_buf->last += ctx->buffer_out.pos - pos_out;
    }

    ctx->redo = 0;

    /* PR #49: State machine logic for action transitions */
    if (zrc > 0) {
        /*
         * rc > 0: zstd has buffered data. For COMPRESS, transition to FLUSH
         * to drain libzstd's internal buffers. For FLUSH/END, keep the action.
         *
         * A call that ran ZSTD_e_end is already in the terminal phase even
         * when ctx->action has not caught up (the directive selection above
         * picks END directly from `ctx->last && no_more_input`, one
         * iteration before this machine would have transitioned). Record
         * that here rather than parking the action in FLUSH: a FLUSH action
         * with ctx->last set would still re-select END on the next
         * iteration -- the directive is correct either way -- but leaving
         * the state saying "flushing" while the frame epilogue is being
         * written misdescribes the stream to every later reader of
         * ctx->action, including the emit trace and the flush accounting
         * below.
         */
        if (directive == ZSTD_e_end) {
            ctx->action = NGX_HTTP_ZSTD_FILTER_END;

        } else if (ctx->action == NGX_HTTP_ZSTD_FILTER_COMPRESS) {
            ctx->action = NGX_HTTP_ZSTD_FILTER_FLUSH;
        }
        ctx->redo = 1;

    } else if (ctx->last && ctx->action != NGX_HTTP_ZSTD_FILTER_END
               && directive != ZSTD_e_end
               && ctx->buffer_in.pos >= ctx->buffer_in.size
               && no_more_input)
    {
        /*
         * `directive != ZSTD_e_end` is what keeps this arm meaning what
         * its body says. It exists for the case where the call that just
         * ran did NOT close the frame, so a further ZSTD_e_end iteration
         * still has to happen -- which is why it can return NGX_AGAIN and
         * suppress the buffer. Since the directive selection above may now
         * pick END on this very call, the arm would otherwise be reachable
         * with the frame already terminal (zrc == 0, directive
         * ZSTD_e_end): it would then swallow the zero-output terminal
         * buffer and return NGX_AGAIN forever instead of emitting the
         * zero-length last_buf -- the request hang PR #196 fixed on this
         * same path. With the guard, a terminal END call falls through to
         * the `last` computation below, exactly as before.
         *
         * PR #49: All input consumed; transition to END only when:
         * - last flag is set (we know this is the final chunk)
         * - input buffer fully drained (no more bytes to feed libzstd)
         * - no more chain links queued (all input streams exhausted)
         * This prevents premature END transitions that cause 131072-byte
         * truncation.
         */
        ctx->action = NGX_HTTP_ZSTD_FILTER_END;
        ctx->redo   = 1;

        /*
         * We have only just switched to END; the call above ran with
         * ZSTD_e_continue/flush and has NOT yet written the zstd end-of-frame
         * marker. If it produced no output, force another iteration so
         * ZSTD_e_end runs. If it did produce output, fall through to emit
         * those (valid, non-terminal) bytes — but `last` must stay false this
         * iteration so we do not set last_buf before the end marker exists.
         *
         * Keyed on THIS call's delta (buffer_out.pos - pos_out), not
         * ngx_buf_size(ctx->out_buf): the whole-buffer size also counts the
         * dcz 40-byte prefix that ngx_http_zstd_filter_get_buf() may have
         * already written into a freshly allocated buffer before this call
         * ever ran. Checking the whole-buffer size made a buffer holding
         * only the prefix look "non-empty" and forced a premature,
         * non-terminal 40-byte emission instead of forcing the extra
         * iteration that actually reaches ZSTD_e_end -- doubling the
         * output buffers this response needed instead of the reduction
         * this prefix-inlining change is for. The delta is 0 in both the
         * prefix and non-prefix case whenever this call itself wrote
         * nothing, so behaviour for a non-dcz response is unchanged.
         */
        if (ctx->buffer_out.pos - pos_out == 0) {
            return NGX_AGAIN;
        }

    } else if (ctx->action != NGX_HTTP_ZSTD_FILTER_END) {
        /* Restore to COMPRESS after FLUSH drains (unless transitioning
         * to END) */
        ctx->action = NGX_HTTP_ZSTD_FILTER_COMPRESS;
    }

    /*
     * Terminal frame: the call that just ran used ZSTD_e_end (so `directive`
     * — captured before any action transition above — is ZSTD_e_end) and
     * libzstd reports the frame is fully flushed (rc == 0). Keyed on
     * `directive`, not `ctx->action`, because the COMPRESS→END transition
     * above mutates ctx->action *after* the compress call; using ctx->action
     * here would declare the stream terminal one iteration too early and
     * truncate it (no end-of-frame marker written yet).
     *
     * Evaluated before the empty-buffer early return below: a terminal
     * ZSTD_e_end that produces zero output bytes (everything drained on a
     * prior iteration) must still emit a zero-length last_buf, otherwise the
     * request loops forever with NGX_HTTP_GZIP_BUFFERED set and hangs until
     * timeout.
     */
    last = zrc == 0 && ctx->last && directive == ZSTD_e_end;

    /*
     * Structured emit-decision trace. Permanent: compiled out of
     * release builds via NGX_DEBUG (zero runtime cost when off),
     * visible with `error_log ... debug`. This is the single most
     * useful probe for the module's recurring truncation /
     * zero-size-buffer / terminal-frame bug class — it records exactly
     * what the emit guard saw (output size, libzstd return, terminal
     * and flush state, action) so future diagnosis is one
     * `error_log debug` away instead of a patch/rebuild cycle. Behaviour
     * is unchanged; this only observes.
     */
    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd emit?: outsz:%uz rc0:%d last:%d ctx_last:%d "
                   "ctx_flush:%d action:%d",
                   (size_t) ngx_buf_size(ctx->out_buf), zrc == 0, last,
                   ctx->last, ctx->flush, (ngx_uint_t) ctx->action);

    /*
     * Empty, non-terminal output buffer handling.
     *
     * Two distinct empty-buffer cases reach here:
     *
     *  1. A content-less *completed flush*: ctx->flush is set and the
     *     ZSTD_e_flush call returned rc == 0 with zero bytes produced.
     *     Per the libzstd contract rc == 0 from a flush means the
     *     encoder is fully drained — there is genuinely nothing to
     *     send. The OLD code's `!(rc == 0 && ctx->flush)` exception
     *     forwarded a zero-size buffer here, which nginx's
     *     ngx_http_write_filter rejects ("zero size buf in writer")
     *     and aborts the request — bug B, under `proxy_buffering off`
     *     where the upstream forces such flushes.
     *
     *     The flush is COMPLETE, so satisfy and clear it here: drop the
     *     NGX_HTTP_GZIP_BUFFERED bit and ctx->flush, emit nothing, and
     *     return NGX_AGAIN. Clearing ctx->flush is what makes the body
     *     filter's inner loop terminate: ngx_http_zstd_filter_add_data()
     *     keeps the loop alive while ctx->flush is set (expecting this
     *     function to consume it); a naive "suppress the empty buffer
     *     but leave ctx->flush set" change spins the worker at 100% CPU
     *     (a NGX_AGAIN livelock — observed). Clearing it lets the next
     *     add_data() fall through to NGX_DECLINED (input drained) and
     *     break the loop cleanly.
     *
     *  2. Any other empty, non-terminal buffer (no pending flush):
     *     nothing to send and nothing to satisfy — just suppress and
     *     return NGX_AGAIN as before.
     *
     * The genuine terminal empty buffer (last) is never suppressed; it
     * falls through to be emitted with last_buf set below.
     */
    if (ngx_buf_size(ctx->out_buf) == 0 && !last) {
        if (zrc == 0 && ctx->flush) {
            r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;
            ctx->flush = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd emit: content-less flush completed, "
                           "cleared (no empty buffer forwarded)");
        } else {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd emit: suppressed empty non-terminal "
                           "buffer");
        }
        return NGX_AGAIN;
    }

    cl = ngx_http_zstd_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = ctx->out_buf;

    if (zrc == 0 && (ctx->flush || last)) {
        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        b->flush = ctx->flush && !ctx->last;
        b->last_buf = last;

        ctx->done  = b->last_buf;
        ctx->flush = 0;
    }

    /*
     * A terminal frame that produced no output bytes (everything drained on a
     * prior iteration) still has to emit the zero-length last_buf -- that is
     * what the suppression arm above deliberately lets through. But the writer
     * only tolerates a zero-size buffer when ngx_buf_special() accepts it, and
     * that macro requires !ngx_buf_in_memory(b) && !b->in_file. out_buf comes
     * from ngx_http_zstd_create_temp_buf(), so `temporary` is set and
     * start/end point at a real allocation: ngx_buf_in_memory() stays true
     * even once the buffer is fully drained, the special test fails, and
     * ngx_http_write_filter logs
     * "zero size buf in writer" and aborts the response mid-stream.
     *
     * Clearing `temporary` on an empty buffer is exactly what nginx's own gzip
     * filter does for this case (ngx_http_gzip_filter_module.c, in its
     * deflateEnd path). `recycled` goes with it: a zero-size buffer has nothing
     * to reclaim, and leaving the flag set on a buffer the writer treats as
     * special only invites ngx_chain_update_chains() to reason about a buffer
     * that no longer describes memory.
     *
     * Only the size-0 case is touched, so a normal terminal buffer carrying
     * bytes keeps both flags and its ordinary in-memory identity.
     */
    if (ngx_buf_size(b) == 0) {
        b->temporary = 0;
        b->recycled = 0;
    }

    ctx->bytes_out += ngx_buf_size(b);

    cl->next = NULL;
    cl->buf  = b;

    *ctx->last_out = cl;
    ctx->last_out  = &cl->next;

    /*
     * Invalidate out_buf to force get_buf() to acquire a fresh buffer on the
     * next iteration. The guard at get_buf's top (ctx->out_buf != NULL &&
     * ctx->buffer_out.pos < ctx->buffer_out.size) fails when out_buf is NULL,
     * triggering buffer allocation or free-chain reuse.
     *
     * The buffer_out fields (dst, pos, size) are stale after this function
     * queues b; they are always set by get_buf() before compress() reads them.
     * Safety proof: NGX_DECLINED from get_buf() (nomem case) and error paths
     * route through ngx_http_next_body_filter() to send queued buffers before
     * returning (body filter), then ngx_chain_update_chains() recycles buffers
     * and returns, then out_buf = NULL is set before any reentry to compress().
     * No path uses stale buffer_out after queueing.
     */
    ctx->out_buf = NULL;

    return last ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_zstd_filter_add_data(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx,
    ngx_chain_t **in)
{
    ngx_chain_t  *cl;
    ngx_uint_t    retained;

    if (ctx->buffer_in.pos < ctx->buffer_in.size
        || ctx->flush
        || ctx->last
        || ctx->redo)
    {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd in: %p", ctx->in);

    if (ctx->in == NULL && *in == NULL) {
        return NGX_DECLINED;
    }

    /*
     * Drain links retained by an earlier callback before touching this
     * callback's chain.  Retained wrappers are pool-owned and must go back to
     * the pool free list; current-callback wrappers remain caller-owned and
     * are merely advanced through the local cursor.
     */
    retained = ctx->in != NULL;

    if (retained) {
        cl = ctx->in;
        ctx->in = cl->next;

        if (ctx->in == NULL) {
            ctx->last_in = &ctx->in;
        }

    } else {
        cl = *in;
        *in = cl->next;
    }

    ctx->in_buf = cl->buf;

    /*
     * ngx_free_chain() overwrites cl->next.  Never call it for the local
     * cursor: that would mutate a caller-owned chain while its callback is
     * active and could corrupt the upstream filter's bookkeeping.
     */
    if (retained) {
        ngx_free_chain(r->pool, cl);
    }

    /*
     * Test last_buf FIRST, then flush — matching the order used by the
     * nginx gzip and brotli body filters
     * (ngx_http_gzip_filter_module.c / brotli filter). An upstream
     * terminal chain link can legitimately carry BOTH last_buf=1 and
     * flush=1 (e.g. proxy_buffering off + the upstream finalising its
     * stream): with the reverse order ctx->flush wins, ctx->last is
     * never set, the END-action transition below never fires, and the
     * stream is sent without its terminal zstd frame — the connection
     * hangs or the decoder sees a truncated frame. End-of-stream
     * implies a flush at the writer layer, so prioritising last_buf
     * loses nothing.
     */
    if (ctx->in_buf->last_buf) {
        ctx->last = 1;

    } else if (ctx->in_buf->flush) {
        ctx->flush = 1;
    }

    size_t in_size = ngx_buf_size(ctx->in_buf);

    if (in_size == 0) {
        /*
         * Data-less buffer (flush/sync/last carrier, or an empty data
         * buf). Its signal flags were captured above; never load it into
         * buffer_in. These bufs can carry pos == NULL (ngx_buf_special()),
         * and installing that as buffer_in.src both hands libzstd a NULL
         * src and clobbers the pointer other code may treat as state (the
         * old init_cctx first-call check did — see cctx_ready). If last or
         * flush was just set, return OK so the compress step runs the
         * end/flush immediately; otherwise skip to the next link.
         */
        return (ctx->last || ctx->flush) ? NGX_OK : NGX_AGAIN;
    }

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = in_size;

    ctx->bytes_in += in_size;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_zstd_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    size_t      data_offset;
    u_char     *allocation;
    ngx_buf_t  *b;

    data_offset = ngx_align(sizeof(ngx_buf_t), NGX_ALIGNMENT);

    if (size > NGX_MAX_SIZE_T_VALUE - data_offset) {
        return NULL;
    }

    allocation = ngx_http_zstd_palloc(pool, data_offset + size);
    if (allocation == NULL) {
        return NULL;
    }

    b = (ngx_buf_t *) allocation;
    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = allocation + data_offset;
    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + size;
    b->temporary = 1;

    return b;
}


static ngx_int_t
ngx_http_zstd_filter_get_buf(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx,
    ngx_http_zstd_loc_conf_t *zlcf)
{
    ngx_chain_t  *cl;

    /*
     * Keep using the current output buffer only if it still exists AND has
     * room. The body filter deliberately sets ctx->out_buf = NULL after
     * ngx_chain_update_chains() (to avoid touching a buffer that was just
     * recycled onto the free/busy chains). On a response large enough to
     * need more than one ZSTD_CStreamOutSize output buffer (chunked /
     * no-Content-Length is the common trigger), the inner compress loop can
     * re-enter get_buf with ctx->out_buf == NULL while ctx->buffer_out still
     * looks non-full. Without the NULL check this returned NGX_OK and the
     * very next ngx_http_zstd_filter_compress() dereferenced the NULL
     * ctx->out_buf ("ctx->out_buf->last += ...") — a worker SIGSEGV that
     * only manifests past the first ~128 KB of output. Require a live
     * out_buf here so an invalidated one always forces a fresh acquire.
     */
    if (ctx->out_buf != NULL && ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        ctx->out_buf = cl->buf;
        ngx_free_chain(r->pool, cl);

        /*
         * ngx_chain_update_chains() resets pos/last on a recycled buffer but
         * NOT the control flags. This buffer may previously have carried
         * flush / last_buf / last_in_chain (set in the compress step before
         * it went downstream). Clear them here so a later ordinary data
         * buffer cannot trigger a spurious downstream flush or a false
         * end-of-stream marker. See P2.
         */
        ctx->out_buf->flush = 0;
        ctx->out_buf->sync = 0;
        ctx->out_buf->last_buf = 0;
        ctx->out_buf->last_in_chain = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: reused free buffer %p", ctx->out_buf);

    } else if (ctx->bufs < zlcf->bufs.num) {
        size_t      buf_size = zlcf->bufs.size;
        ngx_uint_t  first_buf = ctx->bufs == 0;

        /*
         * The 40-byte dcz skippable-frame prefix (RFC 9842 §2.2) rides in
         * the front of THIS buffer instead of its own temp buffer/chain
         * link: reserve the space here and copy it in below, once, on the
         * very first output buffer this response ever allocates. A dcz
         * response's first get_buf() call is always this fresh-allocation
         * path (ctx->bufs == 0 here always means "never allocated before
         * for this request" — the free-list reuse branch above cannot fire
         * before the first allocation exists), so gating on first_buf is
         * equivalent to, and replaces, the old dcz_header_sent-guarded
         * call site in the body filter.
         */
        ngx_uint_t  want_prefix = first_buf && ctx->dcz_dict != NULL
                                   && !ctx->dcz_header_sent;

        /*
         * Size only the FIRST output buffer from the pledged size, when
         * known. Every allocation shares zlcf->bufs.size (the config
         * directive governs both count and size for the whole pool), so
         * shrinking it globally would change streaming geometry -- forcing
         * libzstd into more, smaller flush boundaries mid-stream, which the
         * :2255-area merge comment exists to avoid. Narrowing to just the
         * first buffer avoids over-allocating a full zlcf->bufs.size
         * (default 131072B on many builds) for a response known in advance
         * to be much smaller, e.g. a 389B body, while every subsequent
         * buffer keeps the full configured size for the unknown-length
         * (chunked/proxied) tail. pledged_size is -1 exactly on that
         * streaming case, so this never fires there.
         */
        if (first_buf && ctx->pledged_size >= 0) {
            size_t  pledged;

            /*
             * FULL-WIDTH first. ctx->pledged_size is an off_t, and
             * ZSTD_compressBound() takes a size_t: on an ILP32 build with
             * large-file support the two are not the same width, and a bare
             * cast here would truncate an upstream-declared length modulo
             * 2^32 -- a 4 GiB + 389 byte pledge becoming 389, and the clamp
             * below then shrinking the first output buffer to ~389 bytes
             * for a 4 GiB body. ngx_http_zstd_pledge_to_bound_input()
             * answers "is this length representable AND is the bound
             * computable" once, at off_t width, before any narrowing; when
             * it declines, buf_size keeps the configured zlcf->bufs.size
             * and nothing is shrunk, which is the safe direction.
             *
             * Note what is NOT done here: the fast path is not disabled.
             * Every pledged length representable in size_t and below
             * ZSTD_MAX_INPUT_SIZE -- i.e. every response an ILP32 host can
             * actually serve from memory, and all of them on LP64 short of
             * ~18 EB -- still takes the sizing below exactly as before.
             */
            if (ngx_http_zstd_pledge_to_bound_input(ctx->pledged_size,
                                                    &pledged))
            {
                /*
                 * ZSTD_compressBound(n) == n + (n>>8) + margin, margin >= 0
                 * always (see zstd.h's ZSTD_COMPRESSBOUND macro) -- so the
                 * bound this call would return can never be smaller than
                 * `pledged` itself, and the `+= 64` pad below only grows it
                 * further. When the pledged size is already at least the
                 * configured buffer size, `bound` (however it is computed)
                 * can therefore never satisfy `bound < buf_size`, so the
                 * clamp below never fires and buf_size is left exactly as
                 * it already is. Skip the call entirely on that path -- one
                 * fewer external libzstd call per known large response,
                 * same buf_size either way.
                 *
                 * This skip needs no platform gate any more. The old
                 * NGX_MAX_OFF_T_VALUE/SIZE_MAX #if existed only to prove
                 * that the value reaching ZSTD_compressBound() could not be
                 * at or above the width-dependent ZSTD_MAX_INPUT_SIZE (for
                 * which ZSTD_compressBound() returns 0, an error, not a
                 * bound) and could not have truncated on the way in. Both
                 * of those are now established by the helper, at full
                 * width, against the real ZSTD_MAX_INPUT_SIZE rather than a
                 * hardcoded 64-bit literal -- so the optimization is
                 * correct on ILP32 too instead of being compiled out there.
                 */
                if (pledged < buf_size) {
                    size_t  bound = ZSTD_compressBound(pledged);

                    /*
                     * ZSTD_compressBound() covers only the compressed
                     * payload; pad it for libzstd's own frame/block header
                     * overhead. Never grow past the configured size, and
                     * keep a small floor so tiny/empty bodies still get a
                     * buffer the frame overhead fits inside.
                     */
                    bound += NGX_HTTP_ZSTD_BOUND_FRAME_SLACK;

                    if (bound < NGX_HTTP_ZSTD_BOUND_MIN) {
                        bound = NGX_HTTP_ZSTD_BOUND_MIN;
                    }

                    if (bound < buf_size) {
                        buf_size = bound;
                    }
                }
            }
        }

        /*
         * Grow the allocation by the prefix length so reserving it never
         * steals space ZSTD_compressBound()/the floor above sized for the
         * compressed payload -- the compressor still gets the full
         * buf_size to fill; the prefix rides in bytes appended past it.
         * On the dcz first buffer, the allocation is deliberately
         * zlcf->bufs.size + NGX_HTTP_ZSTD_DCZ_HEADER_LEN (40 bytes), a
         * bounded exception to the configured per-buffer size. This small
         * overhead avoids a separate pool allocation for the RFC 9842
         * skippable-frame prefix and keeps the compressor's own share
         * intact for a single carefully-sized response.
         */
        if (want_prefix) {
            buf_size += NGX_HTTP_ZSTD_DCZ_HEADER_LEN;
        }

        ctx->out_buf = ngx_http_zstd_create_temp_buf(r->pool, buf_size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

#ifdef NGX_TEST_HARNESS
        ngx_http_zstd_probe_note_buf_alloc();
#endif

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_zstd_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

        if (want_prefix) {
            ctx->out_buf->last = ngx_cpymem(ctx->out_buf->last,
                                             ctx->dcz_dict->frame_header,
                                             NGX_HTTP_ZSTD_DCZ_HEADER_LEN);

            /*
             * Do NOT add NGX_HTTP_ZSTD_DCZ_HEADER_LEN to ctx->bytes_out
             * here. Advancing ->last above already grows ngx_buf_size()
             * of this same buffer by 40 bytes, and the emit path in
             * ngx_http_zstd_filter_compress() (`ctx->bytes_out +=
             * ngx_buf_size(b)`) counts this buffer's full size -- prefix
             * included -- exactly once when it is queued. A separate
             * increment here double-counted the 40-byte prefix on every
             * dcz response ($zstd_bytes_out and the $zstd_ratio derived
             * from it were both 40 bytes too high).
             */
            ctx->dcz_header_sent = 1;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd dcz: 40-byte frame header written into "
                           "first output buffer (dict \"%V\")",
                           &ctx->dcz_dict->file);
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: allocated buffer %p (%i in use)",
                       ctx->out_buf, ctx->bufs);

    } else {
        ctx->nomem = 1;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd get_buf: no free buffer, nomem set");
        return NGX_DECLINED;
    }

    if (ctx->out_buf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: out_buf is NULL after buffer allocation");
        return NGX_ERROR;
    }

    /*
     * dst/size are keyed off ->last, not ->pos: on a freshly allocated
     * buffer carrying the dcz prefix, ->last was already advanced past it
     * above, so the compressor writes immediately after the prefix bytes
     * instead of overwriting them. On every other buffer (recycled, or a
     * fresh non-dcz allocation) ->last == ->pos still, so this is exactly
     * the prior behaviour.
     */
    ctx->buffer_out.dst = ctx->out_buf->last;
    ctx->buffer_out.pos = 0;

    /* Validate buffer pointers to detect corruption before using in ZSTD */
    if (ctx->out_buf->end < ctx->out_buf->start) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: corrupted output buffer: end (%p) < start (%p)",
                      ctx->out_buf->end, ctx->out_buf->start);
        return NGX_ERROR;
    }

    if (ctx->out_buf->end < ctx->out_buf->last) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: corrupted output buffer: end (%p) < last (%p)",
                      ctx->out_buf->end, ctx->out_buf->last);
        return NGX_ERROR;
    }

    ctx->buffer_out.size = ctx->out_buf->end - ctx->out_buf->last;

    return NGX_OK;
}


/*
 * Set one ZSTD_CCtx parameter, logging a uniform NGX_LOG_ALERT and
 * returning NGX_ERROR on failure. Collapses the five structurally
 * identical setParameter+isError+log blocks in init_cctx into one
 * call site each, and gives every parameter the same error-message
 * format (they previously diverged slightly per call). `name` is the
 * human-readable parameter label for the log line.
 */
static ngx_int_t
ngx_http_zstd_set_param(ngx_http_request_t *r, ZSTD_CCtx *cctx,
    ZSTD_cParameter param, int value, const char *name)
{
    size_t  rc;

#ifdef NGX_TEST_HARNESS
    ngx_http_zstd_probe_note_setparam();
#endif

    rc = ZSTD_CCtx_setParameter(cctx, param, value);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_setParameter(%s=%d) failed: %s",
                      name, value, ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Give this request a CCtx: either the worker's cached one on loan, or a
 * fresh per-request context.
 *
 * Extracted from ngx_http_zstd_filter_init_cctx() so the loan bookkeeping --
 * which cleanup handler owns the context, and when `busy` may be set -- reads
 * as one unit instead of as five branches inside the parameter-setting code.
 *
 * On success ctx->cctx is non-NULL and a pool cleanup owns it: either
 * ngx_http_zstd_release_cctx (returns the loan) or ngx_http_zstd_cleanup_cctx
 * (frees an unshared context).
 */
static ngx_int_t
ngx_http_zstd_acquire_cctx(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx,
    ngx_http_zstd_loc_conf_t *zlcf)
{
    ngx_uint_t                      i, borrowed;
    ngx_pool_cleanup_t             *cln;
    ngx_http_zstd_cctx_slot_t      *slot, *free_slot, *lender;
    ngx_http_zstd_cctx_profile_t    zlcf_profile;
    ngx_int_t                       eff_window_log;

    /*
     * The cleanup slot is registered BEFORE the context is claimed, so a
     * borrowed context can never be stranded with busy set: an allocation
     * failure here happens while the cache is still untouched.
     */
    cln = ngx_http_zstd_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    /*
     * The window this request will really compress at -- see
     * ngx_http_zstd_cctx_profile_from_conf_wlog() for why the key must not
     * use zlcf->window_log directly. ctx->dcz_dict is already set by the
     * time acquisition runs: dcz negotiation completes in the header filter,
     * while a CCtx is only acquired on the first body buffer.
     */
    if (ctx->dcz_dict != NULL) {
        if (ctx->dcz_window_log_cache == 0) {
            ctx->dcz_window_log_cache = ngx_http_zstd_dcz_window_log(
                                 ctx->dcz_dict->bytes.len, ctx->pledged_size,
                                 zlcf->window_log, zlcf->dcz_window_cap);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd: dcz window log computed once: %i",
                           ctx->dcz_window_log_cache);
        }

        eff_window_log = ctx->dcz_window_log_cache;
    } else {
        eff_window_log = zlcf->window_log;
    }

    ngx_http_zstd_cctx_profile_from_conf_wlog(&zlcf_profile, zlcf,
                                              eff_window_log);

    borrowed = 0;
    free_slot = NULL;
    lender = NULL;

    /*
     * Borrow a slot whose context is free and was built for this location's
     * complete memory-affecting profile: compression level, long mode and
     * window log. A mismatch in any of the three never re-parameterises a
     * slot: the retained workspace is driven by all three and never shrinks,
     * so honouring a higher-memory location on an existing slot would raise
     * that slot's floor for every subsequent request of every other location
     * mapped to it.
     *
     * The same walk records the first slot that is empty AND not on loan, so
     * a miss can seed it below without a second pass. An empty slot is only
     * ever seeded, never evicted: a live cached context is not thrown away
     * mid-flight, and one already on loan is left alone.
     */
    for (i = 0; i < NGX_HTTP_ZSTD_CCTX_SLOTS; i++) {
        slot = &ngx_http_zstd_worker_cctx_slots[i];

        if (slot->busy) {
            continue;
        }

        if (slot->cctx == NULL) {
            if (free_slot == NULL) {
                free_slot = slot;
            }
            continue;
        }

        if (ngx_http_zstd_cctx_profiles_match(&slot->profile,
                                              &zlcf_profile))
        {
            ctx->cctx = slot->cctx;
            slot->busy = 1;
            lender = slot;
            borrowed = 1;

#if (NGX_DEBUG)
            if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
                ngx_int_t   dbg_level, dbg_wlog;
                ngx_flag_t  dbg_long;

                /*
                 * Unpack rather than read zlcf: this prints what the SLOT
                 * was built for, which is the thing a reuse decision turns
                 * on, and it exercises the key's reversibility on the hot
                 * debug path -- gated on NGX_DEBUG and the runtime log
                 * level so the unpack only runs when the line below will
                 * actually be emitted.
                 */
                ngx_http_zstd_profile_unpack(slot->profile.key, &dbg_level,
                                             &dbg_long, &dbg_wlog);

                ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "zstd: reusing worker cctx %p (slot:%ui) "
                               "level:%i long:%i window_log:%i",
                               ctx->cctx, i, dbg_level, (ngx_int_t) dbg_long,
                               dbg_wlog);
            }
#endif
            break;
        }
    }

    if (!borrowed) {
        ctx->cctx = ZSTD_createCCtx();
        if (ctx->cctx == NULL) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_createCCtx() failed");
            return NGX_ERROR;
        }

        /*
         * Defense-in-depth: INVALID is never cacheable. Every out-of-domain
         * input collapses to the same INVALID sentinel, so two profiles that
         * are in fact different would compare equal and a slot seeded under
         * one could later be borrowed for the other -- a context built with
         * the wrong parameters, which changes bytes on the wire.
         *
         * Guarding the seed is sufficient to close the borrow too: a slot is
         * only ever seeded here, so an INVALID key is never written into
         * slot->profile and can therefore never be matched by the walk above.
         * Unreachable today (every field is bounded at config load); if a
         * future directive widens a domain, the cost is one uncached context
         * per request, and a fresh context is always safe.
         */
        if (free_slot != NULL
            && zlcf_profile.key != NGX_HTTP_ZSTD_PROFILE_INVALID)
        {
            free_slot->cctx = ctx->cctx;
            ngx_http_zstd_cctx_profile_from_conf_wlog(&free_slot->profile,
                zlcf, eff_window_log);
            free_slot->busy = 1;
            lender = free_slot;
            borrowed = 1;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "zstd: created cctx %p (cached:%ui)",
                       ctx->cctx, borrowed);
    }

    /*
     * The two handlers take different data: release_cctx() returns a loan
     * and is given its lending slot, cleanup_cctx() owns an uncached
     * context outright and is given the context itself.
     */
    if (borrowed) {
        cln->handler = ngx_http_zstd_release_cctx;
        cln->data = lender;

    } else {
        cln->handler = ngx_http_zstd_cleanup_cctx;
        cln->data = ctx->cctx;
    }

    return NGX_OK;
}


/*
 * Configure this request's CCtx on first body data.
 *
 * The context comes from ngx_http_zstd_acquire_cctx() -- either the worker's
 * cached one on loan or a fresh per-request one -- and is attached to the
 * request cleanup chain either way, so overlapping requests in one worker
 * never share libzstd streaming state. Every parameter is (re-)applied here
 * after a full reset, which is what makes a carried-over context equivalent
 * to a freshly created one.
 */
static ngx_int_t
ngx_http_zstd_filter_init_cctx(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx, ngx_http_zstd_loc_conf_t *zlcf)
{
    size_t      rc;
    ZSTD_CCtx  *cctx;

    if (ctx->cctx == NULL
        && ngx_http_zstd_acquire_cctx(r, ctx, zlcf) != NGX_OK)
    {
        return NGX_ERROR;
    }

    cctx = ctx->cctx;

    /* Full reset: session state + all parameters. */
    rc = ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd: ZSTD_CCtx_reset() failed: %s",
                      ZSTD_getErrorName(rc));
        return NGX_ERROR;
    }

    /*
     * ZSTD_c_compressionLevel is one of the "compression parameters"
     * ZSTD_CCtx_refCDict() unconditionally overrides from the CDict's own
     * baked-in ZSTD_compressionParameters (see the enum block comment in
     * zstd.h: "When compressing with a ZSTD_CDict these parameters are
     * superseded by the parameters used to construct the ZSTD_CDict" --
     * ZSTD_c_compressionLevel is the first parameter in that block). Skip
     * setting it only when refCDict is actually going to run below --
     * i.e. zlcf->dict is set AND this request did NOT negotiate dcz,
     * exactly the "else if (zlcf->dict)" condition the refCDict call site
     * itself uses. zstd_dict_file is an http{}-context directive, so a
     * dcz-negotiated request can have BOTH ctx->dcz_dict and zlcf->dict
     * non-NULL at once; the dcz branch below always wins that mutual
     * exclusion (ZSTD_CCtx_refPrefix() only, never refCDict), so gating on
     * zlcf->dict alone would wrongly skip the level on such a request even
     * though refCDict is never called for it. The dcz path uses
     * ZSTD_CCtx_refPrefix(), which does NOT override sticky parameters, so
     * level must still be set there.
     */
    if (zlcf->dict == NULL || ctx->dcz_dict != NULL) {
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_compressionLevel,
                                    (int) zlcf->level, "level")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /*
     * Issue #38: Apply target compressed block size if configured.
     *
     * Gate on the library version, NOT #ifdef ZSTD_c_targetCBlockSize:
     * ZSTD_c_targetCBlockSize is an enum member, not a preprocessor macro,
     * so #ifdef is always false and silently compiled this whole block out
     * even on libzstd >= 1.5.6 where the parameter is fully supported. The
     * directive was therefore a permanent no-op. See C1.
     */
#if ZSTD_VERSION_NUMBER >= 10506
    if (zlcf->target_cblock_size > 0) {
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_targetCBlockSize,
                                    (int) zlcf->target_cblock_size,
                                    "targetCBlockSize")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
#endif

    /*
     * Long-distance matching. zstd keeps a secondary long-range hash
     * table that finds repeats far beyond the regular match window —
     * a meaningful ratio win on large, internally repetitive bodies
     * (concatenated JSON, HTML with repeated boilerplate, logs) at a
     * modest, bounded extra memory cost. Off by default; the win only
     * materialises on inputs large enough to exceed the window, and
     * small responses should not pay the table allocation. Set before
     * zstd_window_log below so an explicit window cap still takes
     * precedence over the LDM-derived default.
     */
    if (zlcf->long_mode) {
        if (ngx_http_zstd_set_param(r, cctx,
                                    ZSTD_c_enableLongDistanceMatching, 1,
                                    "enableLongDistanceMatching")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    /*
     * Cap the compression window. zstd's per-context working memory is
     * dominated by the window size (~2^windowLog bytes plus match-table
     * overhead). Without a cap, a high level on large bodies lets each
     * concurrent request inflate worker RSS unpredictably. Bounding
     * windowLog gives operators a hard, predictable per-request memory
     * ceiling at a small ratio cost on inputs larger than the window.
     * Unset (0) keeps zstd's level-derived default.
     *
     * NOT superseded-by-cdict, unlike level above: ZSTD_resetCCtx_
     * byAttachingCDict() and ZSTD_resetCCtx_byCopyingCDict() (zstd_compress.c,
     * every version from the module's 1.4.0 floor through 1.5.7) both take
     * windowLog = params.cParams.windowLog -- the CCtx's OWN value, restored
     * immediately after copying the CDict's other cParams -- not from the
     * CDict. Both also assert(windowLog != 0), i.e. they require the CCtx
     * side to have set it. Leaving it unset here means
     * ZSTD_CCtx_init_compressStream2() derives cParams (windowLog included)
     * from cdict->compressionLevel's defaults instead (0 for a CDict built
     * via ZSTD_createCDict_advanced()), silently dropping zstd_window_log's
     * cap for every CDict-backed response -- exactly the C2/R1 regression
     * the CDict construction comment below already fought off once. So this
     * generic block must still fire for the zlcf->dict (CDict) mode; only
     * the dcz branch (ctx->dcz_dict) replaces it with a more specific value,
     * computed a few lines below via ngx_http_zstd_dcz_window_log() --
     * setting the plain zlcf->window_log here first would just be
     * overwritten one call later by that dcz-aware value, so dcz mode alone
     * is skipped here.
     */
    if (zlcf->window_log > 0 && ctx->dcz_dict == NULL) {
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_windowLog,
                                    (int) zlcf->window_log, "windowLog")
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ctx->dcz_dict != NULL) {
        ngx_int_t  wlog;

        /*
         * RFC 9842 window bound, plus both operator memory ceilings. Read
         * ngx_http_zstd_dcz_window_log()'s comment for the sizing rationale
         * and for why both clamps are opt-in.
         *
         * This must be the SAME value ngx_http_zstd_acquire_cctx() packed
         * into the CCtx ring key above -- a request that borrows a slot
         * keyed on one window and then compresses at another contaminates
         * that slot's retained workspace for every later borrower. Rather
         * than calling the helper again and relying on both call sites
         * staying in lockstep, read the single memoised result computed at
         * most once per request in ctx->dcz_window_log_cache: acquire_cctx()
         * fills it when it runs (ctx->cctx == NULL above), and when it is
         * skipped (a borrowed cctx already set on this ctx) the cache was
         * necessarily already filled the first time this request acquired
         * one, since ctx->dcz_dict does not change mid-request.
         */
        if (ctx->dcz_window_log_cache == 0) {
            ctx->dcz_window_log_cache = ngx_http_zstd_dcz_window_log(
                                        ctx->dcz_dict->bytes.len,
                                        ctx->pledged_size,
                                        zlcf->window_log,
                                        zlcf->dcz_window_cap);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd: dcz window log computed once: %i",
                           ctx->dcz_window_log_cache);
        }

        wlog = ctx->dcz_window_log_cache;

        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_windowLog, (int) wlog,
                                    "windowLog(dcz)")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * Reference the raw dictionary bytes as a prefix — RFC 9842
         * type=raw semantics exactly (ZSTD_CCtx_refPrefix interprets the
         * buffer as raw content, not a trained-dictionary structure).
         * Per-request table build over the prefix is the deliberate MVP
         * trade against caching a CDict per (dict, level, window) tuple;
         * the buffer itself is config-pool memory that outlives the
         * request. Mutually exclusive with the trained zstd_dict_file
         * CDict below: a dcz response's frame must reference ONLY the
         * negotiated dictionary or the client cannot decode it.
         */
#ifdef NGX_TEST_HARNESS
        if (ngx_http_zstd_probe_refprefix_fault()
            == NGX_HTTP_ZSTD_PROBE_REFPREFIX_ERROR)
        {
            /* See the codec fault site for why (size_t) -1 is the stable,
             * public-API-only synthetic error value. Substituting before the
             * call leaves the CCtx untouched, exactly like a real failure. */
            rc = (size_t) -1;
        } else {
            rc = ZSTD_CCtx_refPrefix(cctx, ctx->dcz_dict->bytes.data,
                                     ctx->dcz_dict->bytes.len);
        }
#else
        rc = ZSTD_CCtx_refPrefix(cctx, ctx->dcz_dict->bytes.data,
                                 ctx->dcz_dict->bytes.len);
#endif
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_CCtx_refPrefix() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }

        /*
         * Content checksum on dcz frames — defence in depth against a
         * mismatched dictionary. Decoding against a wrong same-size
         * dictionary structurally SUCCEEDS: raw-prefix back-references
         * stay in range and nothing else ties the output to the
         * content, so the client gets wrong bytes with a success code
         * (demonstrated in review of the supplied-hash argument, where
         * a stale declared hash is the realistic way to get there).
         * The checksum (XXH64-low32 of the uncompressed content,
         * verified by libzstd-based clients — i.e. browsers — by
         * default) turns that into a visible decode error. Four bytes
         * per response plus an XXH64 pass; negligible next to the
         * compression itself. Plain responses are unchanged: a
         * zstd_dict_file CDict already embeds a dictionary ID that the
         * decoder checks (a wrong trained dictionary fails as
         * "Dictionary mismatch"), and a dictionary-less response has
         * nothing to mismatch. Only the RFC 9842 raw prefix carries no
         * such binding, which is why it needs the checksum.
         */
        if (ngx_http_zstd_set_param(r, cctx, ZSTD_c_checksumFlag, 1,
                                    "checksumFlag(dcz)")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else if (zlcf->dict) {
        rc = ZSTD_CCtx_refCDict(cctx, zlcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "zstd: ZSTD_CCtx_refCDict() failed: %s",
                          ZSTD_getErrorName(rc));
            return NGX_ERROR;
        }
    }

    /*
     * When the response body length is known exactly (a declared
     * Content-Length, i.e. the common proxied / static case), tell zstd
     * up front. With the pledged size the encoder can size its internals
     * to the input and write a more compact frame header (an exact
     * content-size field instead of the streaming-unknown encoding),
     * improving both speed and ratio slightly at no cost.
     *
     * This stays strictly per-request: it is set on this request's own
     * CCtx after the reset above and before the first compress call,
     * exactly as ZSTD_CCtx_setPledgedSrcSize() requires. It does NOT
     * reintroduce a shared/worker-lifetime context — the per-request
     * context model from 774b4a5 is a deliberate correctness guarantee
     * and is preserved.
     *
     * ctx->pledged_size is the body length captured in the header filter
     * before ngx_http_clear_content_length() wiped it (the header filter
     * runs the eligibility gate and clear; the live content_length_n is -1
     * by now). For a non-chunked response that is exactly what is fed to the
     * compressor. The pledge is only an optimisation hint, so a failure to
     * set it is logged and ignored rather than failing the request; a genuine
     * size mismatch would still be caught by ZSTD_compressStream2() and
     * handled on the existing failed: path.
     */
    if (ctx->pledged_size >= 0) {
        rc = ZSTD_CCtx_setPledgedSrcSize(
                 cctx, (unsigned long long) ctx->pledged_size);
        if (ZSTD_isError(rc)) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "zstd: ZSTD_CCtx_setPledgedSrcSize(%O) ignored: %s",
                           ctx->pledged_size, ZSTD_getErrorName(rc));
        }
    }

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd cctx ready: level:%i long:%i window_log:%i "
                   "dict:%p dcz:%p",
                   zlcf->level, zlcf->long_mode, zlcf->window_log,
                   zlcf->dict, ctx->dcz_dict);

    return NGX_OK;
}


static void *
ngx_http_zstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    zmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_main_conf_t));
    if (zmcf == NULL) {
        return NULL;
    }

    /* NGX_CONF_UNSET so ngx_conf_set_flag_slot does not mistake the
     * pcalloc'd 0 for an already-set value ("is duplicate"). */
    zmcf->dict_unsafe = NGX_CONF_UNSET;
    zmcf->dict_strict_path = NGX_CONF_UNSET;
    zmcf->dcz_dict_trust_hashes = NGX_CONF_UNSET;

    return zmcf;
}


static char *
ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_zstd_main_conf_t *zmcf = conf;

    /*
     * Cache ZSTD_CStreamOutSize() once per cycle. The constant-returning
     * libzstd function is called once here and reused in every location
     * merge instead of calling it once per enabled location.
     */
    zmcf->stream_out_size = ZSTD_CStreamOutSize();

    /*
     * Preformat $zstd_dcz_dicts_hashed once per cycle. The value is
     * configuration-constant by this point: dcz dictionaries are hashed
     * by the zstd_dcz_dict directive handler, which runs during config
     * parsing, i.e. strictly before init_main_conf(). Storing the final
     * decimal ngx_str_t in the cycle-owned main conf lets the variable
     * handler return an immutable buffer instead of allocating
     * NGX_INT_T_LEN bytes and calling ngx_sprintf on every request.
     *
     * This MUST stay above the zstd_dict_file early return below: dcz
     * dictionaries are configured with zstd_dcz_dict and do not require
     * zstd_dict_file, so returning first would leave the string empty
     * for exactly the configurations that use the variable.
     */
    zmcf->dcz_dicts_hashed_str.data = ngx_pnalloc(cf->pool, NGX_INT_T_LEN);
    if (zmcf->dcz_dicts_hashed_str.data == NULL) {
        return NGX_CONF_ERROR;
    }

    zmcf->dcz_dicts_hashed_str.len =
        ngx_sprintf(zmcf->dcz_dicts_hashed_str.data, "%ui",
                    zmcf->dcz_dicts_hashed)
        - zmcf->dcz_dicts_hashed_str.data;

    /*
     * Normalize here for anything that reads the flag AFTER this point
     * (nothing currently does). ngx_http_zstd_dcz_dict_file() runs
     * during ngx_conf_parse(), strictly BEFORE init_main_conf, so its
     * own read of dict_strict_path treats NGX_CONF_UNSET (-1) as "not
     * requested" directly rather than relying on this normalization —
     * see ngx_http_zstd_open_dict_file()'s caller.
     */
    if (zmcf->dict_strict_path == NGX_CONF_UNSET) {
        zmcf->dict_strict_path = 0;
    }

    /*
     * Reject the ordering rather than silently accept an unchecked
     * load: zstd_dcz_dict_file records (above) the first time it loads
     * a dictionary while dict_strict_path did not yet read as the
     * explicit "on". If the flag's FINAL value is "on", every such
     * recorded load ran without the O_NOFOLLOW / writable-target checks
     * this directive exists to apply -- fail the config rather than
     * start with a dictionary the operator asked to have vetted but
     * that never was. nginx directives are conventionally
     * order-independent, so this is a real operator trap, not pedantry:
     * confirmed live, a world-writable dcz dictionary loaded before a
     * later "zstd_dict_strict_path on;" line passed with no warning.
     */
    if (zmcf->dict_strict_path == 1
        && zmcf->dcz_dict_loaded_before_strict_on)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_dict_strict_path on\" was declared "
                           "AFTER \"zstd_dcz_dict_file %V\", which had "
                           "already loaded unchecked by that point. "
                           "nginx directives are order-independent by "
                           "convention, but this one is not: move "
                           "\"zstd_dict_strict_path on;\" before every "
                           "\"zstd_dcz_dict_file\" directive it must "
                           "apply to",
                           &zmcf->dcz_dict_loaded_before_strict_on_file);
        return NGX_CONF_ERROR;
    }

    if (zmcf->dcz_dict_trust_hashes == NGX_CONF_UNSET) {
        zmcf->dcz_dict_trust_hashes = 0;
    }

    /*
     * Same ordering rejection as strict_path above, for the same
     * reason with the opposite polarity: a literal that loaded before
     * a later "zstd_dcz_dict_trust_hashes on;" was VERIFIED -- correct
     * bytes, but the full hashing pass the directive exists to skip
     * was silently paid. Rejecting keeps the directive's effect
     * position-independent instead of quietly partial.
     */
    if (zmcf->dcz_dict_trust_hashes == 1
        && zmcf->dcz_dict_verified_before_trust_on)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_dcz_dict_trust_hashes on\" was "
                           "declared AFTER \"zstd_dcz_dict_file %V\", "
                           "whose hash literal had already been verified "
                           "(hashed) by that point. nginx directives are "
                           "order-independent by convention, but this "
                           "one is not: move \"zstd_dcz_dict_trust_"
                           "hashes on;\" before every "
                           "\"zstd_dcz_dict_file\" directive it must "
                           "apply to",
                           &zmcf->dcz_dict_verified_before_trust_on_file);
        return NGX_CONF_ERROR;
    }

    if (zmcf->dict_file.len == 0) {
        return NGX_CONF_OK;
    }

    /*
     * RFC1: zstd_dict_file emits Content-Encoding: zstd while compressing with
     * an external dictionary. That is not HTTP dictionary negotiation: RFC 9842
     * (Sept 2025) defines the "dcz" content coding and Available-Dictionary for
     * that. A generic client that only advertises "zstd" cannot decode this
     * response, and a shared cache keys it as an ordinary zstd variant. Until
     * dcz is implemented, refuse to start unless the operator explicitly
     * acknowledges the non-standard, control-both-ends-only mode.
     */
    if (zmcf->dict_unsafe != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_dict_file\" produces a non-standard "
                           "\"Content-Encoding: zstd\" response that only "
                           "clients sharing the dictionary can decode and that "
                           "is not negotiated per RFC 9842 (dcz). Set "
                           "\"zstd_dict_file_unsafe on;\" to acknowledge you "
                           "control both ends (and key any shared cache "
                           "accordingly), or remove \"zstd_dict_file\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &zmcf->dict_file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_zstd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *    conf->bufs.num = 0;
     *    conf->types = { NULL };
     *    conf->types_keys = NULL;
     *    conf->dict = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->level = NGX_HTTP_ZSTD_LEVEL_UNSET;
    conf->min_length = NGX_CONF_UNSET;
    conf->max_length = NGX_CONF_UNSET;
    conf->target_cblock_size = NGX_CONF_UNSET;
    conf->window_log = NGX_CONF_UNSET;
    conf->long_mode = NGX_CONF_UNSET;
    conf->max_cctx_memory = NGX_CONF_UNSET;
    /*
     * Not NGX_CONF_UNSET: this is derived, never inherited and never
     * written by a directive. It is (re)computed for every location that
     * carries a budget, after the budget itself has merged. 0 = no cap.
     */
    conf->dcz_window_cap = 0;
    conf->bufs_unsafe = NGX_CONF_UNSET;
    conf->bypass = NGX_CONF_UNSET_PTR;
    conf->dcz_dicts = NGX_CONF_UNSET_PTR;
    conf->dcz_assume_secure = NGX_CONF_UNSET;

    return conf;
}


#if !(NGX_WIN32)
#include <fcntl.h>   /* openat(), O_DIRECTORY, O_NOFOLLOW, AT_FDCWD */
/*
 * AT_FDCWD is the portable signal that the POSIX.1-2008 *at() family is
 * available. Where it is absent strict mode has no way to resolve a path
 * component-by-component, and it fails CLOSED at config load rather than
 * silently degrading to the leaf-only O_NOFOLLOW guarantee it used to
 * give (see ngx_http_zstd_open_dict_file()).
 */
#ifdef AT_FDCWD
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  1
#else
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  0
#endif
#else
#define NGX_HTTP_ZSTD_HAVE_STRICT_WALK  0
#endif


#if (NGX_HTTP_ZSTD_HAVE_STRICT_WALK)

/*
 * Strict-mode component-by-component open (M3).
 *
 * O_NOFOLLOW on the full path guards ONLY the leaf: the kernel resolves
 * every intermediate component normally, so /srv/current/dict.bin with
 * "current" a symlink is followed silently and strict mode selects
 * whatever bytes the symlink's owner points it at -- exactly the
 * release-symlink swap the directive's README warning says strict mode
 * defends against. Walking the path with openat(O_NOFOLLOW|O_DIRECTORY)
 * one component at a time makes an intermediate symlink fail the walk
 * (ELOOP) instead of being traversed, and the leaf is then opened
 * relative to the verified parent fd -- so the whole resolution, not
 * just its last step, is symlink-free and TOCTOU-safe against a
 * component swap racing the walk.
 *
 * Absolute paths only. nginx has already run the config path through
 * ngx_conf_full_name(), so a dictionary path reaching here is absolute;
 * a relative one would have to be resolved against a cwd this function
 * cannot pin, and strict mode fails CLOSED rather than fall back to a
 * whole-path open.
 *
 * Returns the leaf fd, or NGX_INVALID_FILE having logged the reason.
 */
/*
 * fstat() one directory fd opened during the strict walk and refuse it
 * under the same rule the leaf ownership/mode checks apply (M4, see
 * ngx_http_zstd_open_dict_file()): owned by neither root nor the
 * loading principal, or writable by group or other.
 *
 * The walk's whole point is to make resolution of the ENTIRE path
 * symlink-free and TOCTOU-safe, not just the leaf -- so a directory
 * component left unvetted is the same class of gap M3 closed for
 * symlinks. A local user who owns, or can write into, an ancestor
 * directory can rename() a root-owned 0644 file into the leaf position
 * and pass both leaf checks while still having fully steered which
 * bytes strict mode loads. Deliberately NO sticky-bit exemption: a
 * sticky world-writable ancestor (a /tmp-style directory) still lets an
 * unprivileged user create the next path component, which is exactly
 * the steering this function exists to refuse.
 *
 * `label` names the component for the diagnostic ("/" for the root fd,
 * the component bytes otherwise); `path` is the accumulated path
 * so far, for the same purpose the leaf checks use `path` for.
 */
static ngx_int_t
ngx_http_zstd_check_strict_dir(ngx_conf_t *cf, int fd, const char *label,
    ngx_str_t *path)
{
    struct stat  st;

    if (fstat(fd, &st) < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "fstat(\"%s\") failed while resolving \"%V\" "
                           "under \"zstd_dict_strict_path on\"",
                           label, path);
        return NGX_ERROR;
    }

    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "directory component \"%s\" of \"%V\" is owned "
                           "by uid %uD, neither root nor the loading "
                           "principal (uid %uD); refused by "
                           "\"zstd_dict_strict_path on\", because that "
                           "owner can rename a different file into this "
                           "directory and steer what a later privileged "
                           "reload loads. Deploy dictionaries under a "
                           "directory tree owned and writable only by the "
                           "deploying principal (the default, "
                           "\"zstd_dict_strict_path off;\", leaf-checks "
                           "the file instead)",
                           label, path, (uint32_t) st.st_uid,
                           (uint32_t) geteuid());
        return NGX_ERROR;
    }

    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "directory component \"%s\" of \"%V\" is "
                           "writable by group or other (no sticky-bit "
                           "exemption -- a sticky world-writable directory "
                           "still lets an unprivileged user create the "
                           "next component); refused by "
                           "\"zstd_dict_strict_path on\". Deploy "
                           "dictionaries under a directory tree owned and "
                           "writable only by the deploying principal",
                           label, path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_fd_t
ngx_http_zstd_open_dict_strict(ngx_conf_t *cf, ngx_str_t *path, int flags)
{
    u_char  *p, *start, *end;
    int      fd, next, oflags;

    if (path->len == 0 || path->data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" is not an absolute path; refused by "
                           "\"zstd_dict_strict_path on\", which resolves "
                           "the path one component at a time and cannot "
                           "verify a relative prefix", path);
        return NGX_INVALID_FILE;
    }

    fd = open("/", O_RDONLY | O_DIRECTORY
#ifdef O_CLOEXEC
              | O_CLOEXEC
#endif
              );
    if (fd < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "open(\"/\") failed while resolving \"%V\" "
                           "under \"zstd_dict_strict_path on\"", path);
        return NGX_INVALID_FILE;
    }

    /*
     * The root fd is a walked component like any other -- vet it with
     * the same rule before it is trusted as the base of every openat()
     * below. On most systems "/" is root-owned 0755 and this is a
     * no-op; a container or chroot base that fails this is exactly the
     * layout strict mode is meant to refuse.
     */
    if (ngx_http_zstd_check_strict_dir(cf, fd, "/", path) != NGX_OK) {
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

    start = path->data + 1;
    end = path->data + path->len;

    for ( ;; ) {
        /* skip any run of separators; a trailing one means no leaf */
        while (start < end && *start == '/') {
            start++;
        }

        if (start >= end) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" names a directory, not a "
                               "dictionary file; refused by "
                               "\"zstd_dict_strict_path on\"", path);
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }

        for (p = start; p < end && *p != '/'; p++) { /* void */ }

        /*
         * openat() needs a NUL-terminated component. The component is
         * COPIED into a local buffer rather than NUL-terminated in place:
         * path->data is nginx's own config string, and writing into it --
         * even a byte restored immediately afterwards -- would mutate
         * shared config memory that other directives and the error log
         * still read. A component longer than the buffer cannot name a
         * file any filesystem will accept, so it is refused rather than
         * silently truncated (truncation would open a DIFFERENT name).
         */
        {
            u_char  comp[NGX_MAX_PATH];
            size_t  complen = (size_t) (p - start);
            int     last;
            u_char  *q;

            if (complen >= sizeof(comp)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"%V\" has a path component longer "
                                   "than %uz bytes; refused by "
                                   "\"zstd_dict_strict_path on\"",
                                   path, sizeof(comp) - 1);
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            ngx_memcpy(comp, start, complen);
            comp[complen] = '\0';

            last = 1;
            for (q = p; q < end; q++) {
                if (*q != '/') {
                    last = 0;
                    break;
                }
            }

            /*
             * "." and ".." are refused rather than resolved: ".." would
             * climb back above a component already verified, which
             * makes the walk's guarantee unstatable, and neither has a
             * legitimate place in a deployed dictionary path.
             */
            if (ngx_strcmp(comp, ".") == 0 || ngx_strcmp(comp, "..") == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "\"%V\" contains a \".\" or \"..\" "
                                   "component; refused by "
                                   "\"zstd_dict_strict_path on\"", path);
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            /*
             * O_CLOEXEC is applied to BOTH arms deliberately. Folding it
             * into the ternary via a bare "#ifdef ... | O_CLOEXEC" would
             * bind it to the else-branch alone by C's precedence rules,
             * silently leaving the leaf fd inheritable across an exec.
             */
            oflags = last ? (flags | O_NOFOLLOW)
                          : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
#ifdef O_CLOEXEC
            oflags |= O_CLOEXEC;
#endif

            next = openat(fd, (char *) comp, oflags);

            if (next < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   "openat(\"%s\") failed while resolving "
                                   "\"%V\" under "
                                   "\"zstd_dict_strict_path on\" (a "
                                   "symlink at any component is refused, "
                                   "not followed; a release-symlink "
                                   "deployment needs "
                                   "\"zstd_dict_strict_path off;\", the "
                                   "default)", comp, path);
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            ngx_close_file(fd);
            fd = next;

            if (last) {
                return fd;
            }

            /*
             * `next`/`fd` is a directory fd that will be trusted as the
             * base for the next openat() -- vet it before it is used
             * for anything else, same rule as the root fd above.
             */
            if (ngx_http_zstd_check_strict_dir(cf, fd, (char *) comp, path)
                != NGX_OK)
            {
                ngx_close_file(fd);
                return NGX_INVALID_FILE;
            }

            start = p;
        }
    }
}

#endif /* NGX_HTTP_ZSTD_HAVE_STRICT_WALK */


/*
 * Shared open+validate path for both dictionary loaders (zstd_dict_file
 * in ngx_http_zstd_merge_loc_conf() and zstd_dcz_dict_file() below).
 *
 * Rationale, both rows:
 *
 * 1. Non-regular inputs (G5 row "Reject non-regular dictionary inputs"):
 *    neither loader used to test ngx_is_file() before reading. Pointing
 *    zstd_dict_file at a FIFO opens read-only and then blocks the
 *    config-parsing master in read(2) until a writer appears on the
 *    other end -- "nginx -t" or a reload simply hangs. A directory or
 *    device node instead reaches a confusing read/size error much
 *    later. Opening with O_NONBLOCK where the platform has it (POSIX;
 *    Win32's NGX_FILE_NONBLOCK is defined to 0, a no-op, since
 *    CreateFile() has no non-blocking-open equivalent for a regular
 *    path) means an open against a FIFO with no reader returns
 *    immediately (ENXIO) instead of blocking, so the ordinary error
 *    path below handles it as any other unopenable file -- no explicit
 *    FIFO test needed. fstat() + ngx_is_file() then rejects anything
 *    that did open (a directory opens fine on most platforms) before a
 *    single byte is read.
 *
 * 2. Trust policy (G5 row "strict dictionary-path trust policy"): a
 *    symlink or a group/world-writable target lets a less-privileged
 *    local writer choose or mutate the bytes a root master snapshots
 *    into every worker on the next reload. zstd_dict_strict_path on
 *    (off by default -- a release-symlink deploy is a legitimate,
 *    common layout and must keep working unconfigured) opens with
 *    O_NOFOLLOW on POSIX (Win32 has no directive-level follow to
 *    suppress here; ngx_is_link() on that platform is hardwired to 0,
 *    see os/win32/ngx_files.h) so a symlink target is refused as a
 *    symlink rather than transparently followed, and additionally
 *    rejects a target writable by group or other. The open happens
 *    once; every subsequent check and the eventual read run against
 *    the returned fd, never by reopening the path, so a rename or
 *    swap after this call cannot change which inode is loaded
 *    (TOCTOU-safe by construction).
 *
 * On success returns an open fd with *info already populated by
 * ngx_fd_info(); the caller reads from it and is responsible for
 * closing it. On failure returns NGX_INVALID_FILE having already
 * logged the reason and closed any fd it opened.
 */
static ngx_fd_t
ngx_http_zstd_open_dict_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_flag_t strict, ngx_file_info_t *info)
{
    ngx_fd_t  fd;

#if (NGX_WIN32)

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

#else

    if (strict) {

#if (NGX_HTTP_ZSTD_HAVE_STRICT_WALK)

        /*
         * M3: resolve every component, not just the leaf. See
         * ngx_http_zstd_open_dict_strict().
         */
        fd = ngx_http_zstd_open_dict_strict(cf, path,
                                            O_RDONLY | NGX_FILE_NONBLOCK);

        if (fd == NGX_INVALID_FILE) {
            /* the walk has already logged the precise component */
            return NGX_INVALID_FILE;
        }

#else

        /*
         * Fail CLOSED. Without openat() strict mode can only offer the
         * leaf-only O_NOFOLLOW guarantee, which an intermediate symlink
         * defeats -- accepting the config here would let the directive
         * claim a protection the platform cannot deliver.
         */
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_dict_strict_path on\" is not supported "
                           "on this platform (no openat(); the path cannot "
                           "be resolved one component at a time, so an "
                           "intermediate symlink could not be refused). "
                           "Refusing \"%V\" rather than loading it with a "
                           "weaker guarantee than the directive states",
                           path);
        return NGX_INVALID_FILE;

#endif

    } else {
        fd = ngx_open_file(path->data,
                           NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
                           NGX_FILE_OPEN, 0);
    }

#endif

    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", path);
        return NGX_INVALID_FILE;
    }

    if (ngx_fd_info(fd, info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", path);
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

    if (!ngx_is_file(info)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" is not a regular file", path);
        ngx_close_file(fd);
        return NGX_INVALID_FILE;
    }

#if !(NGX_WIN32)

    if (strict) {

        /*
         * The component walk above refused a symlink at EVERY component,
         * leaf included; this is the fstat()-side confirmation
         * (ngx_is_link() on the fd's own info is always false for a fd
         * that reached here, because O_NOFOLLOW on the leaf openat()
         * would have refused the open first -- kept as an explicit,
         * self-documenting assertion of the property this function
         * guarantees under strict mode rather than a live code path).
         */
        if (ngx_is_link(info)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" is a symlink; refused by "
                               "\"zstd_dict_strict_path on\" (a release-"
                               "symlink deployment needs "
                               "\"zstd_dict_strict_path off;\", the "
                               "default)", path);
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }

        /*
         * M4: ownership, not just the group/other bits.
         *
         * A dictionary owned by an unprivileged account with a perfectly
         * ordinary mode 0644 passes a group/other-writability test while
         * a root master reads it -- and that owner can rewrite the file
         * at will, so the next privileged reload snapshots whatever bytes
         * they chose. The directive's stated goal is to exclude a
         * less-privileged local writer, which the mode bits alone do not
         * achieve. Strict mode therefore requires the file to be owned by
         * the principal doing the loading (the effective uid of the
         * config-parsing master), and root-owned files are additionally
         * accepted because root is not "less privileged" than the loader
         * in any configuration that reaches here.
         */
        if ((info)->st_uid != geteuid() && (info)->st_uid != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" is owned by uid %uD, neither the "
                               "loading principal (uid %uD) nor root; "
                               "refused by \"zstd_dict_strict_path on\", "
                               "because that owner can rewrite the file "
                               "and steer what a later privileged reload "
                               "loads. Deploy dictionaries via an "
                               "immutable, content-addressed path owned "
                               "and writable only by the deploying "
                               "principal",
                               path, (uint32_t) (info)->st_uid,
                               (uint32_t) geteuid());
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }

        if (ngx_file_access(info) & (S_IWGRP | S_IWOTH)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"%V\" is writable by group or other; "
                               "refused by \"zstd_dict_strict_path on\". "
                               "Deploy dictionaries via an immutable, "
                               "content-addressed path owned and "
                               "writable only by the deploying "
                               "principal", path);
            ngx_close_file(fd);
            return NGX_INVALID_FILE;
        }
    }

    /*
     * Clear O_NONBLOCK now that the target is confirmed regular.
     *
     * The flag exists only so the open() above cannot block the
     * config-parsing master on a FIFO with no writer (see the FIFO
     * discussion in this function's header); that job is done the
     * moment fstat() + ngx_is_file() have accepted the target. Leaving
     * it set on a regular fd invites the non-blocking-regular-file
     * behaviour some filesystems have and ext4/xfs do not: on a 9p or
     * drvfs mount a read() of a regular file can return a SHORT count.
     * The read loop handles a short count correctly either way, so this
     * is defence in depth rather than a correctness requirement --
     * blocking reads simply return the whole file in fewer syscalls.
     *
     * fcntl() failure is ignored deliberately: the fd is valid and the
     * flags are defined, there is no meaningful failure mode here, and
     * refusing to load a perfectly good dictionary over a hardening
     * detail would be the worse outcome.
     */
    {
        int  fl = fcntl(fd, F_GETFL);

        if (fl != -1) {
            (void) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        }
    }

#endif

    return fd;
}


/*
 * Read exactly `size` bytes of a dictionary file into `buf`, or fail.
 *
 * Both dictionary loaders (zstd_dict_file and the dcz loader) previously
 * issued ONE ngx_read_fd() and treated any short count as fatal. That is
 * wrong twice over:
 *
 *   - read() on a regular file is permitted to return fewer bytes than
 *     requested. It usually does not on a local ext4/xfs file, which is
 *     why the single-read form survived, but it is not a guarantee the
 *     kernel makes. A 9p/drvfs mount (a WSL /mnt/c dictionary, a Plan 9
 *     export) returns a short count on a regular file as normal
 *     behaviour, and a large enough dictionary then fails config load.
 *   - EINTR. A signal delivered mid-read returns early with no bytes
 *     lost and nothing wrong; the caller is expected to reissue. The
 *     master is parsing configuration here, so it is squarely in a
 *     window where signals arrive. This one is independent of the file
 *     system AND of O_NONBLOCK -- clearing that flag (which the opener
 *     does, and should) does not remove it.
 *
 * Loop until the buffer is full, treating a short count as "continue"
 * rather than "fail", and reissue on EINTR. Two failures remain fatal
 * and are reported distinctly, because they mean different things to an
 * operator: a read error (the file became unreadable) and early EOF (the
 * file shrank between fstat() and here, so the dictionary on disk is not
 * the dictionary whose size we validated and allocated for). Neither may
 * be silently tolerated -- a partially-populated buffer handed to
 * ZSTD_createCDict() is a dictionary made partly of uninitialised heap.
 *
 * Callers have already validated `size` (non-zero, <= MAX_DICT_SIZE) and
 * allocated `buf` for exactly that many bytes.
 */
static ngx_int_t
ngx_http_zstd_read_dict_file(ngx_conf_t *cf, ngx_fd_t fd, ngx_str_t *path,
    u_char *buf, size_t size)
{
    ssize_t  n;
    size_t   done;

    for (done = 0; done < size; /* void */) {

        n = ngx_read_fd(fd, (void *) (buf + done), size - done);

        if (n < 0) {

#if !(NGX_WIN32)
            /*
             * Interrupted before transferring anything: not an error,
             * reissue. ngx_errno is read immediately so nothing between
             * here and the test can clobber it.
             *
             * POSIX only, and NGX_WIN32 rather than a "does NGX_EINTR
             * exist" test because that is the actual reason: win32's
             * ngx_errno.h defines no NGX_EINTR at all, because ReadFile()
             * on a synchronous handle is not interruptible -- there is no
             * such error to retry. Guarding on the platform says so;
             * guarding on the macro would read as a portability
             * workaround for a value that is merely spelled differently.
             */
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
#endif

            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_fd_n " \"%V\" failed", path);
            return NGX_ERROR;
        }

        if (n == 0) {
            /*
             * EOF with bytes still owed. The file is shorter than the
             * fstat() that sized this buffer said it was -- it was
             * truncated or replaced underneath us mid-load.
             */
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dictionary file \"%V\" ended after %uz of "
                               "%uz bytes; it changed size during config "
                               "load", path, done, size);
            return NGX_ERROR;
        }

        done += (size_t) n;
    }

    return NGX_OK;
}


#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400

/*
 * Advisory threshold for the implicit (no zstd_max_cctx_memory) budget
 * policy, in bytes of per-request compressor working set.
 *
 * The module retains up to NGX_HTTP_ZSTD_CCTX_SLOTS (4) contexts per
 * worker, and ZSTD_sizeof_CCtx() does not shrink on reset, so the
 * retained worker high-water mark is threshold x slots -- 128 MB at the
 * value below. Multiply again by worker_processes for the box.
 *
 * Chosen from ZSTD_estimateCStreamSize_usingCCtxParams() measured on
 * libzstd 1.5.7, streaming with unknown content size (the module's
 * path), no zstd_window_log, no LDM:
 *
 *     zstd_comp_level   estimate      per worker (x4)
 *      1                  1.3 MB           5.2 MB
 *      3 (default)        3.5 MB          14.0 MB
 *      6                  5.7 MB          23.0 MB
 *      9                 16.7 MB          67.0 MB
 *     11                 28.7 MB         115.0 MB
 *     ---- 32 MB advisory threshold ----
 *     12                 52.7 MB         211.0 MB
 *     15                 68.7 MB         275.0 MB
 *     19                 89.5 MB         358.0 MB
 *     22                769.5 MB        3078.0 MB
 *
 * and with the specialist window/LDM levers at the DEFAULT level 3:
 *
 *     zstd_long on                     137.6 MB         550.6 MB
 *     zstd_window_log 27               129.5 MB         518.0 MB
 *     zstd_long on + window_log 20       2.6 MB          10.3 MB
 *
 * 32 MB therefore falls in the natural gap between level 11 (28.7 MB)
 * and level 12 (52.7 MB): every level in the ordinary web-serving range
 * stays silent, while every profile that reaches hundreds of MB per
 * worker -- high levels, LDM, and a wide explicit window -- is named.
 * It is not a directive: an operator who wants a real bound sets
 * zstd_max_cctx_memory (hard failure), and one who has accepted the
 * larger profile sets "zstd_max_cctx_memory 0" to acknowledge it.
 */
#ifndef NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES
#define NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES  (32 * 1024 * 1024)
#endif


/*
 * Compute libzstd's own estimate of the per-request streaming compressor
 * working set for this location's configured profile.
 *
 * Single source of truth for both consumers -- the hard check against an
 * explicit zstd_max_cctx_memory and the implicit advisory -- so the two
 * cannot drift into disagreeing about what a profile costs. Every exit
 * path frees the ZSTD_CCtx_params; a leak here would be per-location at
 * config load.
 *
 * On success writes the estimate to *est and returns NGX_CONF_OK. On
 * failure it has already logged an actionable diagnostic at
 * NGX_LOG_EMERG and returns NGX_CONF_ERROR: a profile whose cost cannot
 * be computed is a configuration we refuse to start on, not one we
 * quietly stop measuring.
 */
static char *
ngx_http_zstd_estimate_cctx_memory(ngx_conf_t *cf,
    ngx_http_zstd_loc_conf_t *conf, ngx_int_t window_log, size_t *est)
{
    ZSTD_CCtx_params  *cp;
    size_t             srv;
    size_t             e;

    cp = ZSTD_createCCtxParams();
    if (cp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ZSTD_createCCtxParams() failed");
        return NGX_CONF_ERROR;
    }

    srv = ZSTD_CCtxParams_init(cp, (int) conf->level);
    if (ZSTD_isError(srv)) {
        ZSTD_freeCCtxParams(cp);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ZSTD_CCtxParams_init(level=%i) failed: %s",
                           conf->level, ZSTD_getErrorName(srv));
        return NGX_CONF_ERROR;
    }

    if (window_log > 0) {
        srv = ZSTD_CCtxParams_setParameter(cp, ZSTD_c_windowLog,
                                           (int) window_log);
        if (ZSTD_isError(srv)) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_CCtxParams_setParameter("
                               "windowLog=%i) failed: %s",
                               window_log,
                               ZSTD_getErrorName(srv));
            return NGX_CONF_ERROR;
        }
    }

    if (conf->long_mode) {
        ngx_int_t  ldm_wlog, ldm_hlog, ldm_rlog;

        srv = ZSTD_CCtxParams_setParameter(
                  cp, ZSTD_c_enableLongDistanceMatching, 1);
        if (ZSTD_isError(srv)) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_CCtxParams_setParameter("
                               "enableLongDistanceMatching) failed: %s",
                               ZSTD_getErrorName(srv));
            return NGX_CONF_ERROR;
        }

        /*
         * BLOCKER fix: ZSTD_estimateCStreamSize_usingCCtxParams()
         * divides by params->ldmParams.hashRateLog. libzstd derives
         * the LDM sub-parameters lazily, inside compression setup --
         * a ZSTD_CCtx_params that has only had
         * ZSTD_c_enableLongDistanceMatching set still carries
         * hashRateLog == 0, so the estimator divides by zero and the
         * whole process dies with SIGFPE during "nginx -t". Setting
         * ZSTD_c_windowLog does not help: the divisor is unrelated to
         * the window.
         *
         * There is no public "adjust these params the way you would
         * internally" entry point, so we derive the same four values
         * libzstd documents in zstd.h and push them explicitly. From
         * the ZSTD_c_ldm* documentation:
         *
         *   - enabling LDM raises the default windowLog to 27
         *     (128 MB) unless windowLog was expressly set;
         *   - ldmHashLog     default = windowLog - 7, clamped to
         *                    [ZSTD_LDM_HASHLOG_MIN,
         *                     ZSTD_LDM_HASHLOG_MAX];
         *   - ldmMinMatch    default = 64;
         *   - ldmBucketSizeLog default = 3;
         *   - ldmHashRateLog default = MAX(0, windowLog - ldmHashLog).
         *
         * Seeding these makes the estimate accurate rather than
         * merely non-crashing. Measured against a real streaming
         * ZSTD_CCtx compressing 256 MB with unknown content size
         * (libzstd 1.5.7, level 3): seeded estimate 144328225 bytes
         * vs. ZSTD_sizeof_CCtx() 144262689 -- 0.05% conservative.
         * With "zstd_window_log 20": 2705953 vs. 2705441, 0.02%
         * conservative. So the operator's budget still means what it
         * says under LDM; we neither crash nor silently drop the
         * bound, and we do not manufacture spurious rejections.
         *
         * Note that windowLog is pushed explicitly here even when the
         * operator did not configure one: the estimator must see the
         * same 27 that libzstd would default to under LDM, otherwise
         * it would size for the level's much smaller default window
         * and under-report by two orders of magnitude.
         */

        ldm_wlog = window_log > 0 ? window_log
                                        : NGX_HTTP_ZSTD_LDM_WINDOWLOG;

        ldm_hlog = ldm_wlog - NGX_HTTP_ZSTD_LDM_HASHLOG_OFFSET;
        if (ldm_hlog < ZSTD_LDM_HASHLOG_MIN) {
            ldm_hlog = ZSTD_LDM_HASHLOG_MIN;
        }
        if (ldm_hlog > ZSTD_LDM_HASHLOG_MAX) {
            ldm_hlog = ZSTD_LDM_HASHLOG_MAX;
        }

        ldm_rlog = ldm_wlog - ldm_hlog;
        if (ldm_rlog < 0) {
            ldm_rlog = 0;
        }

        srv = ZSTD_CCtxParams_setParameter(cp, ZSTD_c_windowLog,
                                           (int) ldm_wlog);
        if (!ZSTD_isError(srv)) {
            srv = ZSTD_CCtxParams_setParameter(cp, ZSTD_c_ldmHashLog,
                                               (int) ldm_hlog);
        }
        if (!ZSTD_isError(srv)) {
            srv = ZSTD_CCtxParams_setParameter(
                      cp, ZSTD_c_ldmMinMatch,
                      NGX_HTTP_ZSTD_LDM_MINMATCH);
        }
        if (!ZSTD_isError(srv)) {
            srv = ZSTD_CCtxParams_setParameter(
                      cp, ZSTD_c_ldmBucketSizeLog,
                      NGX_HTTP_ZSTD_LDM_BUCKETSIZELOG);
        }
        if (!ZSTD_isError(srv)) {
            srv = ZSTD_CCtxParams_setParameter(cp, ZSTD_c_ldmHashRateLog,
                                               (int) ldm_rlog);
        }

        if (ZSTD_isError(srv)) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_CCtxParams_setParameter() failed "
                               "while deriving the \"zstd_long\" "
                               "parameters for the per-request "
                               "compressor memory estimate: %s",
                               ZSTD_getErrorName(srv));
            return NGX_CONF_ERROR;
        }

        /*
         * Defence in depth. The derivation above is the documented
         * one, but it is libzstd's documentation rather than a
         * contract enforced by a public API, and a future release
         * could add a fifth divisor-bearing sub-parameter. Rather
         * than risk another SIGFPE taking out "nginx -t", refuse the
         * configuration if the estimate would still be computed from
         * a zero divisor we know about.
         */
        if (ldm_rlog <= 0) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the per-request compressor memory "
                               "estimate cannot be computed for this "
                               "\"zstd_long\" profile: the derived LDM "
                               "hash rate is zero (window_log %i). Raise "
                               "\"zstd_window_log\" or disable "
                               "\"zstd_long\"",
                               (ngx_int_t) ldm_wlog);
            return NGX_CONF_ERROR;
        }
    }

#if ZSTD_VERSION_NUMBER >= 10506
    if (conf->target_cblock_size > 0) {
        srv = ZSTD_CCtxParams_setParameter(
                  cp, ZSTD_c_targetCBlockSize,
                  (int) conf->target_cblock_size);
        if (ZSTD_isError(srv)) {
            ZSTD_freeCCtxParams(cp);
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_CCtxParams_setParameter("
                               "targetCBlockSize=%z) failed: %s",
                               conf->target_cblock_size,
                               ZSTD_getErrorName(srv));
            return NGX_CONF_ERROR;
        }
    }
#endif

    e = ZSTD_estimateCStreamSize_usingCCtxParams(cp);
    ZSTD_freeCCtxParams(cp);

    if (ZSTD_isError(e)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ZSTD_estimateCStreamSize_usingCCtxParams() "
                           "failed: %s", ZSTD_getErrorName(e));
        return NGX_CONF_ERROR;
    }

    *est = e;

    return NGX_CONF_OK;
}


/*
 * Largest window log whose estimated CCtx memory still fits
 * "zstd_max_cctx_memory", for the dcz path to clamp against.
 *
 * Why this exists: the nginx -t gate below vets ONE figure, computed from
 * conf->window_log. A dcz (RFC 9842) request does not use that window -- it
 * derives its own from the negotiated dictionary, up to
 * NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG -- so it walks straight through a budget
 * config load already accepted. Measured on libzstd 1.5.7 at level 3, the
 * escape is 3 663 393 B (default window) vs 9 954 849 B (wlog 23), 2.72x;
 * at level 1 it is 6.74x. "zstd_max_cctx_memory" is a memory ceiling of the
 * same class as "zstd_window_log", and the module already holds that a
 * dictionary must not silently void such a ceiling (audit C2/R1).
 *
 * Why at config load: the answer depends only on config -- level, long mode,
 * target block size, budget -- so it is computed ONCE here and the request
 * path does a min(). ZSTD_estimateCStreamSize_usingCCtxParams() per request
 * would be a hot-path regression for a constant.
 *
 * Search is a downward walk from NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG to
 * NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG, inclusive: at most 14 estimate calls,
 * once, and monotonicity of workspace in the window is not assumed. The
 * floor is NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG -- returning less would push an
 * invalid windowLog into libzstd. The floor is itself estimated and checked
 * like every other candidate, rather than assumed to fit by falling out of
 * the loop unevaluated. The floor cannot actually fail to fit once the
 * caller's gate has passed -- see the invariant argument at the pin below
 * -- so the fallthrough pins to the floor rather than raising a second,
 * differently-worded rejection for a config the gate already vetted.
 *
 * Writes 0 ("no cap") and succeeds when no budget is configured -- the
 * default, where dcz behaviour must be exactly what it was.
 */
static char *
ngx_http_zstd_dcz_window_cap(ngx_conf_t *cf, ngx_http_zstd_loc_conf_t *conf,
    ngx_int_t *cap)
{
    ngx_int_t  wlog;
    size_t     est;

    *cap = 0;

    if (conf->max_cctx_memory == NGX_CONF_UNSET
        || conf->max_cctx_memory <= 0)
    {
        return NGX_CONF_OK;
    }

    for (wlog = NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG;
         wlog >= NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG;
         wlog--)
    {
        if (ngx_http_zstd_estimate_cctx_memory(cf, conf, wlog, &est)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (est <= (size_t) conf->max_cctx_memory) {
            break;
        }
    }

    /*
     * If even NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG did not fit the budget, the
     * loop above still evaluated it (unlike the old wlog > MIN loop, which
     * exited with the floor unevaluated) and then decremented past it. Pin
     * the cap back to the floor: this function must not return a windowLog
     * below its documented floor.
     *
     * The pin is a defensive invariant, not budget enforcement, and needs
     * no error path: whenever the caller's hard gate passed, this branch
     * is unreachable. (The search above still does not assume
     * monotonicity -- that keeps the chosen cap correct under any
     * libzstd; the argument here is only about whether the fallthrough
     * can be entered at all.) NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG equals
     * ZSTD_WINDOWLOG_MIN, so the floor is the smallest window libzstd
     * accepts, and ZSTD_estimateCStreamSize_usingCCtxParams() is monotone
     * non-decreasing in windowLog. The gate estimates at a window that is
     * never below the floor, hence est(floor) <= est(gate window): a
     * budget the gate accepted always admits the floor too.
     *
     * Two changes would falsify that and require re-examining this branch:
     * a libzstd whose workspace estimate is non-monotone in windowLog, or
     * raising NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG above ZSTD_WINDOWLOG_MIN.
     */
    if (wlog < NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG) {
        wlog = NGX_HTTP_ZSTD_DCZ_MIN_WINDOW_LOG;
    }

    *cap = wlog;

    return NGX_CONF_OK;
}

#endif


/*
 * Detects a DIRECT "$http_*" or "$cookie_*" reference in one zstd_bypass
 * predicate's source text (ngx_http_complex_value_t.value keeps the raw
 * argument as written, even for a script with embedded variables -- see
 * ccv->complex_value->value = *v in ngx_http_compile_complex_value()).
 *
 * Deliberately narrow: only the literal "$http_" / "$cookie_" spellings
 * count. A map or any other indirection (e.g. a "map" result variable) is
 * an explicit documented operator responsibility and must stay silent --
 * a false warning on a map is worse than missing the direct case.
 */
static ngx_uint_t
ngx_http_zstd_predicate_is_direct_header_or_cookie(const ngx_str_t *v)
{
    u_char  *p, *last;

    p = v->data;
    last = v->data + v->len;

    while (p < last) {
        p = ngx_strlchr(p, last, '$');
        if (p == NULL) {
            return 0;
        }

        p++;

        if (p < last && *p == '{') {
            p++;
        }

        if ((size_t) (last - p) >= sizeof("http_") - 1
            && ngx_strncmp(p, "http_", sizeof("http_") - 1) == 0)
        {
            return 1;
        }

        if ((size_t) (last - p) >= sizeof("cookie_") - 1
            && ngx_strncmp(p, "cookie_", sizeof("cookie_") - 1) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static void
ngx_http_zstd_validate_bypass_vary(ngx_conf_t *cf,
    ngx_http_zstd_loc_conf_t *conf)
{
    ngx_http_complex_value_t  *cv;
    ngx_uint_t                 i;

    /* Warn for either half of a cache-vary contract configured alone. */
    if (conf->bypass_vary.len && conf->bypass == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"zstd_bypass_vary\" is set without a "
                           "\"zstd_bypass\" predicate; it adds a \"Vary: %V\" "
                           "field no response varies on. Add a "
                           "\"zstd_bypass\" directive or remove "
                           "\"zstd_bypass_vary\"", &conf->bypass_vary);
    }

    if (conf->bypass == NULL || conf->bypass_vary.len != 0) {
        return;
    }

    cv = conf->bypass->elts;

    for (i = 0; i < conf->bypass->nelts; i++) {
        if (ngx_http_zstd_predicate_is_direct_header_or_cookie(&cv[i].value)) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "\"zstd_bypass\" predicate \"%V\" reads "
                               "a request header or cookie directly "
                               "without a \"zstd_bypass_vary\"; a shared "
                               "cache may mix identity and compressed "
                               "responses under the same key. Add a "
                               "\"zstd_bypass_vary\" directive naming the "
                               "header this varies on", &cv[i].value);
            return;
        }
    }
}


static char *
ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_loc_conf_t *prev = parent;
    ngx_http_zstd_loc_conf_t *conf = child;

    ngx_fd_t                    fd;
    off_t                       fsize;
    size_t                      size;
    char                       *rc;
    u_char                     *buf;
    ngx_file_info_t             info;
    ngx_http_zstd_main_conf_t  *zmcf;

    rc = NGX_CONF_OK;
    buf = NULL;
    fd = NGX_INVALID_FILE;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    /*
     * Hand-rolled rather than ngx_conf_merge_value(): that macro tests
     * against NGX_CONF_UNSET, which is a legal level here. See
     * NGX_HTTP_ZSTD_LEVEL_UNSET above.
     */
    if (conf->level == NGX_HTTP_ZSTD_LEVEL_UNSET) {
        conf->level = (prev->level == NGX_HTTP_ZSTD_LEVEL_UNSET)
                      ? 3 : prev->level;
    }

    ngx_conf_merge_value(conf->min_length, prev->min_length, 1024);
    ngx_conf_merge_value(conf->max_length, prev->max_length, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->target_cblock_size, prev->target_cblock_size, 0);
    ngx_conf_merge_value(conf->window_log, prev->window_log, 0);
    ngx_conf_merge_value(conf->long_mode, prev->long_mode, 0);
    /*
     * Merged to NGX_CONF_UNSET, not to 0, deliberately: the implicit
     * advisory below has to tell "the operator never mentioned this
     * directive" apart from "the operator wrote zstd_max_cctx_memory
     * off", and ngx_conf_set_size_slot() stores the latter as 0. Folding
     * UNSET to 0 here would collapse the two into one value and make the
     * acknowledgement indistinguishable from silence -- the advisory
     * would then either never fire or ignore "off". The only other
     * reader is the explicit-budget check, which already tests
     * "!= NGX_CONF_UNSET && > 0" and is unaffected.
     */
    ngx_conf_merge_value(conf->max_cctx_memory, prev->max_cctx_memory,
                         NGX_CONF_UNSET);
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_str_value(conf->bypass_vary, prev->bypass_vary, "");

    /*
     * Sort an array owned by this location once, after its last
     * zstd_dcz_dict_file push and before inheritance is resolved. An
     * inheriting child must not re-sort the parent's shared array. No
     * pointer into the array is captured before this point --
     * ngx_http_zstd_dcz_negotiate() takes &dicts[i]/&dicts[mid] only at
     * request time, long after config load finishes -- so re-ordering
     * the elements here cannot invalidate anything a caller is holding.
     * See ngx_http_zstd_dcz_dict_cmp() for why the order is unambiguous.
     */
    if (conf->dcz_dicts != NGX_CONF_UNSET_PTR) {
        ngx_http_zstd_dcz_dict_sort(conf->dcz_dicts);
    }

    /* a location that declares its own zstd_dcz_dict_file list replaces the
     * inherited one wholesale (standard nginx array-directive semantics) */
    ngx_conf_merge_ptr_value(conf->dcz_dicts, prev->dcz_dicts, NULL);

    ngx_conf_merge_value(conf->dcz_assume_secure, prev->dcz_assume_secure, 0);

    /* Validate the paired bypass/cache-vary directives after inheritance. */
    ngx_http_zstd_validate_bypass_vary(cf, conf);
    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_zstd_default_types))
    {
        return NGX_CONF_ERROR;
    }

    /*
     * NOTE: do NOT ngx_conf_merge_ptr_value(conf->dict, prev->dict, NULL)
     * here. That copied the parent pointer before the level/window
     * comparison below, leaving conf->dict non-NULL so the "build a fresh
     * child CDict" branch could never run — a child that changed
     * zstd_comp_level silently inherited the parent-level CDict. The dict is
     * resolved explicitly in the block below instead. See C2.
     */

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

    /*
     * Default the output buffer size to the cached ZSTD_CStreamOutSize()
     * value — the encoder's own recommended output granularity (~128 KB).
     * It is the documented minimum at which ZSTD_compressStream2() can
     * flush a full internal block in a single call; with any smaller
     * buffer zstd is forced to fragment a block across calls, costing
     * extra compress round-trips and ngx_alloc_chain_link() churn per
     * response. The previous 4 x 32 KB heuristic approximated this; using
     * the API's value is the principled form and tracks libzstd if it ever
     * changes.
     *
     * Two such buffers: one being filled by the compressor while the
     * other is in flight down the output chain. This raises the
     * per-request filter-memory floor to ~2 x CStreamOutSize()
     * (~256 KB) from the prior ~128 KB — the deliberate cost of never
     * forcing zstd to mid-block flush. Operators who set zstd_buffers
     * explicitly are unaffected (the merge keeps their value), and can
     * tune it down if the memory trade is wrong for their workload.
     *
     * The constant-returning libzstd call is now cached at init_main_conf
     * and reused here instead of being called once per location merge.
     */
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              2, zmcf->stream_out_size);
    ngx_conf_merge_value(conf->bufs_unsafe, prev->bufs_unsafe, 0);

    /*
     * The parse-time slot (ngx_http_zstd_set_bufs_slot()) only sees an
     * EXPLICIT "zstd_buffers" written at this exact location. A value
     * this location inherited from an outer block via
     * ngx_conf_merge_bufs_value() above, or the module's own computed
     * default (2 x stream_out_size when nothing was written anywhere in
     * the chain), never passes through that slot handler and so is
     * otherwise never checked at all. Re-run the same product bound here
     * so every value conf->bufs can hold by the time the filter reads it
     * -- explicit, inherited, or defaulted -- has been validated exactly
     * once.
     */
    if (rc == NGX_CONF_OK
        && ngx_http_zstd_check_bufs_product(cf, &conf->bufs,
                                             conf->bufs_unsafe,
                                             "merged value", 1)
           != NGX_CONF_OK)
    {
        rc = NGX_CONF_ERROR;
    }

    if (conf->enable && zmcf->dict_file.len > 0) {

        ngx_http_zstd_dict_entry_t  *entry, *new_entry;
        ngx_uint_t                   i;

        entry = NULL;

        if (zmcf->dict_registry != NULL) {
            ngx_http_zstd_dict_entry_t  *entries;

            entries = zmcf->dict_registry->elts;

            for (i = 0; i < zmcf->dict_registry->nelts; i++) {
                if (entries[i].level == conf->level
                    && entries[i].window_log == conf->window_log)
                {
                    entry = &entries[i];
                    break;
                }
            }
        }

        if (entry != NULL) {
            /*
             * A location anywhere earlier in this cycle already built a
             * CDict for this exact (level, window_log) — the complete
             * key, see the registry field's comment above. Reuse it: no
             * file read, no CDict build, whether that prior location was
             * this one's parent or an unrelated sibling.
             */
            conf->dict = entry->dict;

        } else {
            /*
             * No registry entry for this profile yet: this is the first
             * location in the cycle to need it. Load the raw dictionary
             * bytes if no earlier profile has already done so (dict_buf
             * is cycle-wide, independent of the profile), then build the
             * CDict and register it under this key so every later
             * location — sibling or descendant — reuses it.
             */

            if (zmcf->dict_buf == NULL) {

                fd = ngx_http_zstd_open_dict_file(cf, &zmcf->dict_file,
                                                  zmcf->dict_strict_path,
                                                  &info);

                if (fd == NGX_INVALID_FILE) {
                    return NGX_CONF_ERROR;
                }

                /*
                 * Compare as off_t BEFORE narrowing to size_t: on an
                 * ILP32 build with large-file support a >4 GiB
                 * dictionary wraps to a small size_t, slipping past the
                 * cap below and loading a truncated dictionary.
                 */
                fsize = ngx_file_size(&info);

                /* Validate dictionary file size to prevent DoS
                 * via memory exhaustion */
                if (fsize > (off_t) NGX_HTTP_ZSTD_MAX_DICT_SIZE) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary file too large: %O "
                                       "bytes (limit: %d bytes)",
                                       fsize, NGX_HTTP_ZSTD_MAX_DICT_SIZE);

                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                /*
                 * Reject an empty file rather than loading a do-nothing
                 * dictionary. ZSTD_createCDict(buf, 0, level) returns a
                 * VALID CDict, and ngx_read_fd(..., 0) returns 0 == size,
                 * so every completeness check downstream passes and the
                 * operator -- who had to set zstd_dict_file_unsafe on to
                 * get here -- silently gets no dictionary at all. The
                 * dcz loader below has always rejected this; the two now
                 * agree.
                 */
                if (fsize == 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "dictionary file \"%V\" is empty",
                                       &zmcf->dict_file);

                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                size = (size_t) fsize;

                buf = ngx_palloc(cf->pool, size);
                if (buf == NULL) {
                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                if (ngx_http_zstd_read_dict_file(cf, fd,
                                                 &zmcf->dict_file,
                                                 buf, size)
                    != NGX_OK)
                {
                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                if (ngx_close_file(fd) == NGX_FILE_ERROR) {
                    /*
                     * The descriptor is consumed either way: invalidate it
                     * BEFORE jumping, or the close: label closes the same fd
                     * a second time and logs a duplicate error.
                     */
                    fd = NGX_INVALID_FILE;

                    ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                       ngx_close_file_n " \"%V\" failed",
                                       &zmcf->dict_file);

                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                fd = NGX_INVALID_FILE;

                zmcf->dict_buf = buf;
                zmcf->dict_buf_size = size;
            }

            buf = zmcf->dict_buf;
            size = zmcf->dict_buf_size;

            /*
             * Bake the location's effective compression parameters into the
             * CDict. ZSTD_CCtx_refCDict() lets a CDict's own
             * ZSTD_compressionParameters supersede compressionLevel (and the
             * other superseded-by-cdict parameters in that zstd.h block) set
             * on the CCtx -- but NOT windowLog: ZSTD_resetCCtx_
             * byAttachingCDict()/ZSTD_resetCCtx_byCopyingCDict() both restore
             * windowLog from the CCtx's OWN params.cParams.windowLog right
             * after copying the CDict's other cParams (init_cctx's windowLog
             * comment has the exact source citation), and assert it is
             * nonzero -- i.e. the CCtx side must have set it, every time, CDict
             * or not. A CDict built with the simple ZSTD_createCDict() (level
             * only, windowLog left at the level's own default) would then
             * disagree with init_cctx's zlcf->window_log-derived cap: the
             * FRAME uses windowLog from the CCtx side (correct), but this
             * repo's own zstd_max_cctx_memory estimate and the CCtx ring-slot
             * key both need to reason about the SAME windowLog the CDict's
             * match tables were sized for (former audit C2 / R1). Build the
             * CDict with ZSTD_createCDict_advanced() seeding windowLog from
             * zstd_window_log so the CDict's tables, the CCtx's applied
             * windowLog, and this module's own memory accounting all agree.
             * The advanced builder lives in libzstd's static API; on a
             * non-static build fall back to the level-only CDict (window cap
             * still applies via init_cctx's CCtx-side set either way, but the
             * CDict's own tables are then sized off the level default instead
             * of zstd_window_log — documented in README).
             *
             * Long-distance matching is a separate CCtx frame parameter, not
             * part of ZSTD_compressionParameters, so refCDict does not override
             * it; zstd_long keeps applying via the CCtx in init_cctx — and is
             * correctly excluded from the registry key above for the same
             * reason.
             */
#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400
            {
                ZSTD_compressionParameters  cparams;

                cparams = ZSTD_getCParams((int) conf->level, 0, size);

                if (conf->window_log > 0) {
                    cparams.windowLog = (unsigned) conf->window_log;
                }

                conf->dict = ZSTD_createCDict_advanced(buf, size,
                                 ZSTD_dlm_byRef, ZSTD_dct_auto, cparams,
                                 ZSTD_defaultCMem);
            }
#else
            conf->dict = ZSTD_createCDict(buf, size, conf->level);
#endif
            if (conf->dict == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_createCDict() failed");
                rc = NGX_CONF_ERROR;
                goto close;
            }

            /* Register cleanup handler to free dictionary when
             * config is destroyed.
             * Note: on this (static-API) path the CDict is built
             * ZSTD_dlm_byRef — it holds a reference into dict_buf, not
             * a private copy, for its entire lifetime. This is safe
             * across reload because dict_buf and the CDict share the
             * same cf->pool: ngx_destroy_pool() runs this cleanup
             * handler (ZSTD_freeCDict) before releasing any pool
             * allocation, so dict_buf outlives every CDict built from
             * it, and an old worker retains its whole old cycle (pool
             * included) until it exits. See the dict_buf field comment
             * above for the full argument. */
            {
                ngx_pool_cleanup_t  *cln;

                cln = ngx_pool_cleanup_add(cf->pool, 0);
                if (cln == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "ngx_pool_cleanup_add() failed");
                    /*
                     * The CDict is allocated outside the config pool and is
                     * only reclaimed by the cleanup handler we failed to
                     * register. Free it here (and drop the dangling pointer)
                     * so a failed reload does not leak the external libzstd
                     * allocation while the master keeps running.
                     */
                    ZSTD_freeCDict(conf->dict);
                    conf->dict = NULL;
                    rc = NGX_CONF_ERROR;
                    goto close;
                }

                cln->handler = ngx_http_zstd_cleanup_dict;
                cln->data = conf->dict;
            }

            /*
             * Register this (level, window_log) -> CDict mapping in the
             * cycle-wide registry so every other location at the same
             * profile — reached before or after this one in the config
             * tree — reuses this exact CDict instead of building its own.
             * The registry array lives in cf->pool, same lifetime as the
             * main conf and every CDict cleanup handler above.
             */
            if (zmcf->dict_registry == NULL) {
                zmcf->dict_registry = ngx_array_create(cf->pool, 4,
                                          sizeof(ngx_http_zstd_dict_entry_t));
                if (zmcf->dict_registry == NULL) {
                    rc = NGX_CONF_ERROR;
                    goto close;
                }
            }

            new_entry = ngx_array_push(zmcf->dict_registry);
            if (new_entry == NULL) {
                rc = NGX_CONF_ERROR;
                goto close;
            }

            new_entry->level = conf->level;
            new_entry->window_log = conf->window_log;
            new_entry->dict = conf->dict;

            /*
             * dict_buf is cycle-wide now (zmcf->dict_buf), not freed
             * here: a later location at a DIFFERENT profile still needs
             * these same raw bytes to build its own CDict. It is
             * reclaimed by ordinary cf->pool cleanup at cycle teardown,
             * the same point every CDict's cleanup handler runs.
             *
             * On the static-API (byRef) path this is stronger than "a
             * later build needs it too": every CDict already built from
             * dict_buf keeps reading it for its entire remaining
             * lifetime, not just until its own construction finishes.
             * Freeing dict_buf early here would be a use-after-free for
             * EVERY profile built from it so far, not only the next
             * distinct one — see the dict_buf field comment above.
             */
        }
    }

close:

    if (fd != NGX_INVALID_FILE && ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &zmcf->dict_file);

        rc = NGX_CONF_ERROR;
    }

    /*
     * Per-request CCtx memory policy (config load).
     *
     * zstd's streaming compressor working set is dominated by the
     * compression-level *strategy* tables (chain/hash/search), not by
     * the window alone -- see the README. Lowering windowLog therefore
     * does NOT meaningfully bound memory for high levels (level 22 at
     * windowLog 20 still estimates ~642 MB per context). The honest,
     * precise lever is libzstd's own estimator, run at config load
     * against the parameters this location actually merged.
     *
     * Two consumers, one estimate (ngx_http_zstd_estimate_cctx_memory()
     * above computes it for both, so they cannot drift):
     *
     *   1. An explicit non-zero "zstd_max_cctx_memory" is a budget the
     *      operator asked to be held to. Exceeding it is a hard error at
     *      config load, unchanged: a too-tight budget is a
     *      misconfiguration the operator should see up front rather than
     *      discover as a worker-RSS surprise under concurrency.
     *
     *   2. No "zstd_max_cctx_memory" at all is the far more common case,
     *      and it used to mean the estimator never ran -- so a later
     *      "zstd_comp_level 22" or "zstd_long on" could quietly commit
     *      hundreds of MB per concurrent response even though the module
     *      already knew the number at config load. Compression enabled
     *      with no explicit budget therefore now runs the same estimate
     *      and WARNS when it exceeds NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES.
     *
     * Why the implicit path warns rather than fails: turning "nginx -t"
     * from pass to fail on a configuration that works today would break
     * running deployments on upgrade. The advisory names the number and
     * the retained worker bound, and tells the operator the two ways to
     * silence it -- an explicit budget (which restores the hard check)
     * or an explicit "zstd_max_cctx_memory 0", which is the
     * acknowledgement that the larger profile is intentional.
     *
     * The estimator API lives in libzstd's experimental section
     * (ZSTDLIB_STATIC_API), so both paths are compiled in only when the
     * module is built with -DZSTD_STATIC_LINKING_ONLY against
     * libzstd >= 1.4.0 (the project's production and CI builds enable
     * this). Without it an explicit directive is rejected with an
     * actionable error rather than silently no-op'd, and the implicit
     * advisory simply does not run -- a non-static build must not
     * pretend to be enforcing a bound it cannot compute.
     */
    if (rc == NGX_CONF_OK && conf->enable
        && conf->max_cctx_memory != NGX_CONF_UNSET
        && conf->max_cctx_memory > 0)
    {
#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400
        size_t  est;

        if (ngx_http_zstd_estimate_cctx_memory(cf, conf,
                                               conf->window_log, &est)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (est > (size_t) conf->max_cctx_memory) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the configured zstd parameters need ~%uz "
                               "bytes of per-request compressor memory, "
                               "which exceeds \"zstd_max_cctx_memory\" %z; "
                               "lower \"zstd_comp_level\" (currently %i), "
                               "lower \"zstd_window_log\", disable "
                               "\"zstd_long\", or raise the budget",
                               est, conf->max_cctx_memory, conf->level);
            return NGX_CONF_ERROR;
        }

        /*
         * The gate above vets conf->window_log. A dcz request derives its
         * own, larger window from the negotiated dictionary and would walk
         * straight through the budget, so precompute the largest window log
         * that still fits it; ngx_http_zstd_dcz_window_log() clamps to this.
         * Config-load work for a value that is constant per location -- the
         * request path only does a min().
         */
        if (ngx_http_zstd_dcz_window_cap(cf, conf, &conf->dcz_window_cap)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_max_cctx_memory\" requires the module "
                           "to be built with -DZSTD_STATIC_LINKING_ONLY "
                           "against libzstd >= 1.4.0 (memory-estimation "
                           "API); rebuild accordingly, or use "
                           "\"zstd_window_log\" for a coarse window-based "
                           "bound");
        return NGX_CONF_ERROR;
#endif
    }

    /*
     * Implicit advisory: compression enabled, no explicit budget.
     *
     * "max_cctx_memory == 0" is reached two ways and they mean different
     * things. NGX_CONF_UNSET means the operator never mentioned the
     * directive anywhere in the inheritance chain -- that is the case
     * this advisory exists for. A merged 0 that is NOT UNSET came from
     * an explicit "zstd_max_cctx_memory 0", which is the operator
     * acknowledging the profile. The two are only distinguishable
     * because the merge above preserves NGX_CONF_UNSET instead of
     * folding it to 0; see the note there.
     */
    if (rc == NGX_CONF_OK && conf->enable
        && conf->max_cctx_memory == NGX_CONF_UNSET)
    {
#if defined(ZSTD_STATIC_LINKING_ONLY) && ZSTD_VERSION_NUMBER >= 10400
        size_t  est;

        if (ngx_http_zstd_estimate_cctx_memory(cf, conf,
                                               conf->window_log, &est)
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (est > NGX_HTTP_ZSTD_CCTX_ADVISORY_BYTES) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "the configured zstd parameters need ~%uz "
                               "bytes of per-request compressor memory "
                               "(zstd_comp_level %i); each worker retains "
                               "up to %d such contexts, so worker RSS can "
                               "reach ~%uz bytes, and that again per "
                               "worker process. Set "
                               "\"zstd_max_cctx_memory\" to a budget to "
                               "have this enforced at config load, or "
                               "\"zstd_max_cctx_memory 0\" to "
                               "acknowledge the profile and silence this "
                               "warning",
                               est, conf->level,
                               (int) NGX_HTTP_ZSTD_CCTX_SLOTS,
                               est * NGX_HTTP_ZSTD_CCTX_SLOTS);
        }
#endif
    }

    /*
     * G5: there is no longer a gzip_vary-off warning here. The header
     * filter emits "Vary: Accept-Encoding" itself on every
     * Accept-Encoding-dependent response (see
     * ngx_http_zstd_vary_accept_encoding()), so correctness no longer
     * depends on the operator setting "gzip_vary on", and the whole
     * question of whether some other module might be emitting Vary on
     * our behalf is moot. Warning about a directive that no longer
     * changes whether the header appears would be actively misleading.
     */

    return rc;
}


static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

#ifdef NGX_TEST_HARNESS
    /*
     * Register the zoneless probe hooks unconditionally, BEFORE the
     * any_enabled early return below: the probe endpoint (reached only
     * through the "zstd_probe" directive, on a location an operator opts
     * into explicitly) must stay reachable even in a config where every
     * "zstd" directive is off, so a test can assert the disabled state
     * itself.
     */
    if (ngx_http_zstd_probe_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }
#endif

    /*
     * TODO row: do not install request hooks when the module is
     * disabled in every merged location. any_enabled is latched
     * conservatively at directive PARSE time (see
     * ngx_http_zstd_set_enable_slot() and the field's own comment on
     * ngx_http_zstd_main_conf_t) by every "zstd on;"/non-"off" value
     * parsed anywhere in this cycle's config, including inside an "if"
     * block. Skipping registration here only removes the two no-op
     * calls an all-disabled deployment currently pays on every
     * response; any location that could compress still gets both
     * filters wired exactly as before.
     */
    if (!zmcf->any_enabled) {
        return NGX_OK;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_zstd_body_filter;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *v;

    /*
     * TODO row: no blanket NGX_HTTP_VAR_NOCACHEABLE here. Each handler
     * below sets vv->no_cacheable per-call instead -- 1 while the
     * compression for this request has not finished yet (ctx->done ==
     * 0), 0 once it reports the final value. nginx's variable cache
     * (ngx_http_get_indexed_variable()) retries a flushed no_cacheable
     * result on the next lookup but reuses a cacheable one, so the
     * first post-completion lookup formats the value once and every
     * later lookup in the same request (e.g. repeated log/map
     * references) reuses that cached ngx_http_variable_value_t instead
     * of reformatting or redividing.
     */
    v = ngx_http_add_variable(cf, &ngx_http_zstd_ratio, 0);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_ratio_variable;

    v = ngx_http_add_variable(cf, &ngx_http_zstd_bytes_in, 0);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_bytes_variable;
    v->data = offsetof(ngx_http_zstd_ctx_t, bytes_in);

    v = ngx_http_add_variable(cf, &ngx_http_zstd_bytes_out, 0);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_bytes_variable;
    v->data = offsetof(ngx_http_zstd_ctx_t, bytes_out);

    v = ngx_http_add_variable(cf, &ngx_http_zstd_dcz_dicts_hashed_name, 0);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_dcz_dicts_hashed_variable;

    return NGX_OK;
}


/*
 * $zstd_dcz_dicts_hashed — how many dcz dictionaries were SHA-256'd at
 * config load in the request's ACTIVE configuration. By default that is
 * the dictionary count, including verified literals. With trust_hashes
 * on, supplied literals are skipped and only literal-free entries count;
 * 0 proves that every entry used a trusted literal. Constant for the
 * lifetime of the configuration; reads the cycle-owned main conf, so a
 * rejected reload cannot leak a refused config's count into this value.
 */
static ngx_int_t
ngx_http_zstd_dcz_dicts_hashed_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    (void) data;

    zmcf = ngx_http_get_module_main_conf(r, ngx_http_zstd_filter_module);

    /*
     * Consistency with merge_loc_conf(), filter_init() and both static-module
     * sites, which all guard this. The main conf is present whenever the
     * module is loaded, so this cannot fire today -- but a reader should not
     * have to prove that from four other call sites to know it is safe.
     */
    if (zmcf == NULL) {
        vv->not_found = 1;
        return NGX_OK;
    }

    vv->data = zmcf->dcz_dicts_hashed_str.data;
    vv->len = zmcf->dcz_dicts_hashed_str.len;

    vv->valid = 1;
    vv->no_cacheable = 0;
    vv->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_uint_t                  ratio_int, ratio_frac;
    const ngx_http_zstd_ctx_t  *ctx;

    (void) data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);
    if (ctx == NULL || ctx->aborted || !ctx->done || ctx->bytes_out == 0) {
        vv->not_found = 1;
        vv->no_cacheable = 1;
        return NGX_OK;
    }

    /* Two ngx_uint_t values (up to NGX_INT_T_LEN digits each) + '.' + '\0' */
    vv->data = ngx_http_zstd_pnalloc(r->pool, NGX_INT_T_LEN * 2 + 2);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    ngx_http_zstd_ratio_parts(ctx->bytes_in, ctx->bytes_out, &ratio_int,
                               &ratio_frac);

    vv->len = ngx_sprintf(vv->data, "%ui.%03ui", ratio_int, ratio_frac)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 0;

    return NGX_OK;
}


/*
 * $zstd_bytes_in / $zstd_bytes_out — absolute byte counts for the
 * compressed response, complementing $zstd_ratio (which only gives the
 * ratio). `data` is the offsetof() of the ctx field to report, so one
 * handler serves both. Only set once the filter has successfully finished
 * compressing this response (log phase), like $zstd_ratio. no_cacheable
 * tracks that same transition (see ngx_http_zstd_add_variables()'s comment):
 * 1 for a pre-completion or aborted not_found result, 0 for the final
 * formatted value.
 */
static ngx_int_t
ngx_http_zstd_bytes_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    uint64_t              value;
    ngx_http_zstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);
    if (ctx == NULL || ctx->aborted || !ctx->done) {
        vv->not_found = 1;
        vv->no_cacheable = 1;
        return NGX_OK;
    }

    value = *(uint64_t *) ((char *) ctx + data);

    vv->data = ngx_http_zstd_pnalloc(r->pool, NGX_INT64_LEN);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    vv->len = ngx_sprintf(vv->data, "%uL", value) - vv->data;
    vv->valid = 1;
    vv->no_cacheable = 0;

    return NGX_OK;
}


static void
ngx_http_zstd_cleanup_cctx(void *data)
{
    ZSTD_CCtx *cctx = data;

    if (cctx != NULL) {
        ZSTD_freeCCtx(cctx);
    }
}


#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
static void
ngx_http_zstd_cleanup_evp_md_ctx(void *data)
{
    EVP_MD_CTX_free(data);
}


static void
ngx_http_zstd_init_evp_md_ctx(ngx_conf_t *cf,
    ngx_http_zstd_main_conf_t *zmcf)
{
    ngx_pool_cleanup_t  *cln;

    zmcf->dcz_evp_md_ctx_attempted = 1;
    zmcf->dcz_evp_md_ctx = EVP_MD_CTX_new();
    if (zmcf->dcz_evp_md_ctx == NULL) {
        return;
    }

    cln = ngx_http_zstd_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        EVP_MD_CTX_free(zmcf->dcz_evp_md_ctx);
        zmcf->dcz_evp_md_ctx = NULL;
        return;
    }

    cln->handler = ngx_http_zstd_cleanup_evp_md_ctx;
    cln->data = zmcf->dcz_evp_md_ctx;
}
#endif


/*
 * Return a borrowed worker context to the cache at request end.
 *
 * Runs from the request pool's cleanup list, so it fires on every exit path --
 * normal completion, client abort, upstream error, worker shutdown of a live
 * request -- which is what makes `busy` a reliable loan flag rather than a leak
 * waiting for the one path that forgot to clear it.
 *
 * The session is reset HERE, not only on the next acquire: a request may be
 * abandoned mid-stream (client reset on a partially compressed response), and
 * leaving that half-finished frame state resident means the cached context
 * holds the previous response's compression state until something else
 * claims it.
 * init_cctx does reset before reuse, so this is defence in depth against a
 * future caller that forgets. It does NOT release the session's internal
 * buffers: measured on libzstd 1.5.7, ZSTD_sizeof_CCtx() is byte-identical
 * before and after ZSTD_reset_session_only at levels 1/7/13/19, for both a
 * completed stream and one abandoned mid-stream. The workspace is
 * level-driven and stays pinned until the slot is freed or replaced; this
 * reset only clears session/frame state, not memory.
 */
static void
ngx_http_zstd_release_cctx(void *data)
{
    ngx_http_zstd_cctx_slot_t  *slot = data;

    if (slot == NULL || slot->cctx == NULL) {
        return;
    }

    /*
     * The lending slot is handed straight to this handler: acquire_cctx()
     * already had it, and nginx's cleanup data is an opaque void *, not a
     * CCtx-only contract. Returning the loan is therefore O(1) with no
     * search.
     *
     * This replaced a pointer-identity walk over the ring. That walk also
     * carried a "not found -> ZSTD_freeCCtx()" fallback for a slot replaced
     * mid-loan; the fallback was already unreachable, because a slot on loan
     * is never evicted or re-seeded (acquire_cctx() skips every busy slot,
     * and only ever seeds one that is empty AND not busy). Any future
     * eviction policy must preserve that invariant -- evicting a busy slot
     * would free a context a live request is still writing into, which no
     * amount of searching here could make safe.
     */
    (void) ZSTD_CCtx_reset(slot->cctx, ZSTD_reset_session_only);
    slot->busy = 0;
}


/* Warn on ABI-compatible skew, but fail when configured compile-time gates
 * rely on a feature floor the dynamically loaded library does not meet. */
static ngx_int_t
ngx_http_zstd_init_module(ngx_cycle_t *cycle)
{
    unsigned                    runtime;
    ngx_http_zstd_version_result_t  policy;
    ngx_http_zstd_main_conf_t  *zmcf;

    runtime = ZSTD_versionNumber();

    zmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                                ngx_http_zstd_filter_module);
    if (zmcf == NULL) {
        /*
         * No http block in this configuration -- a stream-only or
         * mail-only nginx that happens to carry the module. Nothing is
         * configured, so there is no feature floor to enforce; treating
         * this as an error kept such a binary from starting at all,
         * and with no diagnostic (init-module failures are silent).
         */
        return NGX_OK;
    }

    policy = ngx_http_zstd_version_policy(ZSTD_VERSION_NUMBER, runtime,
                                          zmcf->any_target_cblock_size,
                                          zmcf->any_negative_level);
    if (policy == NGX_HTTP_ZSTD_VERSION_OK) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "zstd module was built with libzstd %ui but loaded "
                  "libzstd %ui at runtime",
                  (ngx_uint_t) ZSTD_VERSION_NUMBER, (ngx_uint_t) runtime);

    if (policy == NGX_HTTP_ZSTD_VERSION_REFUSE_TARGET_CBLOCK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "configured zstd_target_cblock_size requires runtime "
                      "libzstd 1.5.6 or newer (loaded %ui)",
                      (ngx_uint_t) runtime);
        return NGX_ERROR;
    }

    if (policy == NGX_HTTP_ZSTD_VERSION_REFUSE_NEGATIVE_LEVEL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "a configured negative zstd_comp_level requires "
                      "runtime libzstd 1.4.0 or newer (loaded %ui)",
                      (ngx_uint_t) runtime);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Free every cached context in the worker's slot ring at process exit.
 *
 * Without this the cache is a live allocation at shutdown, which LeakSanitizer
 * and Valgrind both report -- this tree gates on both, so a "harmless" one-off
 * worker-lifetime leak would be a red CI job, not a footnote.
 *
 * A slot may still be BUSY here: ngx_worker_process_exit() runs every module's
 * exit_process before it touches connections, and on the terminate path it
 * runs straight out of the event loop with requests in flight -- their pools
 * are not destroyed first, and on that path never are. Freeing a lent context
 * is nonetheless unobservable, and that, not "the borrower is already gone",
 * is why it is safe: the process exit()s immediately after these handlers, so
 * no borrower's pool cleanup -- hence no ngx_http_zstd_release_cctx() -- ever
 * runs again on the freed pointer. Anything that reintroduced an event-loop
 * turn after this point would invalidate that reasoning, not merely slow it.
 */
static void
ngx_http_zstd_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_ZSTD_CCTX_SLOTS; i++) {
        if (ngx_http_zstd_worker_cctx_slots[i].cctx != NULL) {
            ZSTD_freeCCtx(ngx_http_zstd_worker_cctx_slots[i].cctx);
            ngx_http_zstd_worker_cctx_slots[i].cctx = NULL;
        }

        ngx_http_zstd_worker_cctx_slots[i].busy = 0;
    }
}


static void
ngx_http_zstd_cleanup_dict(void *data)
{
    ZSTD_CDict  *dict = data;

    if (dict != NULL) {
        ZSTD_freeCDict(dict);
    }
}


/*
 * zstd_dcz_dict_file <path> — load one RFC 9842 dictionary. The file is
 * read and hashed here at config parse (nginx -t validates it), into
 * cf->pool so the raw bytes live exactly as long as the configuration
 * that references them. No CDict is built: the request path references
 * the bytes with ZSTD_CCtx_refPrefix(), which honors whatever
 * per-location parameters that request's CCtx carries — repeating the
 * trained-dict path's CDict-per-(level,window) merge matrix here would
 * buy latency only, and is deferred until profiling demands it.
 */
static char *
ngx_http_zstd_dcz_dict_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zstd_loc_conf_t *zlcf = conf;

    off_t                      fsize;
    size_t                     size;
    ngx_fd_t                   fd;
    ngx_str_t                 *value, path, bytes, hexstr;
    ngx_uint_t                 i, have_hash;
    u_char                     c, hi, lo;
    u_char                     hash[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    u_char                     supplied[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    u_char                     hex[2 * NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    ngx_file_info_t            info;
    ngx_http_zstd_dcz_dict_t  *dict, *dicts;
    ngx_http_zstd_main_conf_t *zmcf;
    ngx_flag_t                 strict, trust;

    (void) cmd;

    value = cf->args->elts;
    path = value[1];

    if (ngx_conf_full_name(cf->cycle, &path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Optional second argument: the dictionary's SHA-256 as 64 hex
     * characters. By default it is VERIFIED against the bytes actually
     * read below — a declaration of what the operator believes the
     * file to be, so a mismatch is a config error naming both values.
     * That default protects a pipeline whose config generation and
     * file placement are decoupled: "zstd_dcz_dict_file new.dict
     * <hash-of-old.dict>" would otherwise compress with new.dict while
     * advertising the old hash, and the client holding the advertised
     * dictionary cannot decode the body.
     *
     * Under "zstd_dcz_dict_trust_hashes on" the literal is instead
     * trusted verbatim as the negotiation key and the hashing pass is
     * skipped — the parse-time cost it removes is not the read (the
     * file lands in cf->pool either way) but the SHA-256 over it,
     * which at hundreds of dictionaries is essentially ALL of the
     * config-load CPU (see the flag's comment in the main conf for
     * the measurement). The opt-in states the trade: the operator's
     * pipeline, not this module, is then the authority on what the
     * bytes are.
     *
     * The literal's SYNTAX is validated before the file is opened
     * so a malformed literal is reported as such, not shadowed by file
     * errors — under either policy; trust changes what a well-formed
     * literal means, not what a malformed one does.
     */
    have_hash = (cf->args->nelts == 3);

    if (have_hash) {

        if (value[2].len != 2 * NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid dcz dictionary hash \"%V\": want %d "
                               "hex characters (the file's SHA-256)",
                               &value[2],
                               2 * NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < NGX_HTTP_ZSTD_SHA256_DIGEST_LEN; i++) {

            c = value[2].data[2 * i];
            hi = ngx_http_zstd_hex_nibble(c);

            c = value[2].data[2 * i + 1];
            lo = ngx_http_zstd_hex_nibble(c);

            if (hi == 0xff || lo == 0xff) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid dcz dictionary hash \"%V\": "
                                   "non-hex character", &value[2]);
                return NGX_CONF_ERROR;
            }

            supplied[i] = (u_char) ((hi << 4) | lo);
        }
    }

    if (zlcf->dcz_dicts == NGX_CONF_UNSET_PTR) {
        zlcf->dcz_dicts = ngx_array_create(cf->pool, 2,
                                           sizeof(ngx_http_zstd_dcz_dict_t));
        if (zlcf->dcz_dicts == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

    /*
     * dict_strict_path is read raw here (not the normalized 0/1 value
     * init_main_conf() later produces): this directive handler runs
     * during ngx_conf_parse(), strictly BEFORE init_main_conf, so if
     * "zstd_dict_strict_path on;" appears LATER in the same config
     * file, it has not been parsed yet and this read sees
     * NGX_CONF_UNSET (-1), not 1. Reading that as "off" is only safe
     * for THIS load -- it does NOT mean the operator declined strict
     * mode overall, only that this line hasn't been reached. A
     * subsequent "on" would mean this dictionary was loaded unchecked
     * despite the operator asking for strict mode -- confirmed live to
     * fail open: a world-writable dictionary loaded here with no error
     * when zstd_dict_strict_path on came after this directive. Record
     * that possibility now (once, keeping the first offending path for
     * the message) so init_main_conf() can reject the ordering outright
     * once the flag's FINAL value is known, rather than silently
     * accepting an unchecked load.
     */
    strict = (zmcf->dict_strict_path == 1);

    if (!strict && !zmcf->dcz_dict_loaded_before_strict_on) {
        zmcf->dcz_dict_loaded_before_strict_on = 1;
        zmcf->dcz_dict_loaded_before_strict_on_file = path;
    }

    /*
     * Raw read for the same reason as dict_strict_path above: a later
     * "zstd_dcz_dict_trust_hashes on;" has not been parsed yet when
     * this line loads, so a literal verified here would silently cost
     * the full hashing pass the operator asked to skip. Record the
     * possibility; init_main_conf() rejects the ordering if the flag's
     * final value turns out to be "on". Only a line WITH a literal is
     * affected -- unhashed lines are computed under either policy.
     */
    trust = (zmcf->dcz_dict_trust_hashes == 1);

    if (have_hash && !trust && !zmcf->dcz_dict_verified_before_trust_on) {
        zmcf->dcz_dict_verified_before_trust_on = 1;
        zmcf->dcz_dict_verified_before_trust_on_file = path;
    }

    fd = ngx_http_zstd_open_dict_file(cf, &path, strict, &info);
    if (fd == NGX_INVALID_FILE) {
        return NGX_CONF_ERROR;
    }

    /*
     * off_t comparison before the size_t narrowing: see the matching
     * note in ngx_http_zstd_merge_loc_conf(). A >4 GiB file on ILP32
     * would otherwise wrap under the cap.
     */
    fsize = ngx_file_size(&info);

    if (fsize == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "dcz dictionary \"%V\" is empty", &path);
        goto failed;
    }

    if (fsize > (off_t) NGX_HTTP_ZSTD_MAX_DICT_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "dcz dictionary \"%V\" too large: %O bytes "
                           "(limit: %d bytes)",
                           &path, fsize, NGX_HTTP_ZSTD_MAX_DICT_SIZE);
        goto failed;
    }

    size = (size_t) fsize;

    /*
     * Between the window cap (2^23) and the hard limit above the frame
     * stays well-formed — the RFC's client guarantee is a floor of
     * max(8 MB, 1.25 x dict), so an 8 MB window is inside it for any
     * dictionary size — but bytes beyond the window are out of the
     * matcher's reach and the far end of the dictionary silently stops
     * contributing. That is a ratio cliff, not an error: warn at config
     * load instead of letting the operator discover it in telemetry.
     */
    if (size > ((size_t) 1 << NGX_HTTP_ZSTD_DCZ_MAX_WINDOW_LOG)) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "dcz dictionary \"%V\" is %uz bytes, larger than "
                           "the 8 MB dcz compression window; bytes beyond "
                           "the window cannot be referenced during "
                           "compression and only shrink the ratio benefit",
                           &path, size);
    }

    /*
     * Build the entry in locals and push it only once the file has been
     * read in full. Pushing first left a half-initialised element (NULL
     * bytes.data, uninitialised hash) in zlcf->dcz_dicts on every error
     * path below -- unreachable today because NGX_CONF_ERROR aborts the
     * load before anything walks the array, but that is a non-local
     * safety argument and the next reader should not have to rebuild it.
     */
    bytes.len = size;
    bytes.data = ngx_palloc(cf->pool, size);
    if (bytes.data == NULL) {
        goto failed;
    }

    if (ngx_http_zstd_read_dict_file(cf, fd, &path, bytes.data, size)
        != NGX_OK)
    {
        goto failed;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &path);
        return NGX_CONF_ERROR;
    }

    if (have_hash && trust) {

        /*
         * zstd_dcz_dict_trust_hashes on: the operator opted out of
         * verification, so the literal IS the negotiation key and the
         * hashing pass is skipped -- along with its
         * $zstd_dcz_dicts_hashed increment, which is the observable
         * witness that the skip actually happened. The trade is the
         * documented one: a stale or mistyped literal is advertised
         * verbatim, and a client holding the advertised dictionary
         * receives responses it may fail to decode or that silently
         * decode wrong under a same-size stale raw dictionary.
         */
        ngx_memcpy(hash, supplied, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);

    } else {

        /*
         * Default: the negotiation key is the hash of the bytes this
         * load actually read. See the have_hash note above.
         */
#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
        if (!zmcf->dcz_evp_md_ctx_attempted) {
            ngx_http_zstd_init_evp_md_ctx(cf, zmcf);
        }
#endif
        ngx_http_zstd_dcz_dict_hash(bytes.data, size, hash,
                                    &zmcf->dcz_dicts_hashed,
                                    zmcf->dcz_evp_md_ctx);

        if (have_hash
            && ngx_memcmp(supplied, hash,
                          NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) != 0)
        {
            hexstr.data = hex;
            hexstr.len = ngx_hex_dump(hex, hash,
                                      NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) - hex;

            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dcz dictionary \"%V\" does not match the "
                               "supplied hash \"%V\": the file's SHA-256 is "
                               "\"%V\"",
                               &path, &value[2], &hexstr);

            return NGX_CONF_ERROR;
        }
    }

    /*
     * Two entries with the same hash make the negotiation lookup
     * ambiguous. For computed hashes that means identical content
     * under two paths — almost certainly a config mistake, e.g. a copy
     * that was meant to be a new version; under trust_hashes a
     * supplied literal is compared as declared, so this also catches
     * one literal pasted onto two lines. Fail loudly at load rather
     * than silently matching the first.
     */
    dicts = zlcf->dcz_dicts->elts;

    for (i = 0; i < zlcf->dcz_dicts->nelts; i++) {
        if (ngx_memcmp(dicts[i].hash, hash,
                       NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "dcz dictionary \"%V\" has the same hash "
                               "as \"%V\"", &path, &dicts[i].file);
            return NGX_CONF_ERROR;
        }
    }

    dict = ngx_array_push(zlcf->dcz_dicts);
    if (dict == NULL) {
        return NGX_CONF_ERROR;
    }

    dict->file = path;
    dict->bytes = bytes;
    ngx_memcpy(dict->hash, hash, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);

    {
        /*
         * Assemble the 40-byte dcz frame prefix once, here, instead of on
         * every request emit_dcz_header runs for this dictionary. Same
         * bytes as before: the zstd skippable-frame magic 0x184D2A5E with
         * a declared 32-byte content, then this dictionary's hash.
         */
        static const u_char  magic[8] = {
            0x5e, 0x2a, 0x4d, 0x18,     /* 0x184D2A5E, little-endian */
            0x20, 0x00, 0x00, 0x00      /* frame content size: 32 */
        };

        u_char  *p = dict->frame_header;

        p = ngx_cpymem(p, magic, sizeof(magic));
        ngx_memcpy(p, dict->hash, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
    }

    return NGX_CONF_OK;

failed:

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", &path);
    }

    return NGX_CONF_ERROR;
}


static char *
ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data)
{
    const ngx_int_t  *np = data;
    ngx_http_zstd_main_conf_t  *zmcf;

    (void)post;

    /*
     * Validate compression level range.
     * ZSTD supports both positive (1-22) and negative (-131072 to -1) levels.
     * - Positive levels: higher number = more compression
     * - Negative levels: faster speed, less compression
     * - 0: Use ZSTD default compression level (ZSTD_CLEVEL_DEFAULT)
     *
     * ZSTD_minCLevel() was introduced in zstd 1.4.0. On older libraries
     * (zstd < 1.4.0) negative levels are not supported; clamp to 1.
     */
#if ZSTD_VERSION_NUMBER >= 10400
    if (*np < (ngx_int_t) ZSTD_minCLevel() || *np > ZSTD_maxCLevel()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zstd compression level must be between %i and %i "
                           "(0 = default, negative = faster, positive = "
                           "slower/better)",
                           (ngx_int_t) ZSTD_minCLevel(), ZSTD_maxCLevel());
        return NGX_CONF_ERROR;
    }
#else
    if (*np < 1 || *np > ZSTD_maxCLevel()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zstd compression level must be between 1 and %i "
                           "(zstd < 1.4.0: negative levels not supported)",
                           ZSTD_maxCLevel());
        return NGX_CONF_ERROR;
    }
#endif

    if (*np < 0) {
        zmcf = ngx_http_conf_get_module_main_conf(cf,
                                                  ngx_http_zstd_filter_module);
        zmcf->any_negative_level = 1;
    }

    return NGX_CONF_OK;
}


/*
 * Shared INT_MAX bound check for the size/num post-handlers below. The
 * value is rejected if negative (these directives have no meaningful
 * negative setting) or above INT_MAX, since both are later passed to
 * libzstd through an (int) cast. `name` is the directive label for the
 * error message.
 */
static char *
ngx_http_zstd_int_max_bound(ngx_conf_t *cf, ngx_int_t value,
    const char *name)
{
    if (value < 0 || value > INT_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%s\" must be between 0 and %d",
                           name, INT_MAX);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zstd_check_size_int_max(ngx_conf_t *cf, void *post, void *data)
{
    ssize_t  *sp = data;
    char     *rc;
    ngx_http_zstd_main_conf_t  *zmcf;

    (void) post;

    rc = ngx_http_zstd_int_max_bound(cf, (ngx_int_t) *sp,
                                     "zstd_target_cblock_size");
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    if (*sp > 0) {
        zmcf = ngx_http_conf_get_module_main_conf(cf,
                                                  ngx_http_zstd_filter_module);
        zmcf->any_target_cblock_size = 1;
    }

    /*
     * ZSTD_c_targetCBlockSize first works in libzstd 1.5.6. On older
     * versions the apply-site at ngx_http_zstd_filter_init_cctx() is
     * version-gated out — meaning the directive is silently ignored at
     * runtime with no feedback to the operator. Warn loudly at config load
     * so the config is recognisable as a no-op rather than appearing to
     * "work" while having no effect. The directive is still accepted (a
     * hard reject would break configs that intentionally target newer
     * libzstd at runtime via library upgrades without rebuilding nginx).
     * Suppress the warning when the value is 0 (the unset default).
     *
     * Gate on ZSTD_VERSION_NUMBER, not #ifndef ZSTD_c_targetCBlockSize:
     * the symbol is an enum member, so #ifndef was always true and this
     * warning fired even on libzstd >= 1.5.6 where the directive does work.
     */
#if ZSTD_VERSION_NUMBER < 10506
    if (*sp > 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"zstd_target_cblock_size\" is set but the "
                           "module was built against libzstd without "
                           "ZSTD_c_targetCBlockSize support (requires "
                           "libzstd >= 1.5.6); the directive will have "
                           "no effect at runtime");
    }
#else
    /*
     * On a library that supports the parameter, validate the configured
     * value against libzstd's own accepted range now, at config load. Once
     * C1 made the runtime apply path live, an out-of-range value would
     * otherwise pass nginx -t and then fail ZSTD_CCtx_setParameter() for
     * every request in the location (a 500 storm). 0 stays "unset". See C3.
     */
    if (*sp > 0) {
        ZSTD_bounds  b = ZSTD_cParam_getBounds(ZSTD_c_targetCBlockSize);

        if (ZSTD_isError(b.error)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_cParam_getBounds(targetCBlockSize) "
                               "failed: %s", ZSTD_getErrorName(b.error));
            return NGX_CONF_ERROR;
        }

        if ((ngx_int_t) *sp < b.lowerBound || (ngx_int_t) *sp > b.upperBound) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"zstd_target_cblock_size\" must be 0 "
                               "(default) or between %d and %d",
                               b.lowerBound, b.upperBound);
            return NGX_CONF_ERROR;
        }
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_zstd_check_num_int_max(ngx_conf_t *cf, void *post, void *data)
{
    ngx_int_t  *np = data;
    char       *rc;

    (void) post;

    rc = ngx_http_zstd_int_max_bound(cf, *np, "zstd_window_log");
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /*
     * 0 means "unset" (keep zstd's level-derived default). Any other value
     * is passed straight to ZSTD_c_windowLog. Ask the linked library for the
     * actual accepted range with ZSTD_cParam_getBounds() — a stable-API call
     * (no ZSTD_STATIC_LINKING_ONLY needed) — instead of inlining hard-coded
     * constants that can drift from the library. libzstd would otherwise
     * reject an out-of-range value per-request (a 500 on every response for
     * this location); catching it at config load turns that into a clear
     * startup error instead. See C3.
     */
    if (*np != 0) {
        ZSTD_bounds  b = ZSTD_cParam_getBounds(ZSTD_c_windowLog);

        if (ZSTD_isError(b.error)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ZSTD_cParam_getBounds(windowLog) failed: %s",
                               ZSTD_getErrorName(b.error));
            return NGX_CONF_ERROR;
        }

        if (*np < b.lowerBound || *np > b.upperBound) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "\"zstd_window_log\" must be 0 (default) or "
                               "between %d and %d", b.lowerBound, b.upperBound);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zstd_set_num_slot_with_negatives(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t        *np;
    ngx_str_t        *value;


    np = (ngx_int_t *) (p + cmd->offset);

    /*
     * NGX_HTTP_ZSTD_LEVEL_UNSET, not NGX_CONF_UNSET: this slot serves
     * only zstd_comp_level, whose unset marker is out of band precisely
     * because NGX_CONF_UNSET (-1) is a valid level. Testing the shared
     * sentinel here let "zstd_comp_level -1; zstd_comp_level 5;" through
     * as if the first line had never been parsed.
     */
    if (*np != NGX_HTTP_ZSTD_LEVEL_UNSET) {
        return (char *) "is duplicate";
    }

    value = cf->args->elts;

    if (*(value[1].data) == '-') {
        /* Parse ignoring the leading '-' character */
        *np = ngx_atoi(value[1].data + 1, value[1].len - 1);

        /* NGX_ERROR is -1 so we need to check for that before making the
         * parsed result negative */
        if (*np == NGX_ERROR) {
            return (char *) "invalid number";
        }

        *np = -*np;
    } else {
        *np = ngx_atoi(value[1].data, value[1].len);

        if (*np == NGX_ERROR) {
            return (char *) "invalid number";
        }
    }

    if (cmd->post) {
        ngx_conf_post_t  *post = cmd->post;

        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}


/*
 * Aggregate memory bound for "zstd_buffers number size" and its inherited
 * value.
 *
 * ngx_conf_set_bufs_slot() (nginx core) parses each of the two arguments
 * independently and rejects only a parse error or a zero -- it never looks
 * at the product. ngx_conf_merge_bufs_value() (invoked from
 * ngx_http_zstd_merge_loc_conf()) then either keeps an explicit value,
 * inherits the parent's, or applies this module's own default
 * (2 x ZSTD_CStreamOutSize()); none of those three paths re-validates the
 * pair either. A typo ("zstd_buffers 100000 100000;" instead of
 * "100 100k;") or an inherited value from an outer block can therefore
 * request an overflowing or merely enormous per-response pool that nginx
 * happily commits per concurrent response -- this directive sizes the
 * OUTPUT chain nginx allocates from ngx_http_zstd_filter_module's own
 * ngx_http_zstd_bufs_t path (see the merge site), separate from and
 * additive with the per-request CCtx working set the
 * "zstd_max_cctx_memory" advisory above already covers.
 *
 * Three tiers on the representable (non-overflowing) product, in
 * ascending severity:
 *
 *   <= NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES (8 MB)   silent. This is the
 *       ordinary range: nginx's own "zstd_buffers 32 4k" default (128 KB)
 *       and this module's own 2 x CStreamOutSize() default (~256 KB at
 *       level 6) both land far under it.
 *
 *   >  NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES,
 *   <= NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES (256 MB)  [warn]. Large but a
 *       config that loads today must keep loading -- same non-breaking
 *       posture as the zstd_max_cctx_memory advisory.
 *
 *   >  NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES            [emerg], refused
 *       UNLESS "zstd_buffers_unsafe on;" is also set. Unlike the advisory
 *       tier, this one is NOT "operator typed a big number and can live
 *       with the log line" -- number and size are two integers the
 *       operator wrote out literally (unlike the CCtx estimate, which
 *       depends on libzstd internals the operator never sees), so at
 *       this magnitude a refusal-by-default is the safe reading of "the
 *       operator probably made a mistake", with an explicit opt-out for
 *       the rare deployment that means it. 256 MB is two hundred times
 *       nginx's own default and comfortably past any legitimate output
 *       buffer size; a real deployment tuning zstd_buffers for throughput
 *       does so in the single-digit MB range, not hundreds.
 *
 * Overflow is refused unconditionally at every tier -- there is no
 * representable size for which "the operator meant this", so no
 * acknowledgement spelling exists for it.
 *
 * The warning/refusal states the total is PER RESPONSE and points at the
 * CCtx section so an operator sizing worker RSS adds the two: this
 * directive's total plus the up-to-NGX_HTTP_ZSTD_CCTX_SLOTS-times CCtx
 * figure that "zstd_max_cctx_memory" (undocumented) or its advisory
 * (documented above) reports.
 */
#ifndef NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES
#define NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES  (8 * 1024 * 1024)
#endif

#ifndef NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES
#define NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES  (256 * 1024 * 1024)
#endif


/*
 * Shared by the parse-time slot (explicit "zstd_buffers") and the
 * post-merge check (inherited or defaulted value): division-based
 * overflow pre-check, then -- when "advise" is set -- the
 * advisory/hard-cap tiers on the representable product. "ctx" names
 * which of the two callers is reporting so the operator can tell an
 * explicit typo from an inherited value without re-deriving it
 * themselves. "unsafe" is the merged conf->bufs_unsafe flag; it is only
 * consulted when the hard-cap tier fires.
 *
 * The overflow check always runs (both callers pass advise or not, but
 * overflow is unconditional either way, with no acknowledgement
 * spelling); the advisory/cap tiers are evaluated only from the
 * merge-time caller ("advise" true), never from the parse-time slot.
 * Every value ends up merged exactly once per location -- the merge
 * site is what conf->bufs is actually read from at request time -- so
 * gating those tiers there is what keeps a single explicit
 * "zstd_buffers" from being reported twice (once at parse, again at
 * merge) while still failing an overflowing product at the earliest
 * possible point.
 */
static char *
ngx_http_zstd_check_bufs_product(ngx_conf_t *cf, const ngx_bufs_t *bufs,
    ngx_flag_t unsafe, const char *ctx, ngx_flag_t advise)
{
    size_t  total;

    if (bufs->num <= 0 || bufs->size == 0) {
        /* Neither ngx_conf_set_bufs_slot() nor the module's own default
         * can produce this; defend anyway rather than assume. */
        return NGX_CONF_OK;
    }

    /*
     * Division-based pre-check, not "num * size < num": bufs->num is a
     * signed ngx_int_t, so a post-hoc "a * b < a" comparison on the
     * wrapped product is itself operating on a signed overflow, which is
     * undefined behaviour rather than merely wrong. Comparing against
     * NGX_MAX_SIZE_T_VALUE / size first never multiplies past the type's
     * range at all.
     */
    if ((size_t) bufs->num > NGX_MAX_SIZE_T_VALUE / bufs->size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_buffers\" (%s) requests %i buffers of "
                           "%uz bytes each; that product overflows the "
                           "platform's size_t and cannot be a config any "
                           "operator meant to write",
                           ctx, bufs->num, bufs->size);
        return NGX_CONF_ERROR;
    }

    if (!advise) {
        return NGX_CONF_OK;
    }

    total = (size_t) bufs->num * bufs->size;

    if (total > NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES) {
        if (unsafe) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "\"zstd_buffers\" (%s) requests %i x %uz "
                               "bytes = ~%uz bytes of output-chain memory "
                               "PER RESPONSE, above the %d MB hard cap; "
                               "accepted because \"zstd_buffers_unsafe "
                               "on;\" acknowledges it. That total is on "
                               "top of the per-request compressor (CCtx) "
                               "working set -- see the "
                               "\"zstd_max_cctx_memory\" advisory above "
                               "-- and both are multiplied by concurrent "
                               "responses under load",
                               ctx, bufs->num, bufs->size, total,
                               (int) (NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES
                                      / (1024 * 1024)));
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zstd_buffers\" (%s) requests %i x %uz bytes "
                           "= ~%uz bytes of output-chain memory PER "
                           "RESPONSE, above the %d MB hard cap -- that is "
                           "on top of the per-request compressor (CCtx) "
                           "working set (see the \"zstd_max_cctx_memory\" "
                           "advisory above) and both are multiplied by "
                           "concurrent responses under load. Lower "
                           "\"zstd_buffers\", or set "
                           "\"zstd_buffers_unsafe on;\" to acknowledge "
                           "this total is intentional",
                           ctx, bufs->num, bufs->size, total,
                           (int) (NGX_HTTP_ZSTD_BUFS_HARD_CAP_BYTES
                                  / (1024 * 1024)));
        return NGX_CONF_ERROR;
    }

    if (total > NGX_HTTP_ZSTD_BUFS_ADVISORY_BYTES) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"zstd_buffers\" (%s) requests %i x %uz bytes "
                           "= ~%uz bytes of output-chain memory PER "
                           "RESPONSE; that is on top of the per-request "
                           "compressor (CCtx) working set -- see the "
                           "\"zstd_max_cctx_memory\" advisory above for "
                           "that figure -- and both are multiplied by "
                           "concurrent responses under load",
                           ctx, bufs->num, bufs->size, total);
    }

    return NGX_CONF_OK;
}


/*
 * Validate value as a single RFC 9110 field-name token. Per RFC 9110 §5.1:
 *   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-"
 *         / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 * Reject commas and semicolons (list/parameter separators) and quotes
 * (not tchar; never part of a token). Accept all other tchar including
 * '*' in non-solitary positions (e.g., X-Foo*Bar is a valid token).
 *
 * Returns NULL when value is a valid token, or the exact error string to
 * return from the directive handler otherwise.
 */
static const char *
ngx_http_zstd_validate_field_name_token(const ngx_str_t *value)
{
    u_char  *p, *end;

    for (p = value->data, end = value->data + value->len; p < end; p++) {
        u_char  c = *p;

        /* List/parameter separators: reject to prevent ambiguous Vary. */
        if (c == ',' || c == ';') {
            return "invalid value: comma or semicolon (not a token)";
        }

        /* Quoted string: DQUOTE is never part of a token. */
        if (c == '"') {
            return "invalid value: quoted string (not a token)";
        }

        /* tchar set per RFC 9110 §5.1. Accept all, including '*' in
         * non-solitary positions (e.g., X-Foo*Bar is valid). */
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9')
              || c == '!' || c == '#' || c == '$' || c == '%'
              || c == '&' || c == '\'' || c == '*' || c == '+'
              || c == '-' || c == '.' || c == '^' || c == '_'
              || c == '`' || c == '|' || c == '~'))
        {
            return "invalid value: not a valid field-name token "
                   "(RFC 9110)";
        }
    }

    return NULL;
}


/*
 * Custom setter for zstd_bypass_vary directive. Validates that the value is
 * exactly ONE RFC 9110 field-name token (case-preserving), and rejects:
 *   - Bare wildcard "*", which disables shared caching
 *   - Comma or semicolon (list/parameter separators)
 *   - Quoted strings (DQUOTE), which are never part of a token
 *   - Any non-tchar byte
 *
 * Per RFC 9110 §5.1, tchar includes: ! # $ % & ' * + - . ^ _ ` | ~
 *   and DIGIT / ALPHA.
 *
 * Valid examples: "Accept-Encoding", "X-My-Header", "content-type"
 * Invalid: "*" (alone), "Accept-Encoding, Custom", "Accept-Encoding;q=1"
 */
static char *
ngx_http_zstd_set_bypass_vary(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zstd_loc_conf_t  *zlcf = conf;
    ngx_str_t                 *value;
    const char                *err;

    value = cf->args->elts;

    /* Check for duplicate within the same block: .data != NULL detects
     * parse-time duplicates (directive appearing twice in same {}). Each
     * block starts zero-initialized from create_loc_conf (ngx_pcalloc), so
     * .data is NULL until we set it. Inheritance from parent blocks happens
     * later via ngx_conf_merge_str_value after parsing, so child blocks can
     * override parent values without error — normal nginx semantics. */
    if (zlcf->bypass_vary.data != NULL) {
        return (char *) "is duplicate";
    }

    /* ngx_conf_set_str_slot would just dup this; validate first. */
    value = &value[1];  /* Skip directive name, take the argument */

    if (value->len == 0) {
        return (char *) "empty value";
    }

    /* Bare wildcard is never valid: it disables shared caching and matches
     * any Vary field, defeating the purpose of naming a specific header. */
    if (value->len == 1 && value->data[0] == '*') {
        return (char *)
                   "invalid value: bare wildcard '*' disables shared caching";
    }

    err = ngx_http_zstd_validate_field_name_token(value);
    if (err != NULL) {
        return (char *) err;
    }

    /* Valid token: store it. ngx_conf_set_str_slot behavior (dup into
     * pool). */
    zlcf->bypass_vary.len = value->len;
    zlcf->bypass_vary.data = ngx_pstrdup(cf->pool, value);

    if (zlcf->bypass_vary.data == NULL) {
        return (char *) "allocation failed";
    }

    return NGX_CONF_OK;
}


/*
 * Wraps the stock ngx_conf_set_flag_slot() for the "zstd" directive so
 * every "zstd on;"/"zstd <var>;" parsed ANYWHERE in the config — main,
 * srv, loc, or an NGX_HTTP_LIF_CONF conf synthesized for a rewrite-phase
 * "if" block — latches ngx_http_zstd_main_conf_t.any_enabled. See the
 * field's own comment for why parse time (not the location-conf merge
 * walk) is used and why a false positive here is harmless while a false
 * negative is not: an "if" loc conf is not provably visited by the
 * normal merge walk, so this is the deliberately conservative option.
 *
 * Only the literal "off" clears the possibility; every other value this
 * directive can legally take at parse time — "on", or a variable/complex
 * value from ngx_conf_set_flag_slot's own value table — must be assumed
 * enabling, because ngx_conf_set_flag_slot() rejects anything that is
 * not exactly "on"/"off" before we ever see it, and "if(cond) { zstd on;
 * } if(!cond) { zstd off; }" plus nginx's "if" mechanics can still make
 * the on-branch conf reachable regardless of what a sibling loc parses.
 */
static char *
ngx_http_zstd_set_enable_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    char                       *rc;
    ngx_http_zstd_main_conf_t  *zmcf;

    rc = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    value = cf->args->elts;

    /* value[1] is the directive's single argument: "on" or "off" (the
     * only two ngx_conf_set_flag_slot accepts — anything else already
     * made it return an error string above). */
    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        return NGX_CONF_OK;
    }

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);
    zmcf->any_enabled = 1;

    return NGX_CONF_OK;
}


/*
 * Wraps nginx's own ngx_conf_set_bufs_slot() rather than reimplementing
 * argument parsing: nginx's parse/zero rejection and its exact error text
 * for those cases are preserved verbatim, and this wrapper only adds the
 * overflow check on the ngx_bufs_t that parse produced -- fast, hard
 * feedback on an unrepresentable explicit value at the earliest possible
 * point. It deliberately does NOT run the advisory/hard-cap tiers
 * (advise=0): the post-merge check in ngx_http_zstd_merge_loc_conf()
 * is the single owner of those, because it is the only point that also
 * covers a value this location never wrote itself but inherited from an
 * outer block, or the module's own computed default -- neither of which
 * runs through this slot handler at all. It is also the only point where
 * conf->bufs_unsafe is guaranteed to already hold its final, merged
 * value: "zstd_buffers_unsafe" can appear before OR after "zstd_buffers"
 * in the same block, or at an outer level entirely, and this slot fires
 * the moment "zstd_buffers" is parsed -- reading bufs_unsafe here could
 * see it still unset. Running the hard-cap tier here too would also
 * double-report it for the common case of an explicit large value that
 * survives to the merge unchanged.
 */
static char *
ngx_http_zstd_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char        *p = conf;
    char        *rc;
    ngx_bufs_t  *bufs;

    rc = ngx_conf_set_bufs_slot(cf, cmd, conf);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    bufs = (ngx_bufs_t *) (p + cmd->offset);

    return ngx_http_zstd_check_bufs_product(cf, bufs, 0,
                                             "explicit directive", 0);
}
