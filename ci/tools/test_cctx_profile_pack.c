/*
 * Unit oracle for the CCtx profile 64-bit key.
 *
 * The packer and unpacker (and their layout #defines) are EXTRACTED VERBATIM
 * from src/ngx_http_zstd_filter_module.c by test_cctx_profile_pack.sh into
 * generated_profile_pack.inc -- this file never re-implements the arithmetic,
 * so it cannot quietly agree with a stale copy of itself.
 *
 * What the row demands, and therefore what is asserted here:
 *
 *   1. REVERSIBLE   -- unpack(pack(t)) == t for every in-domain tuple t.
 *   2. COLLISION-FREE -- distinct tuples never produce the same key. Proved
 *      here without an O(n^2) compare and without a hash set: because (1)
 *      holds for every tuple in the swept domain, pack is injective on that
 *      domain by construction (a left inverse exists), so a collision is
 *      impossible. The sweep additionally checks the reserved high bits are
 *      clear and that no in-domain key ever equals the INVALID sentinel,
 *      which is the only way a real profile could be confused with a refusal.
 *   3. FAIL-CLOSED  -- out-of-domain inputs return NGX_HTTP_ZSTD_PROFILE_INVALID
 *      rather than being masked into a valid-looking key. Masking is what
 *      would let two different compression settings share one CCtx, which
 *      changes bytes on the wire with no diagnostic.
 *
 * Domain swept: the full range the config layer can deliver.
 *   level      -131072 .. 22   (ZSTD_minCLevel()..ZSTD_maxCLevel();
 *                               negative values are libzstd's fast levels)
 *   window_log 0 .. 63         (0 = "unset"; the accepted maximum is a
 *                               libzstd bound -- 31 on 64-bit today -- so the
 *                               field is 6 bits wide and the WHOLE field is
 *                               swept, not just today's library limit)
 *   long_mode  0 .. 1
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Minimal nginx-typedef shim: the extracted code uses these two names. */
typedef long  ngx_int_t;
typedef long  ngx_flag_t;

#include "generated_profile_pack.inc"

#define LEVEL_MIN  (-131072)
#define LEVEL_MAX  (22)
#define WLOG_MAX   ((ngx_int_t) NGX_HTTP_ZSTD_PROFILE_WLOG_MAX)

int
main(void)
{
    ngx_int_t   level, window_log, long_mode;
    ngx_int_t   u_level, u_window_log;
    ngx_flag_t  u_long;
    uint64_t    key;
    long long   swept = 0;
    long long   revfail = 0;
    long long   sentinel_clash = 0;
    long long   reserved_dirty = 0;
    int         rc = 0;

    for (level = LEVEL_MIN; level <= LEVEL_MAX; level++) {
        for (window_log = 0; window_log <= WLOG_MAX; window_log++) {
            for (long_mode = 0; long_mode <= 1; long_mode++) {

                key = ngx_http_zstd_profile_pack(level,
                                                 (ngx_flag_t) long_mode,
                                                 window_log);
                swept++;

                if (key == NGX_HTTP_ZSTD_PROFILE_INVALID) {
                    sentinel_clash++;
                    continue;
                }

                /* Nothing above the long_mode bit may ever be set. */
                if ((key >> (NGX_HTTP_ZSTD_PROFILE_LONG_SHIFT + 1)) != 0) {
                    reserved_dirty++;
                }

                ngx_http_zstd_profile_unpack(key, &u_level, &u_long,
                                             &u_window_log);

                if (u_level != level
                    || u_window_log != window_log
                    || (ngx_int_t) u_long != long_mode)
                {
                    if (revfail < 5) {
                        fprintf(stderr,
                                "REVERSIBILITY: (%ld,%ld,%ld) -> key %llu -> "
                                "(%ld,%ld,%ld)\n",
                                (long) level, (long) long_mode,
                                (long) window_log,
                                (unsigned long long) key,
                                (long) u_level, (long) u_long,
                                (long) u_window_log);
                    }
                    revfail++;
                }
            }
        }
    }

    printf("swept %lld in-domain tuples "
           "(level %d..%d, window_log 0..%ld, long_mode 0..1)\n",
           swept, LEVEL_MIN, LEVEL_MAX, (long) WLOG_MAX);
    printf("  reversibility failures : %lld\n", revfail);
    printf("  INVALID-sentinel clashes: %lld\n", sentinel_clash);
    printf("  reserved bits set       : %lld\n", reserved_dirty);

    if (revfail || sentinel_clash || reserved_dirty) {
        rc = 1;
    }

    /*
     * Injectivity follows from reversibility over the swept domain: unpack is
     * a left inverse of pack there, so pack cannot map two distinct tuples to
     * one key. State it rather than implying it.
     */
    if (!rc) {
        printf("  => pack is injective over the swept domain "
               "(left inverse exists for every tuple): 0 collisions\n");
    }

    /* --- fail-closed checks: out-of-domain must REFUSE, not mask. --- */
    {
        struct { ngx_int_t lvl, wlog; const char *what; } bad[] = {
            { LEVEL_MIN - 1,   0, "level below bias" },
            { 1 << 20,         0, "level above field" },
            { 0,  WLOG_MAX + 1,  "window_log above field" },
            { 0,            -1,  "window_log negative" },
        };
        size_t i;
        uint64_t key1, key2;

        for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            key = ngx_http_zstd_profile_pack(bad[i].lvl, 0, bad[i].wlog);
            if (key != NGX_HTTP_ZSTD_PROFILE_INVALID) {
                fprintf(stderr,
                        "FAIL-CLOSED: %s (level=%ld window_log=%ld) returned "
                        "%llu, expected INVALID\n",
                        bad[i].what, (long) bad[i].lvl, (long) bad[i].wlog,
                        (unsigned long long) key);
                rc = 1;
            }
        }
        if (!rc) {
            printf("  => all %zu out-of-domain inputs refused "
                   "(no silent masking)\n", sizeof(bad) / sizeof(bad[0]));
        }

        /*
         * Assert that two distinct out-of-domain profiles collapse to the
         * SAME sentinel: this is the aliasing the cache guard must detect.
         * Both should pack to INVALID, proving they compare equal, which is
         * why acquire_cctx must refuse to borrow or seed on INVALID.
         */
        key1 = ngx_http_zstd_profile_pack(LEVEL_MIN - 1, 0, 0);
        key2 = ngx_http_zstd_profile_pack(0, 0, WLOG_MAX + 1);
        if (key1 != NGX_HTTP_ZSTD_PROFILE_INVALID
            || key2 != NGX_HTTP_ZSTD_PROFILE_INVALID
            || key1 != key2)
        {
            fprintf(stderr,
                    "SENTINEL-ALIASING: two distinct out-of-domain profiles "
                    "did not both collapse to INVALID: "
                    "key1=%llu key2=%llu INVALID=%llu\n",
                    (unsigned long long) key1,
                    (unsigned long long) key2,
                    (unsigned long long) NGX_HTTP_ZSTD_PROFILE_INVALID);
            rc = 1;
        } else {
            printf("  => distinct out-of-domain profiles alias to INVALID "
                   "(cache guard must refuse)\n");
        }
    }

    if (rc) {
        printf("FAIL\n");
        return 1;
    }

    printf("PASS\n");
    return 0;
}
