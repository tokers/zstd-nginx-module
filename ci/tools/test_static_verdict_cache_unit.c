/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit fixture for the static module's probe-verdict cache
 * (ngx_http_zstd_static_cached_verdict() /
 *  ngx_http_zstd_static_remember()).
 *
 * Both helpers are `static` inside src/ngx_http_zstd_static_module.c, so
 * test_static_verdict_cache_unit.sh extracts them verbatim by line range
 * -- the repo's established precedent, see test_static_pread_unit.sh --
 * and this file #includes the generated slice, so the test always
 * exercises the SHIPPED lookup and insert rather than a hand-copied
 * duplicate that would keep passing while the real code regressed.
 *
 * WHY A UNIT FIXTURE AND NOT A CONFIG FIXTURE. What must be pinned is the
 * cache's IDENTITY KEY and its BOUND. A live-nginx fixture can show a
 * repeat request is served, but it cannot distinguish "the cache hit" from
 * "the probe ran again and agreed", and it cannot vary st_ino independently
 * of mtime and size at all. Here every field of the key is set directly,
 * so dropping any one of them from the comparison is observable as a
 * specific named check going red -- which is exactly the mutation the
 * script's negative control runs.
 *
 * THE POSITIVE VERDICT IS THE DANGEROUS ONE. A stale BAD verdict costs a
 * fallback to identity; a stale GOOD verdict serves a sidecar that was
 * never validated. So the invalidation checks below (mtime, size, uniq,
 * path) are all stated against GOOD entries.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

/* --- minimal nginx type/macro surface the extracted functions need --- */

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;
typedef uint64_t       ngx_file_uniq_t;

#define NGX_MAX_PATH   4096

typedef struct { size_t len; u_char *data; } ngx_str_t;

/*
 * Only the four fields the key reads. Keeping this struct minimal is
 * deliberate: if the shipped lookup ever starts consulting another
 * ngx_open_file_info_t member, this fixture fails to COMPILE rather than
 * silently testing a narrower key than production uses.
 */
typedef struct {
    ngx_file_uniq_t  uniq;
    time_t           mtime;
    off_t            size;
} ngx_open_file_info_t;

#define ngx_memcmp(a, b, n)  memcmp((const char *) (a), (const char *) (b), n)
#define ngx_memcpy(a, b, n)  memcpy(a, b, n)

/* The extraction carries the declarations, the table and both helpers. */
#if defined(TEST_EXPIRED_ENTRY_MUTANT)
#include "generated_verdict_cache_expired_mutant.inc"
#elif defined(TEST_PATH_COMPARE_MUTANT)
#include "generated_verdict_cache_path_mutant.inc"
#else
#include "generated_verdict_cache.inc"
#endif

/* --- harness ---------------------------------------------------------- */

static int  failures;
static time_t now = 1700000100;
static time_t good_valid = 60;

static ngx_uint_t
test_cached_verdict(ngx_str_t *path, ngx_open_file_info_t *of)
{
    return ngx_http_zstd_static_cached_verdict(path, of, now, good_valid);
}

static void
test_remember(ngx_str_t *path, ngx_open_file_info_t *of, ngx_uint_t verdict)
{
    ngx_http_zstd_static_remember(path, of, verdict, now, good_valid);
}

static void
check(int ok, const char *name)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", name);
    if (!ok) {
        failures++;
    }
}

static ngx_str_t
mkpath(const char *s)
{
    ngx_str_t  p;

    p.data = (u_char *) s;
    p.len = strlen(s);

    return p;
}

static void
reset_cache(void)
{
    memset(ngx_http_zstd_static_verdict_cache, 0,
           sizeof(ngx_http_zstd_static_verdict_cache));
    ngx_http_zstd_static_verdict_cache_next = 0;
    ngx_http_zstd_static_verdict_cache_count = 0;
}

int
main(void)
{
    ngx_str_t             p, other;
    ngx_open_file_info_t  of, mutated;
    ngx_uint_t            i, hits;
    char                  buf[64];

    p = mkpath("/srv/www/app.js.zst");
    other = mkpath("/srv/www/foo.js.zst");

    of.uniq = 0x1122334455667788ULL;
    of.mtime = 1700000000;
    of.size = 8206;

    /* --- a cold cache must not answer -------------------------------- */

    reset_cache();
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a cold cache returns VERDICT_NONE, so the probe runs");

    /* --- a GOOD verdict is returned verbatim on a hit ----------------- */

    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
          "a hit on an unchanged file returns the same GOOD verdict");

    /*
     * A hit must be IDEMPOTENT: reading it twice must not consume, rotate
     * or downgrade the entry. A lookup that mutated state would make the
     * second request on a hot file re-probe.
     */
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
          "a second lookup returns GOOD too -- the lookup does not consume");

    now += 59;
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
          "a GOOD verdict remains valid just before open_file_cache_valid");
    now++;
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a GOOD verdict expires at open_file_cache_valid");
    check(ngx_http_zstd_static_verdict_cache_count == 1,
          "expiry does not shrink the populated-slot high-water mark");

    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
          "a fresh verdict is visible after an expired duplicate");

    reset_cache();
    now = 1700000100;
    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    now--;
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a clock rollback invalidates a future-dated GOOD verdict");
    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
          "a fresh verdict is visible after clock-rollback invalidation");
    now = 1700000100;

    reset_cache();
    good_valid = 0;
    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a GOOD verdict is not cached when open_file_cache is disabled");
    check(ngx_http_zstd_static_verdict_cache_next == 0,
          "disabled positive caching consumes no cache slot");
    check(ngx_http_zstd_static_verdict_cache_count == 0,
          "disabled positive caching leaves the high-water mark empty");
    good_valid = 60;

    /* --- BAD and GOOD do not alias ----------------------------------- */

    reset_cache();
    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_BAD);
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_BAD,
          "a BAD verdict comes back as BAD, not as GOOD");
    good_valid = 0;
    now += 1000;
    check(test_cached_verdict(&p, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_BAD,
          "open_file_cache coupling does not expire established BAD verdicts");
    good_valid = 60;
    now = 1700000100;

    /* --- every key field invalidates a GOOD verdict -------------------
     *
     * These four are the whole safety argument for caching a POSITIVE
     * verdict: a sidecar that was regenerated must not inherit the old
     * file's "this frame is valid" answer.
     */

    reset_cache();
    test_remember(&p, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    mutated = of;
    mutated.mtime = of.mtime + 1;
    check(test_cached_verdict(&p, &mutated)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a changed mtime invalidates the cached GOOD verdict");

    mutated = of;
    mutated.size = of.size + 1;
    check(test_cached_verdict(&p, &mutated)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a changed size invalidates the cached GOOD verdict");

    mutated = of;
    mutated.uniq = of.uniq ^ 1;
    check(test_cached_verdict(&p, &mutated)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "a changed uniq (inode) invalidates the cached GOOD verdict");

    check(test_cached_verdict(&other, &of)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "an equal-length different path does not reuse a GOOD verdict");

    /*
     * Length, not just prefix. A comparison that memcmp'd only the
     * shorter length would let a path that is a strict prefix of a cached
     * one inherit its verdict.
     */
    {
        ngx_str_t  prefix = mkpath("/srv/www/app.js");

        check(test_cached_verdict(&prefix, &of)
                  == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
              "a path that is a prefix of a cached one does not hit");
    }

    /* --- the bound holds: more distinct files than slots -------------- */

    reset_cache();

    for (i = 0; i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS * 3; i++) {
        ngx_str_t             q;
        ngx_open_file_info_t  qof;

        snprintf(buf, sizeof(buf), "/srv/www/f%u.zst", (unsigned) i);
        q = mkpath(buf);

        qof.uniq = 0x1000 + i;
        qof.mtime = 1700000000;
        qof.size = 4096 + (off_t) i;

        test_remember(&q, &qof, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);
    }

    /*
     * Fixed storage, round-robin eviction: after 3 * SLOTS inserts the
     * table still holds exactly SLOTS entries and the cursor is back at
     * 0. A table that grew, or an insert that walked off the end, is a
     * worker-lifetime defect this check exists to catch.
     */
    hits = 0;
    for (i = 0; i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS; i++) {
        if (ngx_http_zstd_static_verdict_cache[i].valid
            != NGX_HTTP_ZSTD_STATIC_VERDICT_NONE)
        {
            hits++;
        }
    }

    check(hits == NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS,
          "3x SLOTS inserts fill exactly SLOTS entries -- the table is bounded");
    check(ngx_http_zstd_static_verdict_cache_next == 0,
          "the round-robin cursor wraps back to 0, it does not run past the end");
    check(ngx_http_zstd_static_verdict_cache_count
              == NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS,
          "the populated-slot high-water mark is capped at SLOTS");

    /*
     * The LAST SLOTS files inserted are the ones retained; the earliest
     * are gone. This is what makes the bound an eviction policy rather
     * than a silent write-off-the-end.
     */
    {
        ngx_str_t             q;
        ngx_open_file_info_t  qof;
        unsigned              last;

        last = NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS * 3 - 1;
        snprintf(buf, sizeof(buf), "/srv/www/f%u.zst", last);
        q = mkpath(buf);
        qof.uniq = 0x1000 + last;
        qof.mtime = 1700000000;
        qof.size = 4096 + (off_t) last;

        check(test_cached_verdict(&q, &qof)
                  == NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD,
              "the most recently inserted file is still cached after wraparound");

        snprintf(buf, sizeof(buf), "/srv/www/f0.zst");
        q = mkpath(buf);
        qof.uniq = 0x1000;
        qof.size = 4096;

        check(test_cached_verdict(&q, &qof)
                  == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
              "the earliest inserted file was evicted, not retained forever");
    }

    /* --- an overlong path is never stored and never hits -------------- */

    reset_cache();
    {
        static char  longpath[NGX_MAX_PATH + 16];
        ngx_str_t    q;

        memset(longpath, 'a', sizeof(longpath) - 1);
        longpath[sizeof(longpath) - 1] = '\0';
        q = mkpath(longpath);

        test_remember(&q, &of, NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD);

        check(ngx_http_zstd_static_verdict_cache[0].valid
                  == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
              "a path at or above NGX_MAX_PATH is not stored (no overflow)");
        check(test_cached_verdict(&q, &of)
                  == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
              "an overlong path always misses, retaining the uncached path");
    }

    if (failures) {
        printf("\n%d check(s) FAILED\n", failures);
        return 1;
    }

    printf("\nall verdict-cache checks passed\n");
    return 0;
}
