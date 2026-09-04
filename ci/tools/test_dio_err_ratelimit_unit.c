/*
 * Unit fixture for ngx_http_zstd_static_dio_err_should_log() — A33-F4(b),
 * PR #314 review: the directio hard-error probe arm in
 * ngx_http_zstd_static_module.c logs NGX_LOG_ERR on every request once a
 * sidecar's directio_alignment mismatches the device, 1:1 with request
 * volume. The fix rate-limits the LOG only; *malformed stays 0 on that
 * arm (unchanged — see the header comment in the .c file for why the
 * bad-file ring cannot absorb a config-mismatch failure).
 *
 * ngx_http_zstd_static_dio_err_should_log() is `static` inside
 * src/ngx_http_zstd_static_module.c, so it cannot be linked from outside
 * that TU. test_dio_err_ratelimit_unit.sh extracts it (plus its window
 * constant and file-scope counters) verbatim by line range and #includes
 * the generated file here — this test always exercises the CURRENT
 * shipped implementation, never a hand-copied duplicate.
 *
 * The extracted function calls ngx_time() and ngx_log_debug1(); both are
 * stubbed below — ngx_time() as a test-controlled fake clock, including a
 * backward-step arm matching the production helper's defensive handling,
 * ngx_log_debug1() as a no-op exactly as it compiles in a non-NGX_DEBUG
 * build (see src/core/ngx_log.h's third #define block).
 */

#include <stdio.h>
#include <stdint.h>

typedef unsigned long  ngx_uint_t;
typedef long            time_t_dummy;  /* unused; time_t comes from <time.h> */
#include <time.h>

typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s { int unused; };

/* Test-controlled fake clock, standing in for ngx_cached_time->sec. */
static time_t  fake_now;

#define ngx_time()  fake_now

/* No-op, matching the non-NGX_DEBUG compiled shape of the real macro. */
#define ngx_log_debug1(level, log, err, fmt, arg1)

#include "generated_dio_ratelimit.inc"

#define NOT_SUPPRESSED  ((ngx_uint_t) -1)

static int  failures;
static int  checks;

static void
reset_state(void)
{
    ngx_http_zstd_static_dio_err_window_start = 0;
    ngx_http_zstd_static_dio_err_suppressed = 0;
    fake_now = 1000;
}

static void
check(const char *what, ngx_uint_t got, ngx_uint_t want)
{
    checks++;
    if (got != want) {
        printf("FAIL - %s: got=%lu want=%lu\n",
               what, (unsigned long) got, (unsigned long) want);
        failures++;
    }
}

int
main(void)
{
    ngx_uint_t  r;
    int         i;

    /*
     * 1. First call in a fresh worker (window_start == 0) must ALWAYS
     *    log — this is the "do not swallow the first one" invariant.
     *    It reports 0 prior occurrences.
     */
    reset_state();
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("first call logs immediately", r, 0);

    /*
     * 2. Every subsequent call inside the same window is suppressed
     *    (sentinel NOT_SUPPRESSED), and the internal counter increments
     *    once per suppressed call — proven indirectly via what the NEXT
     *    logged call reports.
     */
    for (i = 0; i < 5; i++) {
        r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
        check("mid-window call is suppressed", r, NOT_SUPPRESSED);
    }

    /*
     * 3. Still inside the window (window boundary is a `>=` on the delta,
     *    so window_start + WINDOW - 1 is still inside): still suppressed.
     */
    fake_now = 1000 + NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW - 1;
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("last second before rollover still suppressed", r, NOT_SUPPRESSED);

    /*
     * 4. At exactly window_start + WINDOW, the window rolls over: this
     *    call logs again and reports every suppressed hit folded in —
     *    5 from step 2 plus 1 from step 3 = 6.
     */
    fake_now = 1000 + NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW;
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("window rollover reports folded suppressed count", r, 6);

    /*
     * 5. The rollover call itself resets the window and the counter, so
     *    the immediately following call (still at the same fake_now) is
     *    suppressed again with the count restarted at 0 prior — proven by
     *    checking the NEXT rollover reports exactly 1, not 7.
     */
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("call right after rollover is suppressed", r, NOT_SUPPRESSED);

    fake_now += NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW;
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("counter did not leak across the rollover", r, 1);

    /*
     * 6. A worker-cycle reset (a fresh process/window_start back to 0,
     *    as happens on config reload's fork of new workers) always logs
     *    immediately again, regardless of how much suppressed history the
     *    OLD worker had accumulated — a reload must not hide a NEW
     *    problem behind a stale suppression window.
     */
    reset_state();
    ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("old worker has suppressed state", r, NOT_SUPPRESSED);

    reset_state();
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("fresh worker-cycle state logs immediately", r, 0);

    /*
     * 7. Monotonic-forward clock sanity: a window boundary exactly one
     *    tick past window_start (the minimum non-negative delta reaching
     *    WINDOW) rolls over; one tick short of it does not. This pins the
     *    boundary condition the .c file's SAFETY comment claims never
     *    underflows.
     */
    reset_state();
    ngx_http_zstd_static_dio_err_should_log(NULL, -1); /* opens window at 1000 */
    fake_now = 1000 + NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW - 1;
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("boundary-1 still suppressed", r, NOT_SUPPRESSED);
    fake_now = 1000 + NGX_HTTP_ZSTD_STATIC_DIO_ERR_WINDOW;
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("boundary rolls over", r, 1);

    /*
     * 8. Backward wall-clock step (NTP correction, admin action):
     *    ngx_time() going backward must force a rollover, not extend
     *    suppression indefinitely. A signed `now - window_start` under a
     *    backward step is negative and would otherwise stay under the
     *    `>=` window threshold forever.
     */
    reset_state();
    ngx_http_zstd_static_dio_err_should_log(NULL, -1); /* opens window at 1000 */
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("mid-window before clock step is suppressed", r, NOT_SUPPRESSED);

    fake_now = 500; /* clock stepped backward past window_start */
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("backward clock step forces rollover, not extended suppression",
          r, 1);

    /* A malformed short read must not consume the hard-error window. */
    reset_state();
    r = ngx_http_zstd_static_dio_err_should_log(NULL, 0);
    check("zero-byte EOF logs without rate limiting", r, 0);
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("first hard error after zero-byte EOF still logs", r, 0);

    reset_state();
    r = ngx_http_zstd_static_dio_err_should_log(NULL, 3);
    check("short malformed read logs without rate limiting", r, 0);
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("first hard error after malformed read still logs", r, 0);
    r = ngx_http_zstd_static_dio_err_should_log(NULL, -1);
    check("following hard error is rate limited", r, NOT_SUPPRESSED);

    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }

    printf("OK: directio probe log rate limiter (%d checks)\n", checks);
    return 0;
}
