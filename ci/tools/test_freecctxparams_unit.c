/*
 * Unit fixture for ngx_http_zstd_estimate_cctx_memory().
 *
 * The function is `static` inside src/ngx_http_zstd_filter_module.c, so it
 * cannot be linked from outside that TU. test_freecctxparams_unit.sh
 * extracts it verbatim by line range (the repo's established precedent --
 * see test_read_dict_file_unit.sh and test_cctx_profile_pack.sh) and
 * #includes the generated file here, so this test always exercises the
 * CURRENT shipped implementation rather than a hand-copied duplicate.
 *
 * WHY A UNIT FIXTURE AND NOT THE HTTP FAULT-INJECTION PROBE. This function
 * takes an ngx_conf_t * and runs during "nginx -t" config load, before any
 * request exists -- the probe endpoint that arms the other libzstd fault
 * sites in this module has no request in flight through which to reach it.
 * A direct unit fixture that fakes the ZSTD_CCtx_params call chain is the
 * only way to force each of the six early-return error exits.
 *
 * THE DEFECT CLASS THIS GUARDS. Every one of the six early returns must
 * call ZSTD_freeCCtxParams(cp) before returning NGX_CONF_ERROR; a leak in
 * ANY ONE of the six passes CI silently because the other five still free
 * correctly and no per-request path ever touches this function again.
 * Six independent scenarios below each force exactly one exit and assert
 * ZSTD_freeCCtxParams was called EXACTLY ONCE on the SAME cp pointer the
 * function was handed -- a counting assertion, not a reachability check,
 * so deleting any single free call turns that scenario's count from 1 to 0.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* --- minimal nginx type/macro surface the extracted function needs ----- */

typedef long       ngx_int_t;
typedef long       ngx_flag_t;
typedef long       ssize_t_ngx; /* unused placeholder, kept for clarity */

typedef struct { int unused; } ngx_conf_t;

typedef struct {
    ngx_int_t   level;
    ssize_t     target_cblock_size;
    ngx_flag_t  long_mode;
} ngx_http_zstd_loc_conf_t;

#define NGX_LOG_EMERG 2

#define NGX_CONF_OK     ((char *) 0)
#define NGX_CONF_ERROR  ((char *) -1)

/*
 * Diagnostics are counted, not printed: the assertions below care that each
 * failing exit REPORTS (the shipped code always does), not about wording.
 * Variadic and ignoring its arguments so any format string the shipped code
 * uses compiles unchanged.
 */
static int  log_calls;
static void ngx_conf_log_error(int level, ngx_conf_t *cf, int err,
    const char *fmt, ...)
{
    (void) level; (void) cf; (void) err; (void) fmt;
    log_calls++;
}

/* --- real zstd.h for types/macros/enum only; every ZSTD_* function below
 * is faked in this file, not linked from libzstd. ZSTD_STATIC_LINKING_ONLY
 * (passed on the command line by test_freecctxparams_unit.sh) is required
 * for ZSTD_CCtx_params / ZSTD_createCCtxParams / ZSTD_freeCCtxParams /
 * ZSTD_CCtxParams_init / ZSTD_CCtxParams_setParameter /
 * ZSTD_estimateCStreamSize_usingCCtxParams to be declared at all; the
 * struct stays opaque, which is all the extracted function needs. */
#ifndef ZSTD_STATIC_LINKING_ONLY
#define ZSTD_STATIC_LINKING_ONLY
#endif
#include <zstd.h>

/*
 * The production module correctly omits targetCBlockSize when built with
 * libzstd headers older than 1.5.6.  This fixture links no real libzstd,
 * however: every call is faked below, and it must still compile and drive
 * that sixth error exit on CI hosts whose system zstd.h predates 1.5.6.
 * Retain an older header's experimental alias when present, otherwise supply
 * the public 1.5.6 value only to this fake translation unit, then raise the
 * extracted function's version gate accordingly.
 */
#if ZSTD_VERSION_NUMBER < 10506
#ifndef ZSTD_c_targetCBlockSize
#define ZSTD_c_targetCBlockSize  ((ZSTD_cParameter) 130)
#endif
#undef ZSTD_VERSION_NUMBER
#define ZSTD_VERSION_NUMBER  10506
#endif

/* --- scripted fake ZSTD_* layer -----------------------------------------
 *
 * One sentinel ZSTD_CCtx_params object stands in for the real (opaque)
 * struct; the extracted function only ever holds a pointer to it, so
 * identity -- not contents -- is what "the same cp" means here.
 *
 * Each scenario configures which named call should fail (return an error
 * code) via `fail_call`; every other scripted call succeeds (returns 0).
 * free_count / freed_ptr record every ZSTD_freeCCtxParams() invocation so
 * the harness can assert both "freed exactly once" and "freed the right
 * pointer" -- a free on a different pointer, or a leak (0 frees), or a
 * double-free (2+ frees) all fail the assertion.
 */
struct ZSTD_CCtx_params_s {
    int tag;
};

static struct ZSTD_CCtx_params_s  sentinel_cp;
static int                        create_returns_null;
static int                        free_count;
static void                      *freed_ptr;

typedef enum {
    CALL_NONE = 0,
    CALL_INIT,
    CALL_WINDOWLOG,             /* the plain zstd_window_log setParameter */
    CALL_ENABLE_LDM,
    CALL_LDM_WINDOWLOG,         /* first of the 5-step LDM derivation chain */
    CALL_LDM_HASHLOG,
    CALL_LDM_MINMATCH,
    CALL_LDM_BUCKETSIZELOG,
    CALL_LDM_HASHRATELOG,
    CALL_TARGET_CBLOCK,
} which_call_t;

static which_call_t  fail_call;

ZSTD_CCtx_params *
ZSTD_createCCtxParams(void)
{
    if (create_returns_null) {
        return NULL;
    }
    sentinel_cp.tag = 0;
    return &sentinel_cp;
}

size_t
ZSTD_freeCCtxParams(ZSTD_CCtx_params *params)
{
    if (params != NULL) {
        free_count++;
        freed_ptr = params;
    }
    return 0;
}

size_t
ZSTD_CCtxParams_init(ZSTD_CCtx_params *params, int level)
{
    (void) params; (void) level;
    return (fail_call == CALL_INIT) ? (size_t) -1 : 0;
}

size_t
ZSTD_CCtxParams_setParameter(ZSTD_CCtx_params *params, ZSTD_cParameter param,
    int value)
{
    (void) params; (void) value;

    switch ((int) param) {
    case ZSTD_c_windowLog:
        /*
         * Two different call sites push windowLog: the plain
         * "zstd_window_log" push (only when long_mode is off) and the LDM
         * derivation's first push (only when long_mode is on). Only one
         * is reachable per scenario, so a single tag distinguishes them
         * without ambiguity.
         */
        if (fail_call == CALL_WINDOWLOG || fail_call == CALL_LDM_WINDOWLOG) {
            return (size_t) -1;
        }
        return 0;
    case ZSTD_c_enableLongDistanceMatching:
        return (fail_call == CALL_ENABLE_LDM) ? (size_t) -1 : 0;
    case ZSTD_c_ldmHashLog:
        return (fail_call == CALL_LDM_HASHLOG) ? (size_t) -1 : 0;
    case ZSTD_c_ldmMinMatch:
        return (fail_call == CALL_LDM_MINMATCH) ? (size_t) -1 : 0;
    case ZSTD_c_ldmBucketSizeLog:
        return (fail_call == CALL_LDM_BUCKETSIZELOG) ? (size_t) -1 : 0;
    case ZSTD_c_ldmHashRateLog:
        return (fail_call == CALL_LDM_HASHRATELOG) ? (size_t) -1 : 0;
#if ZSTD_VERSION_NUMBER >= 10506
    case ZSTD_c_targetCBlockSize:
        return (fail_call == CALL_TARGET_CBLOCK) ? (size_t) -1 : 0;
#endif
    default:
        return 0;
    }
}

size_t
ZSTD_estimateCStreamSize_usingCCtxParams(const ZSTD_CCtx_params *params)
{
    (void) params;
    return 12345; /* arbitrary non-error size_t */
}

unsigned
ZSTD_isError(size_t code)
{
    return code == (size_t) -1;
}

const char *
ZSTD_getErrorName(size_t code)
{
    (void) code;
    return "fake-error";
}

#include "generated_estimate_cctx_memory.inc"

/* --- harness ------------------------------------------------------------ */

static int  failures;

static void
reset(void)
{
    create_returns_null = 0;
    free_count = 0;
    freed_ptr = NULL;
    fail_call = CALL_NONE;
    log_calls = 0;
}

/*
 * Asserts EXACTLY ONE free, on the SAME cp the function received. This is
 * the counting assertion the item requires: it distinguishes "freed once"
 * (1) from "leaked" (0) and from "double-freed" (2+), and it is falsified
 * by deleting the one ZSTD_freeCCtxParams(cp) call this scenario exercises
 * -- unlike a bare "was it called at all" check, which a stray free on an
 * unrelated exit could still satisfy.
 */
static void
check_freed_once(const char *name, char *rc)
{
    if (rc != NGX_CONF_ERROR) {
        printf("\xe2\x9c\x97 %s: rc=%p want NGX_CONF_ERROR\n", name,
               (void *) rc);
        failures++;
        return;
    }
    if (free_count != 1) {
        printf("\xe2\x9c\x97 %s: ZSTD_freeCCtxParams called %d time(s), "
               "want exactly 1\n", name, free_count);
        failures++;
        return;
    }
    if (freed_ptr != (void *) &sentinel_cp) {
        printf("\xe2\x9c\x97 %s: freed pointer %p != cp %p\n", name,
               freed_ptr, (void *) &sentinel_cp);
        failures++;
        return;
    }
    if (log_calls < 1) {
        printf("\xe2\x9c\x97 %s: rc ok but no diagnostic logged\n", name);
        failures++;
        return;
    }
    printf("\xe2\x9c\x93 %s\n", name);
}

int
main(void)
{
    ngx_conf_t                 cf;
    ngx_http_zstd_loc_conf_t   conf;
    size_t                     est;
    char                      *rc;

    memset(&cf, 0, sizeof(cf));

    /* 0. Baseline: the ordinary success path frees exactly once too. */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.long_mode = 0;
    conf.target_cblock_size = 0;
    est = 0;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    if (rc != NGX_CONF_OK) {
        printf("\xe2\x9c\x97 success path: rc=%p want NGX_CONF_OK\n",
               (void *) rc);
        failures++;
    } else if (free_count != 1) {
        printf("\xe2\x9c\x97 success path: ZSTD_freeCCtxParams called %d "
               "time(s), want exactly 1\n", free_count);
        failures++;
    } else if (est != 12345) {
        printf("\xe2\x9c\x97 success path: *est=%zu want 12345\n", est);
        failures++;
    } else {
        printf("\xe2\x9c\x93 success path frees exactly once\n");
    }

    /* 1. ZSTD_CCtxParams_init() fails -- first error exit. */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    fail_call = CALL_INIT;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    check_freed_once("exit 1: ZSTD_CCtxParams_init fails", rc);

    /*
     * 2. Plain zstd_window_log setParameter fails -- second error exit.
     * Only reached when window_log > 0 and long_mode is off.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    fail_call = CALL_WINDOWLOG;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 20, &est);
    check_freed_once("exit 2: windowLog setParameter fails", rc);

    /*
     * 3. enableLongDistanceMatching setParameter fails -- third error exit.
     * Only reached when long_mode is on.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.long_mode = 1;
    fail_call = CALL_ENABLE_LDM;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    check_freed_once("exit 3: enableLongDistanceMatching setParameter fails", rc);

    /*
     * 4. The 5-step LDM derivation chain fails -- fourth error exit. Each
     * of the five sub-calls is independently capable of triggering this
     * exact exit; exercise the LAST one (ldmHashRateLog) because it proves
     * the short-circuit chain still reaches all the way to the final push
     * before erroring, not just the first.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.long_mode = 1;
    fail_call = CALL_LDM_HASHRATELOG;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    check_freed_once("exit 4: LDM derivation chain fails (ldmHashRateLog)", rc);

    /*
     * 4b. Same exit, different failing sub-call (ldmMinMatch), to show the
     * chain's OWN short-circuit does not accidentally skip the free either.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.long_mode = 1;
    fail_call = CALL_LDM_MINMATCH;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    check_freed_once("exit 4b: LDM derivation chain fails (ldmMinMatch)", rc);

    /*
     * 5. Defence-in-depth: ldm_rlog <= 0 -- fifth error exit. This is NOT
     * a ZSTD_isError() branch; it is a derived-value guard. Drive it by
     * requesting a window_log so small that ldm_hlog clamps to
     * ZSTD_LDM_HASHLOG_MIN >= ldm_wlog, forcing ldm_rlog <= 0.
     * ZSTD_LDM_HASHLOG_MIN in the real libzstd headers is 6, so window_log
     * 6 makes ldm_wlog=6, ldm_hlog clamps to 6, ldm_rlog = 6-6 = 0.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.long_mode = 1;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 6, &est);
    check_freed_once("exit 5: derived LDM hash rate is zero (ldm_rlog<=0)", rc);

    /*
     * 6. targetCBlockSize setParameter fails -- sixth error exit. Only
     * reached when target_cblock_size > 0 (and the libzstd version gate is
     * satisfied, which it is: this build's zstd.h reports
     * ZSTD_VERSION_NUMBER >= 10506).
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    conf.target_cblock_size = 512;
    fail_call = CALL_TARGET_CBLOCK;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    check_freed_once("exit 6: targetCBlockSize setParameter fails", rc);

    /*
     * 7. ZSTD_createCCtxParams() itself returns NULL. Not one of the six
     * counted exits (there is no cp to free), but worth a sanity check that
     * this path does NOT call ZSTD_freeCCtxParams on a NULL cp and does not
     * crash.
     */
    reset();
    memset(&conf, 0, sizeof(conf));
    conf.level = 3;
    create_returns_null = 1;
    rc = ngx_http_zstd_estimate_cctx_memory(&cf, &conf, 0, &est);
    if (rc != NGX_CONF_ERROR) {
        printf("\xe2\x9c\x97 createCCtxParams NULL: rc=%p want "
               "NGX_CONF_ERROR\n", (void *) rc);
        failures++;
    } else if (free_count != 0) {
        printf("\xe2\x9c\x97 createCCtxParams NULL: ZSTD_freeCCtxParams "
               "called %d time(s) on a NULL cp, want 0\n", free_count);
        failures++;
    } else {
        printf("\xe2\x9c\x93 createCCtxParams NULL: no free attempted, "
               "no crash\n");
    }

    if (failures) {
        printf("\xe2\x9d\x8c %d freecctxparams unit assertion(s) failed\n",
               failures);
        return 1;
    }

    printf("\xe2\x9c\x93 all freecctxparams unit assertions passed\n");
    return 0;
}
