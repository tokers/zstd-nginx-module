/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_zstd_probe_hooks.c -- nginx-module-testkit zoneless probe glue
 * for the zstd filter module (CI only).
 *
 * See ngx_http_zstd_probe_hooks.h. Everything here is compiled out unless
 * NGX_TEST_HARNESS is defined.
 *
 * http-zstd has no shm zone, so state that would normally live in shared
 * memory (see ngx_test_probe.h's fault_set comment) lives in process
 * globals instead. That is correct here for a different reason than the
 * generic "single worker in every prober conf" note: the counters below
 * are bumped by the SAME worker that later serves /__probe only when the
 * test topology pins one worker (worker_processes 1, or a single kept-alive
 * connection) -- exactly the constraint ngx_test_probe.h's
 * fault_set_global documents for its own counter. We inherit it rather
 * than re-deriving it.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

#include "ngx_test_probe.h"
#include "ngx_http_zstd_probe_hooks.h"
#include "ngx_http_zstd_common.h"

/*
 * ngx_http_zstd_ctx_t is a plain typedef (not a tag'd struct) local to the
 * filter TU, so this file cannot name it and never peeks through an opaque
 * pointer at it. The ctx fields the probe renders (free chain length and
 * out_buf state) are passed in as explicit parameters by
 * ngx_http_zstd_probe_note_ctx_state(); see its call sites in the filter
 * for the values supplied. Nothing here assumes any struct layout.
 */

/* Running per-process counters, bumped inline at each call site. */
static ngx_uint_t  ngx_http_zstd_probe_chain_links;
static ngx_uint_t  ngx_http_zstd_probe_bufs_allocated;

/* Snapshot of the most recently observed request's ctx state, taken by
 * ngx_http_zstd_probe_note_ctx_state(). Observational only -- see the
 * single-worker caveat above the includes. Renders as null (via the "have"
 * flag) until the first request populates it. */
static ngx_uint_t  ngx_http_zstd_probe_free_links;
static ngx_uint_t  ngx_http_zstd_probe_out_buf_present;
static size_t      ngx_http_zstd_probe_out_buf_size;
static ngx_uint_t  ngx_http_zstd_probe_have_ctx;

/*
 * Fault-injection state. The armed value is the raw `nth` the testkit
 * parsed, still carrying its outcome encoding (see
 * NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE in the header); -1 means disarmed,
 * which is what fault_set_global stores for any negative value.
 *
 * PROCESS GLOBALS, DELIBERATELY. These are armed by the request that hits
 * /__probe and tripped by a LATER request that runs the filter, so the two
 * must land in the same worker. Every prober conf for this module runs a
 * single worker (worker_processes 1) precisely so that holds -- the same
 * constraint ngx_test_probe.h documents for its own fault_set_global
 * counter, inherited here rather than re-derived. There is no shm zone in
 * this module to put them in even if we wanted one (verified: zero
 * ngx_shared_memory_add / shm_zone in src/), which is why the zoneless
 * hook family is registered at all.
 */
static ngx_int_t  ngx_http_zstd_probe_fault_codec_nth     = -1;
static ngx_int_t  ngx_http_zstd_probe_fault_codec_end_nth = -1;
static ngx_int_t  ngx_http_zstd_probe_fault_refprefix_nth = -1;

/*
 * Per-site event counters. These count calls SINCE THE SITE WAS ARMED,
 * not since process start, and fault_set_global resets them to 0 on every
 * arm.
 *
 * That distinction is the whole correctness of the feature. An absolute
 * process-lifetime counter makes `nth` mean "the nth call this worker has
 * ever made", so any earlier compressed request -- a warm-up, an
 * unrelated test case, a previous case in the same file -- pushes the
 * counter past a low nth and `fault_codec=1` then silently never fires.
 * The request succeeds, the test sees a normal response, and a case
 * written to assert a fault path passes by testing nothing. That is a
 * FALSE GREEN, the exact failure class this fault site exists to remove,
 * and it is invisible: there is no error, no log line, nothing to
 * distinguish "the fault did not fire" from "the code handled the fault".
 *
 * Counting from the arm instead gives `fault_codec=N` one unambiguous
 * meaning -- the Nth call at this site after you armed it -- which holds
 * no matter what traffic preceded it.
 *
 * Both are also RENDERED by module_render below, which makes them an
 * assertable observable and not just a fault ordinal: disarm a site
 * (fault_<site>=-1 zeroes its counter), issue exactly one request, then
 * read /__probe and the counter is that request's ZSTD_compressStream2()
 * call count at that site. That is the oracle behind the "one END call per
 * completed response" assertions in ci/t/00-filter.t -- an assertion that
 * cannot be satisfied by a merely-correct response, only by a response
 * that also took the intended number of codec calls.
 */
static ngx_uint_t  ngx_http_zstd_probe_codec_calls;
static ngx_uint_t  ngx_http_zstd_probe_codec_end_calls;
static ngx_uint_t  ngx_http_zstd_probe_refprefix_calls;

/*
 * Pool-allocation fault site. Same shape and same arm-relative counting as
 * the codec sites above; see the header for why the nth is a bare ordinal
 * here (an allocation has no outcome to encode -- it succeeds or it does
 * not) and for the "only wrapped sites count" caveat.
 */
static ngx_int_t   ngx_http_zstd_probe_fault_palloc_nth = -1;
static ngx_uint_t  ngx_http_zstd_probe_palloc_calls;

/*
 * ZSTD_CCtx_setParameter() call counter. No fault, no arm -- see the header.
 * Reset via GET /__probe?setparam_reset=1, mirroring the codec sites'
 * "disarm zeroes the counter" convention closely enough that a driver
 * bracketing one request looks the same shape as the codec-call-count
 * scenario's reset_counters().
 *
 * PROCESS GLOBAL, DELIBERATELY, same reasoning and same constraint as the
 * fault-site counters above (see the "PROCESS GLOBALS, DELIBERATELY"
 * comment on ngx_http_zstd_probe_fault_codec_nth): the request that resets
 * this counter and the later request whose ZSTD_CCtx_setParameter() calls
 * it counts must land in the SAME worker, so every scenario reading it
 * (setparam-call-count, setparam-call-count-nodict) sets
 * `worker_processes 1` in its nginx.conf. A multi-worker conf would read
 * whichever worker happened to answer the GET, not necessarily the one
 * that served the measured request, and the counter would silently mix
 * traffic from other requests in that worker instead of counting the one
 * response the driver is measuring.
 */
static ngx_uint_t  ngx_http_zstd_probe_setparam_calls;

static ngx_int_t ngx_http_zstd_probe_handler(ngx_http_request_t *r);


void
ngx_http_zstd_probe_note_chain_link(void)
{
    ngx_http_zstd_probe_chain_links++;
}


void
ngx_http_zstd_probe_note_buf_alloc(void)
{
    ngx_http_zstd_probe_bufs_allocated++;
}


/*
 * Called by the filter with the request's live ctx (see the header for
 * why we do not dereference a typedef this file does not own). The filter
 * passes the free-chain length it has already walked and the out_buf
 * size/presence, so this file stays independent of ngx_http_zstd_ctx_t's
 * private layout.
 */
void
ngx_http_zstd_probe_note_ctx_state(ngx_uint_t free_links,
    ngx_uint_t out_buf_present, size_t out_buf_size)
{
    ngx_http_zstd_probe_free_links = free_links;
    ngx_http_zstd_probe_out_buf_present = out_buf_present;
    ngx_http_zstd_probe_out_buf_size = out_buf_size;
    ngx_http_zstd_probe_have_ctx = 1;
}


/*
 * Codec fault decision. See the header for the outcome encoding and for
 * why the outcome rides inside `nth` instead of a second query key.
 *
 * Advances the site's event counter -- which fault_set_global zeroed when
 * the site was armed, so it counts calls since the arm -- then answers
 * whether THIS call is the armed nth. One-shot by construction: matching
 * is `==`, so a site armed at nth=1 trips on exactly one call and every
 * later call is unarmed again, and a test does not have to disarm to keep
 * the rest of its traffic clean.
 *
 * Unarmed cost: one increment and one compare against -1 that predicts
 * perfectly, before any of the decode arithmetic runs.
 */
ngx_http_zstd_probe_codec_outcome_e
ngx_http_zstd_probe_codec_fault(ngx_uint_t is_end)
{
    ngx_int_t   armed;
    ngx_uint_t  seq;

    if (is_end) {
        armed = ngx_http_zstd_probe_fault_codec_end_nth;
        seq = ++ngx_http_zstd_probe_codec_end_calls;

    } else {
        armed = ngx_http_zstd_probe_fault_codec_nth;
        seq = ++ngx_http_zstd_probe_codec_calls;
    }

    if (armed < 0) {
        /* The overwhelmingly common case: nothing armed for this site. */
        return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
    }

    if (armed >= NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE) {

        if ((ngx_uint_t) (armed - NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE) != seq) {
            return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
        }

        return NGX_HTTP_ZSTD_PROBE_CODEC_ZERO;
    }

    if ((ngx_uint_t) armed != seq) {
        return NGX_HTTP_ZSTD_PROBE_CODEC_NONE;
    }

    return NGX_HTTP_ZSTD_PROBE_CODEC_ERROR;
}


/*
 * Consume one event at the dcz-only ZSTD_CCtx_refPrefix() site.
 *
 * A prefix reference has no meaningful zero-output success state, so this
 * dedicated outcome has only NONE and ERROR. The site, state, and counter are
 * all independent from CODEC/CODEC_END.
 */
ngx_http_zstd_probe_refprefix_outcome_e
ngx_http_zstd_probe_refprefix_fault(void)
{
    ngx_uint_t  seq;

    seq = ++ngx_http_zstd_probe_refprefix_calls;

    if (ngx_http_zstd_probe_fault_refprefix_nth < 0
        || (ngx_uint_t) ngx_http_zstd_probe_fault_refprefix_nth != seq)
    {
        return NGX_HTTP_ZSTD_PROBE_REFPREFIX_NONE;
    }

    return NGX_HTTP_ZSTD_PROBE_REFPREFIX_ERROR;
}


/*
 * Pool-allocation fault decision, called once per WRAPPED allocation,
 * immediately before the real allocator runs. Advances this site's
 * arm-relative counter and reports whether THIS call is the armed nth.
 *
 * One-shot by construction (`==`, not `>=`), so a test arming nth=1 fails
 * exactly one allocation and every later allocation in the same request --
 * including the ones nginx core makes to build the error response -- is
 * unarmed again. That matters: failing *every* allocation after the first
 * would take down the error path too and the test could not tell a handled
 * failure from a dead worker.
 *
 * Unarmed cost is one increment and one perfectly-predicted compare, and
 * the whole function does not exist in a build without NGX_TEST_HARNESS.
 */
ngx_uint_t
ngx_http_zstd_probe_palloc_should_fail(void)
{
    ngx_uint_t  seq;

    seq = ++ngx_http_zstd_probe_palloc_calls;

    if (ngx_http_zstd_probe_fault_palloc_nth < 0) {
        return 0;
    }

    return (ngx_uint_t) ngx_http_zstd_probe_fault_palloc_nth == seq;
}


/*
 * Wrapped-allocation count since the site was last armed or disarmed.
 * Rendered at /__probe so a test can assert the counter ADVANCED, rather
 * than inferring from a failed request that the fault must have fired --
 * a request can fail for reasons that have nothing to do with the arm, and
 * an oracle that cannot tell those apart asserts nothing.
 */
ngx_uint_t
ngx_http_zstd_probe_palloc_count(void)
{
    return ngx_http_zstd_probe_palloc_calls;
}


/*
 * Bump the setParameter call counter. Called once per
 * ngx_http_zstd_set_param() invocation in init_cctx -- see the header for
 * why this is a plain counter and not a fault site.
 */
void
ngx_http_zstd_probe_note_setparam(void)
{
    ngx_http_zstd_probe_setparam_calls++;
}


ngx_uint_t
ngx_http_zstd_probe_setparam_count(void)
{
    return ngx_http_zstd_probe_setparam_calls;
}


void
ngx_http_zstd_probe_setparam_reset(void)
{
    ngx_http_zstd_probe_setparam_calls = 0;
}


/*
 * module_render hook: append this module's zone-independent counters to
 * the top-level "module" object. ngx_test_probe_render_module() has
 * already written the opening `,"module":{` before calling this hook, so
 * (unlike the zone-addressed zone_render) there is NO leading comma here;
 * must NOT close the brace either. Bounded against `last`.
 */
static u_char *
ngx_http_zstd_probe_module_render(u_char *buf, u_char *last)
{
    buf = ngx_slprintf(buf, last,
                        "\"chain_links_allocated\":%ui"
                        ",\"buffers_allocated\":%ui"
                        ",\"palloc_calls\":%ui"
                        ",\"codec_calls\":%ui"
                        ",\"codec_end_calls\":%ui"
                        ",\"refprefix_calls\":%ui"
                        ",\"refprefix_armed\":%ui"
                        ",\"setparam_calls\":%ui",
                        ngx_http_zstd_probe_chain_links,
                        ngx_http_zstd_probe_bufs_allocated,
                        ngx_http_zstd_probe_palloc_calls,
                        ngx_http_zstd_probe_codec_calls,
                        ngx_http_zstd_probe_codec_end_calls,
                        ngx_http_zstd_probe_refprefix_calls,
                        ngx_http_zstd_probe_fault_refprefix_nth < 0
                            ? 0
                            : (ngx_uint_t)
                                ngx_http_zstd_probe_fault_refprefix_nth,
                        ngx_http_zstd_probe_setparam_calls);

    if (ngx_http_zstd_probe_have_ctx) {
        buf = ngx_slprintf(buf, last,
                            ",\"free_chain_links\":%ui"
                            ",\"out_buf\":{\"present\":%d,\"size\":%uz}",
                            ngx_http_zstd_probe_free_links,
                            (int) ngx_http_zstd_probe_out_buf_present,
                            ngx_http_zstd_probe_out_buf_size);
    } else {
        buf = ngx_slprintf(buf, last,
                            ",\"free_chain_links\":null"
                            ",\"out_buf\":null");
    }

    return buf;
}


/*
 * Is `nth` a value the codec-site encoding actually defines?
 *
 * Negative disarms; 1..999 is the ERROR form; ZERO_BASE+1..ZERO_BASE+999
 * is the ZERO form. Everything else -- 0, exactly ZERO_BASE, and anything
 * above the ZERO range -- is refused rather than stored, because the
 * decoder would otherwise accept a wider set than the header documents
 * (2000..9999 would arm ZERO at calls 1000..8999, and 0 / ZERO_BASE would
 * arm "nth zero", a value the counter never takes since it is
 * pre-incremented). A test that fat-fingers an nth would then arm
 * something that can never fire and pass by testing nothing -- the same
 * false-green class the arm-relative counter exists to prevent.
 *
 * Applied per site rather than up front: SLAB/TEMPFILE/ACCEPT decline
 * because the SITE is unimplemented here, which is true whatever nth says,
 * and conflating the two would answer the wrong question for them even
 * though both answers happen to be NGX_DECLINED. The PALLOC site uses this
 * helper too, but narrows it further -- see its arm, which rejects the
 * codec-only ZERO_BASE range.
 */
static ngx_int_t
ngx_http_zstd_probe_nth_is_valid(ngx_int_t nth)
{
    if (nth < 0) {
        return 1;
    }

    if (nth >= 1 && nth <= 999) {
        return 1;
    }

    if (nth >= NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE + 1
        && nth <= NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE + 999)
    {
        return 1;
    }

    return 0;
}


/*
 * Arm the module-local refPrefix site from the request query string.
 *
 * The generic testkit predates this dcz-only site, so it does not know the
 * fault_refprefix key. Keep the same input contract as its bare-ordinal sites:
 * 1..999 arms, any well-formed negative value disarms, and malformed or
 * out-of-range values leave the current arm unchanged.
 */
static void
ngx_http_zstd_probe_arm_refprefix(ngx_http_request_t *r)
{
    ngx_str_t  value;
    ngx_int_t  nth;

    if (ngx_http_arg(r, (u_char *) "fault_refprefix",
                     sizeof("fault_refprefix") - 1, &value)
        != NGX_OK)
    {
        return;
    }

    if (value.len >= 2 && value.data[0] == '-') {
        nth = ngx_atoi(value.data + 1, value.len - 1);
        if (nth > 0) {
            ngx_http_zstd_probe_fault_refprefix_nth = -1;
            ngx_http_zstd_probe_refprefix_calls = 0;
        }
        return;
    }

    nth = ngx_atoi(value.data, value.len);
    if (nth < 1 || nth > 999) {
        return;
    }

    ngx_http_zstd_probe_fault_refprefix_nth = nth;
    ngx_http_zstd_probe_refprefix_calls = 0;
}


/*
 * Reset the setParameter counter from the request query string
 * (?setparam_reset=1). No fault to arm here, so this is a bare reset
 * rather than routed through fault_set_global -- same reasoning as
 * arm_refprefix() above being module-local because the generic testkit
 * predates this counter.
 */
static void
ngx_http_zstd_probe_arm_setparam_reset(ngx_http_request_t *r)
{
    ngx_str_t  value;

    if (ngx_http_arg(r, (u_char *) "setparam_reset",
                     sizeof("setparam_reset") - 1, &value)
        != NGX_OK)
    {
        return;
    }

    if (value.len == 1 && value.data[0] == '1') {
        ngx_http_zstd_probe_setparam_reset();
    }
}


/*
 * fault_set_global hook: zstd wires no SLAB/TEMPFILE/ACCEPT injection
 * points -- decline those. CODEC/CODEC_END are stored raw,
 * outcome encoding and all; ngx_http_zstd_probe_codec_fault() decodes
 * them at the single ZSTD_compressStream2 call site in the filter.
 *
 * The value IS range-checked before it is stored, per codec site: the
 * testkit's parser only bounds it to +/- 4 digits, which is wider than
 * the outcome encoding defines, so a value outside the documented sets
 * is refused here rather than stored as an arm that can never fire --
 * see ngx_http_zstd_probe_nth_is_valid(). Anything negative disarms, and
 * arming (or disarming) resets that site's call counter so nth counts
 * from the arm.
 */
static ngx_int_t
ngx_http_zstd_probe_fault_set_global(ngx_test_probe_fault_e fault,
    ngx_int_t nth)
{
    switch (fault) {

    case NGX_TEST_PROBE_FAULT_CODEC:
        if (!ngx_http_zstd_probe_nth_is_valid(nth)) {
            return NGX_DECLINED;
        }

        ngx_http_zstd_probe_fault_codec_nth = nth;
        /*
         * Count from the arm, not from process start -- see the counter
         * declarations. Reset on disarm too: it costs nothing and leaves
         * the site in one well-defined state either way.
         */
        ngx_http_zstd_probe_codec_calls = 0;
        return NGX_OK;

    case NGX_TEST_PROBE_FAULT_CODEC_END:
        if (!ngx_http_zstd_probe_nth_is_valid(nth)) {
            return NGX_DECLINED;
        }

        ngx_http_zstd_probe_fault_codec_end_nth = nth;
        ngx_http_zstd_probe_codec_end_calls = 0;
        return NGX_OK;

    case NGX_TEST_PROBE_FAULT_PALLOC:
        /*
         * Bare ordinal, so only the plain 1..999 form (and negatives) is
         * accepted -- the ZERO_BASE encoding is codec-specific and an nth
         * in that range here would arm call 1000+, which no request ever
         * reaches. Refusing beats storing an arm that can never fire.
         */
        if (nth >= NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE
            || !ngx_http_zstd_probe_nth_is_valid(nth))
        {
            return NGX_DECLINED;
        }

        ngx_http_zstd_probe_fault_palloc_nth = nth;
        ngx_http_zstd_probe_palloc_calls = 0;
        return NGX_OK;

    case NGX_TEST_PROBE_FAULT_SLAB:
    case NGX_TEST_PROBE_FAULT_TEMPFILE:
    case NGX_TEST_PROBE_FAULT_ACCEPT:
    default:
        /* Not implemented by this module: refuse, same as no hook at all. */
        return NGX_DECLINED;
    }
}


/*
 * THIS STRUCT IS INITIALISED POSITIONALLY. Never append a member here --
 * ngx_test_probe_module_hooks_t is exactly two function pointers today and
 * this repo builds under -Wextra -Werror, which turns an appended member
 * into -Wmissing-field-initializers, a build failure, in every consumer
 * that initialises it positionally (this one included). If a future testkit
 * version needs more from a zoneless module, that is a THIRD struct with
 * its own registration call, never a member added to this one or to
 * ngx_test_probe_hooks_t (see ngx_test_probe.h's own comment on the same
 * rule for the zone-addressed struct).
 */
static const ngx_test_probe_module_hooks_t  ngx_http_zstd_probe_hooks = {
    ngx_http_zstd_probe_module_render,
    ngx_http_zstd_probe_fault_set_global,
};


/*
 * Directive handler for "zstd_probe": takes no arguments, installs this
 * location's content handler. Exposed (not static) so the filter module's
 * own ngx_command_t table can reference it directly -- this file adds no
 * second ngx_module_t/ngx_http_module_t of its own. filter/config builds
 * this TU as an extra source of the SAME dynamic module
 * (ngx_http_zstd_filter_module), not a separate one; see the traps note in
 * plan-testkit-integration.md about ngx_addon_dir and single-module builds.
 */
char *
ngx_http_zstd_probe_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_zstd_probe_handler;

    return NGX_CONF_OK;
}


/*
 * Content handler: render the probe snapshot as JSON and return 200 OK.
 * No shm zone to pass (this module has none) -- NULL routes
 * ngx_test_probe_arm() and ngx_test_probe_json() through the
 * zone-independent path.
 */
static ngx_int_t
ngx_http_zstd_probe_handler(ngx_http_request_t *r)
{
    size_t        size;
    u_char       *buf, *last;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Arm-then-render: the response must reflect fault state AFTER
     * arming. No zone, so this always falls through to
     * fault_set_global -- see ngx_test_probe_arm()'s dispatch-order
     * comment.
     */
    ngx_http_zstd_probe_arm_refprefix(r);
    ngx_http_zstd_probe_arm_setparam_reset(r);
    (void) ngx_test_probe_arm(NULL, &r->args);

    /*
     * NGX_TEST_PROBE_JSON_MAX covers the harness's generic document.
     * This module has no zone name to add, but module_render appends
     * module counters plus a nested out_buf object plus the
     * `,"module":{}` wrapper -- comfortably under 256 bytes, and we
     * oversize per the header's "when in doubt, oversize" guidance
     * rather than count bytes exactly. An undersized buffer truncates
     * and fails EVERY case, not just one -- see plan-testkit-
     * integration.md Traps.
     */
    size = NGX_TEST_PROBE_JSON_MAX + 256;

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_test_probe_json(buf, buf + size, NULL);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = last - buf;
    ngx_str_set(&r->headers_out.content_type, "application/json");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = buf;
    b->last = last;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


ngx_int_t
ngx_http_zstd_probe_init(ngx_conf_t *cf)
{
    ngx_test_probe_register_module(&ngx_http_zstd_probe_hooks);

    return NGX_OK;
}

#endif /* NGX_TEST_HARNESS */
