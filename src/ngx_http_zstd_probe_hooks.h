/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_zstd_probe_hooks.h -- nginx-module-testkit zoneless probe glue
 * for the zstd filter module (CI only).
 *
 * http-zstd has zero shm zones (verified: no ngx_shared_memory_add /
 * shm_zone in src/), so the zone-addressed hook family
 * (ngx_test_probe_hooks_t / ngx_test_probe_register()) does not apply. This
 * file wires the zone-INDEPENDENT hooks instead
 * (ngx_test_probe_module_hooks_t / ngx_test_probe_register_module()),
 * rendering into the top-level "module" object.
 *
 * Entirely compiled out unless NGX_TEST_HARNESS is defined -- see
 * filter/config for the two build switches this requires
 * (TEST_HARNESS=1 for the sources, -DNGX_TEST_HARNESS for the macro; both
 * are required, see plan-testkit-integration.md § Ground truth).
 */

#ifndef NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_
#define NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

/*
 * Register the zoneless testkit hooks. Call once from
 * ngx_http_zstd_filter_init() (postconfiguration) -- see the call site
 * there. Unconditional: called even when every location has "zstd off",
 * because the probe endpoint must stay reachable regardless of filter
 * enablement.
 */
ngx_int_t ngx_http_zstd_probe_init(ngx_conf_t *cf);

/*
 * Handler for the "zstd_probe" directive (NGX_CONF_NOARGS), added to the
 * filter module's own ngx_command_t table -- this file registers no
 * ngx_module_t of its own. Installs this location's content handler.
 */
char *ngx_http_zstd_probe_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * Per-request instrumentation call sites. Both are cheap process-global
 * counter bumps guarded entirely by NGX_TEST_HARNESS, so they cost nothing
 * in a packaged build (the calls themselves compile out via the macro guard
 * at each call site, not just the bodies here).
 *
 * ngx_http_zstd_probe_note_chain_link() -- called once per ngx_chain_link_t
 * allocated when the body filter lazily retains an unconsumed input tail.
 *
 * ngx_http_zstd_probe_note_buf_alloc() -- called once per fresh output
 * buffer created in ngx_http_zstd_filter_get_buf() (the ctx->bufs < ...
 * branch, i.e. NOT the free-list reuse branch).
 *
 * ngx_http_zstd_probe_note_ctx_state() -- called with values already
 * derived from the request's ctx so the probe can snapshot free-list length
 * and out_buf state. Safe to call repeatedly (e.g. once per body filter
 * invocation); last write wins. The snapshot is observational only -- see
 * the .c file for the single-worker caveat this inherits from
 * fault_set_global's per-worker-global contract.
 */
void ngx_http_zstd_probe_note_chain_link(void);
void ngx_http_zstd_probe_note_buf_alloc(void);

/*
 * Snapshot the request's free-chain length and out_buf state. The filter
 * passes already-derived values (not the ctx pointer itself) so this file
 * stays independent of ngx_http_zstd_ctx_t's private layout, which is a
 * file-static typedef in the filter TU.
 */
void ngx_http_zstd_probe_note_ctx_state(ngx_uint_t free_links,
    ngx_uint_t out_buf_present, size_t out_buf_size);


/*
 * Codec fault injection (Phase 3).
 *
 * The outcome an armed site produces. The testkit's arm parser carries a
 * single integer per site (fault_codec=<nth>), and the probe contract is
 * explicit that the module owns the injection point AND ITS SEMANTICS --
 * so http-zstd encodes the outcome in the high part of that integer
 * rather than asking the testkit for a second query key. See
 * NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE below.
 */
typedef enum {
    NGX_HTTP_ZSTD_PROBE_CODEC_NONE = 0,  /* not armed for this event    */
    NGX_HTTP_ZSTD_PROBE_CODEC_ERROR,     /* return a ZSTD_isError value */
    NGX_HTTP_ZSTD_PROBE_CODEC_ZERO       /* succeed, writing no output  */
} ngx_http_zstd_probe_codec_outcome_e;


/*
 * Outcome encoding inside the single `nth` the testkit hands us.
 *
 *   fault_codec=<n>         n in 1..999   -> ERROR outcome on the nth call
 *   fault_codec=<1000 + n>  n in 1..999   -> ZERO-OUTPUT outcome on the nth
 *   fault_codec=<negative>                -> disarm
 *
 * "the nth call" counts FROM THE ARM, not from process start: arming
 * resets that site's counter. So fault_codec=1 always means "the very
 * next call at this site", whatever traffic the worker served before.
 * Counting absolutely instead would let any earlier compressed request
 * push the counter past a low nth, and the arm would then silently never
 * fire -- a false green, since a request that was never faulted looks
 * exactly like one whose fault was handled.
 *
 * Values outside those three sets are REFUSED (NGX_DECLINED) rather than
 * stored, so a mistyped nth surfaces at the probe endpoint instead of
 * arming something that never fires.
 *
 * WHY ENCODE RATHER THAN ADD A KEY. The ZERO outcome is not optional
 * decoration: the suppression arm in the filter gates on
 * ngx_buf_size(ctx->out_buf) == 0, which is a libzstd *output* decision,
 * not an error. An error-returning fault aborts the request before that
 * arm is ever evaluated, so without a success-with-zero-output outcome the
 * arm stays unreachable. Adding a second query key would mean changing the
 * testkit, which is out of scope for this repo; the testkit's own contract
 * (ngx_test_probe.h, "the module owns every actual injection point")
 * delegates exactly this choice to us. The base is 1000 because the parser
 * bounds a fault value at NGX_TEST_PROBE_FAULT_MAX_DIGITS (4) digits, so
 * 1000..1999 is representable while leaving 1..999 for the plain form.
 */
#define NGX_HTTP_ZSTD_PROBE_FAULT_ZERO_BASE  1000


/*
 * Consume one codec-call event for the given site and report which
 * outcome, if any, this call must produce.
 *
 * `is_end` selects the site: the ZSTD_e_end call is CODEC_END, every other
 * directive is CODEC. Called exactly once per ZSTD_compressStream2 call,
 * immediately before it, and it is the call that advances that site's
 * event counter -- so a site armed at nth=2 trips on the second call
 * REGARDLESS of which outcome was requested.
 *
 * Returns NGX_HTTP_ZSTD_PROBE_CODEC_NONE for the overwhelmingly common
 * unarmed case; both globals sit at -1 then and the function is a pair of
 * predictable compares, which is the "zero measurable cost when not armed"
 * requirement. When not compiled (no NGX_TEST_HARNESS) neither this
 * declaration nor its call site exists at all.
 */
ngx_http_zstd_probe_codec_outcome_e
    ngx_http_zstd_probe_codec_fault(ngx_uint_t is_end);


/*
 * Dedicated dcz raw-prefix fault site.
 *
 * Armed with GET /__probe?fault_refprefix=<nth>. The nth
 * ZSTD_CCtx_refPrefix() call after the arm is replaced with a synthetic
 * ZSTD_isError()-true result. Negative values disarm. This is deliberately
 * separate from CODEC/CODEC_END: ordinary zstd requests never call
 * ZSTD_CCtx_refPrefix(), and folding the site into either codec counter would
 * let a plain request consume a fault intended for the dcz-only setup path.
 *
 * The counter is rendered as refprefix_calls so the harness can distinguish
 * "the dcz branch handled the fault" from "the arm was never reached".
 */
typedef enum {
    NGX_HTTP_ZSTD_PROBE_REFPREFIX_NONE = 0,
    NGX_HTTP_ZSTD_PROBE_REFPREFIX_ERROR
} ngx_http_zstd_probe_refprefix_outcome_e;

ngx_http_zstd_probe_refprefix_outcome_e
    ngx_http_zstd_probe_refprefix_fault(void);


/*
 * Pool-allocation fault injection.
 *
 * Armed with GET /__probe?fault_palloc=<nth>: the nth pool allocation the
 * filter makes THROUGH THE WRAPPERS in the filter TU, counted from the arm,
 * returns NULL instead of memory. Negative disarms. Unlike the codec site
 * there is no outcome encoding -- an allocation either succeeds or returns
 * NULL -- so `nth` carries only the ordinal and the valid set is 1..999
 * plus negatives.
 *
 * WHY A MODULE-LOCAL WRAPPER AND NOT A REAL POOL FAILURE. nginx's pool
 * allocator only fails when the OS refuses memory, which a test cannot
 * provoke without an ulimit/cgroup that would take the whole worker down
 * (and with it every oracle in the run). The wrapper narrows the failure to
 * exactly one call, at exactly one site, leaving the rest of the request
 * intact -- which is the only way an "allocation failed HERE" branch can be
 * asserted individually.
 *
 * COUNTING IS FROM THE ARM, for the same reason the codec counter is: an
 * absolute counter makes a low nth unreachable after any earlier traffic,
 * and an arm that can never fire is a false green (see the codec counter's
 * comment for the full argument).
 *
 * IMPORTANT -- only wrapped call sites are counted. A pool allocation the
 * filter makes by calling ngx_palloc() directly is invisible to both the
 * counter and the fault, so `nth` means "the nth WRAPPED allocation", not
 * "the nth allocation". Which ordinal reaches which site is therefore a
 * property of the request, not a constant; ci/t/harness-scenarios/
 * fault-palloc/driver.sh documents the map it relies on and asserts the
 * counter advanced, so a change in that order fails the oracle loudly
 * instead of silently aiming it at a different site.
 *
 * ngx_http_zstd_probe_palloc_count() exposes the counter so a test can
 * assert it actually advanced, which is what distinguishes "the fault fired
 * and the branch handled it" from "the arm was silently refused and the
 * request failed for some unrelated reason".
 */
ngx_uint_t ngx_http_zstd_probe_palloc_should_fail(void);
ngx_uint_t ngx_http_zstd_probe_palloc_count(void);


/*
 * ZSTD_CCtx_setParameter() call counter -- observation only, no fault.
 *
 * Bumped once per call from ngx_http_zstd_set_param() in init_cctx,
 * counting from process start (not from an arm: there is nothing to arm
 * here, only a count to read). Exists to pin the per-mode setParameter
 * call count this module makes when configuring a request's CCtx --
 * skipping a superseded-by-CDict parameter must show up as a lower count
 * for that mode, and a mutation that re-adds the redundant set must show
 * up as a higher one. ngx_http_zstd_probe_setparam_count() reads it;
 * ngx_http_zstd_probe_setparam_reset() zeroes it so a driver can bracket
 * exactly one request's calls the same way the codec sites are bracketed
 * by their arm-relative reset.
 */
void       ngx_http_zstd_probe_note_setparam(void);
ngx_uint_t ngx_http_zstd_probe_setparam_count(void);
void       ngx_http_zstd_probe_setparam_reset(void);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_HTTP_ZSTD_PROBE_HOOKS_H_INCLUDED_ */
