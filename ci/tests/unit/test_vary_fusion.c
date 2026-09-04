/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the fused Vary walk in src/ngx_http_zstd_common.h
 * (ngx_http_zstd_vary_ae_dcz(), which replaces calling
 * ngx_http_zstd_vary_accept_encoding() then ngx_http_zstd_vary_dcz() back
 * to back at a call site that always wants both).
 *
 * This links the REAL, shipped src/ngx_http_zstd_common.h against the
 * configured nginx headers supplied to ci/tools/test_vary_fusion.sh --
 * not a hand-copied decision-logic shim. ngx_list_push()/ngx_palloc() are
 * stubbed as trivial arena allocators and ngx_strncasecmp() uses the same
 * faithful upstream copy as the parser fixture, so the test needs no full
 * nginx process, ngx_cycle or config parse: the Vary helpers only touch
 * r->headers_out.headers, r->gzip_vary and one loc_conf pointer.
 *
 * WHAT THIS PINS: the ae_dcz fusion must produce byte-identical Vary
 * header lines to calling the two original (still-shipped, still used
 * elsewhere) helpers back to back, in every combination of:
 *   - clcf->gzip_vary on vs off
 *   - want_dcz 1 vs 0 (the dcz_dicts-configured guard)
 *   - a pre-existing "Vary: Accept-Encoding" line already in
 *     headers_out.headers (the zstd_bypass_vary case) -- must still
 *     produce exactly ONE Accept-Encoding line, never two.
 *
 * At least one assertion below FAILS if the want_dcz=0 guard is
 * dropped (case_no_dcz_when_disabled): with want_dcz=0 the helper must
 * push no Available-Dictionary/Sec-Fetch-Site line even though the
 * dcz tokens are absent from the request's Vary state -- a fused
 * helper that always looks for and pushes the dcz tokens regardless of
 * the flag makes this case FAIL by producing an extra header line.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <string.h>

static int  failures = 0;
static int  checks = 0;
static int  casefold_calls = 0;

#define OK(desc, cond) \
    do { \
        checks++; \
        if (cond) { \
            printf("ok   %s\n", desc); \
        } else { \
            printf("FAIL %s\n", desc); \
            failures++; \
        } \
    } while (0)


/* ------------------------------------------------------------------- */
/* Minimal arena: ngx_palloc()/ngx_list_push() need no real ngx_pool_t  */
/* internals for this test -- only bump-pointer allocation.            */
/* ------------------------------------------------------------------- */

#define ARENA_SIZE  (1 << 20)

static u_char  arena[ARENA_SIZE];
static size_t  arena_used;

static void *
arena_alloc(size_t size)
{
    void  *p;

    /* 8-byte align, matching real ngx_palloc's small-alloc behaviour
     * closely enough for POD structs. */
    arena_used = (arena_used + 7) & ~(size_t) 7;

    if (arena_used + size > ARENA_SIZE) {
        fprintf(stderr, "test arena exhausted\n");
        abort();
    }

    p = &arena[arena_used];
    arena_used += size;

    return p;
}


void *
ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return arena_alloc(size);
}


void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {
        last = arena_alloc(sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = arena_alloc(l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}


/*
 * src/core/ngx_string.c: ngx_strncasecmp() -- faithful upstream copy,
 * identical to the one ci/fuzz/ngx_shim.h ships for the same reason:
 * linking the real ngx_string.o here pulls in ngx_cycle/ngx_alloc/
 * ngx_pnalloc from unrelated functions in that translation unit. This
 * is not the code under test (the Vary token walk is); it is the same
 * few-line primitive the parser suite already trusts a shimmed copy of.
 */
ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    casefold_calls++;

    while (n) {
        c1 = (ngx_uint_t) *s1++;
        c2 = (ngx_uint_t) *s2++;

        c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;
        c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

        if (c1 == c2) {
            if (c1) {
                n--;
                continue;
            }
            return 0;
        }

        return c1 - c2;
    }

    return 0;
}


/* Now pull in the real, shipped Vary helpers under test. */
#include "../../../src/ngx_http_zstd_common.h"


/* ------------------------------------------------------------------- */
/* Fixture plumbing                                                     */
/* ------------------------------------------------------------------- */

/*
 * ngx_http_get_module_loc_conf(r, module) expands to
 * r->loc_conf[module.ctx_index] -- only .ctx_index is ever read, so a
 * zero-initialized definition of the real extern global (declared in
 * ngx_http_core_module.h) is enough; no other field of ngx_module_t is
 * touched by anything this test exercises.
 */
ngx_module_t  ngx_http_core_module = { 0 };

static ngx_http_request_t *
make_request(ngx_flag_t gzip_vary)
{
    ngx_http_request_t       *r;
    ngx_http_core_loc_conf_t *clcf;
    void                     **loc_conf;

    r = arena_alloc(sizeof(ngx_http_request_t));
    memset(r, 0, sizeof(*r));

    clcf = arena_alloc(sizeof(ngx_http_core_loc_conf_t));
    memset(clcf, 0, sizeof(*clcf));
    clcf->gzip_vary = gzip_vary;

    loc_conf = arena_alloc(sizeof(void *) * 1);
    loc_conf[0] = clcf;
    r->loc_conf = loc_conf;

    if (ngx_list_init(&r->headers_out.headers, NULL, 8,
                       sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        abort();
    }

    return r;
}


/* Push a raw "Vary: <value>" line directly, as zstd_bypass_vary does. */
static void
push_vary_line(ngx_http_request_t *r, const char *value)
{
    ngx_table_elt_t  *v;

    v = ngx_list_push(&r->headers_out.headers);
    if (v == NULL) {
        abort();
    }

    v->hash = 1;
#if (nginx_version >= 1023000)
    v->next = NULL;
#endif
    ngx_str_set(&v->key, "Vary");
    v->value.data = (u_char *) value;
    v->value.len = ngx_strlen(value);
}


/* Collect every "Vary" line's value into one comma-joined buffer, in
 * header-list order, skipping hash==0 (deleted) lines -- mirrors what a
 * client/cache actually sees. */
static void
collect_vary(ngx_http_request_t *r, char *out, size_t out_len)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    size_t            used;

    out[0] = '\0';
    used = 0;

    for (part = &r->headers_out.headers.part, h = part->elts, i = 0;
         /* void */;
         i++)
    {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash == 0
            || h[i].key.len != sizeof("Vary") - 1
            || ngx_strncasecmp(h[i].key.data, (u_char *) "Vary",
                               sizeof("Vary") - 1) != 0)
        {
            continue;
        }

        if (used != 0 && used + 2 < out_len) {
            memcpy(out + used, "; ", 2);
            used += 2;
        }

        if (used + h[i].value.len < out_len) {
            memcpy(out + used, h[i].value.data, h[i].value.len);
            used += h[i].value.len;
            out[used] = '\0';
        }
    }
}


static int
count_token_occurrences(const char *haystack, const char *token)
{
    int          n;
    const char  *p;
    size_t       tlen;

    n = 0;
    tlen = strlen(token);
    p = haystack;

    while ((p = strstr(p, token)) != NULL) {
        n++;
        p += tlen;
    }

    return n;
}


static void
check_differential(const char *name, ngx_flag_t gzip_vary,
    ngx_uint_t want_dcz, const char *initial_vary)
{
    ngx_http_request_t  *fused, *reference;
    ngx_int_t            fused_rc, reference_rc;
    char                 fused_out[512], reference_out[512];
    int                  fused_calls, reference_calls;

    fused = make_request(gzip_vary);
    reference = make_request(gzip_vary);
    if (initial_vary != NULL) {
        push_vary_line(fused, initial_vary);
        push_vary_line(reference, initial_vary);
    }

    casefold_calls = 0;
    fused_rc = ngx_http_zstd_vary_ae_dcz(fused, want_dcz);
    fused_calls = casefold_calls;

    casefold_calls = 0;
    reference_rc = ngx_http_zstd_vary_accept_encoding(reference);
    if (reference_rc == NGX_OK && want_dcz) {
        reference_rc = ngx_http_zstd_vary_dcz(reference);
    }
    reference_calls = casefold_calls;

    collect_vary(fused, fused_out, sizeof(fused_out));
    collect_vary(reference, reference_out, sizeof(reference_out));
    OK(name, fused_rc == reference_rc
             && fused->gzip_vary == reference->gzip_vary
             && strcmp(fused_out, reference_out) == 0);
    OK("fused walk performs no extra case-fold comparisons",
       fused_calls <= reference_calls);
}


int
main(void)
{
    char  buf[512];

    check_differential("gzip_vary on matches the two-helper oracle", 1, 1,
                       "X-Existing");
    check_differential("gzip_vary on skips the unnecessary AE comparison",
                       1, 1, "123456789012345");
    check_differential("gzip_vary on with dcz disabled skips the whole walk",
                       1, 0, "123456789012345");
    check_differential("gzip_vary off matches the two-helper oracle", 0, 1,
                       "X-Existing");
    check_differential("dcz disabled matches Accept-Encoding oracle", 0, 0,
                       "X-Existing");
    check_differential("pre-existing AE matches the two-helper oracle", 0, 1,
                       "X-No-Compression, Accept-Encoding");
    check_differential("no pre-existing Vary matches the two-helper oracle",
                       0, 1, NULL);
    check_differential("pre-existing Sec-Fetch-Site matches the oracle",
                       0, 1, "Sec-Fetch-Site");
    check_differential("both dcz tokens present match the oracle", 0, 1,
                       "Available-Dictionary, Sec-Fetch-Site");
    check_differential("case-insensitive tokens match the oracle", 0, 1,
                       "accept-encoding, AVAILABLE-DICTIONARY, "
                       "sec-fetch-site");

    /* ---- gzip_vary ON, want_dcz 1, no pre-existing Vary ---- */
    {
        ngx_http_request_t  *r = make_request(1);

        OK("gzip_vary=on/want_dcz=1: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 1) == NGX_OK);
        OK("gzip_vary=on/want_dcz=1: r->gzip_vary latched",
           r->gzip_vary == 1);

        collect_vary(r, buf, sizeof(buf));
        OK("gzip_vary=on/want_dcz=1: no Accept-Encoding line pushed "
           "(nginx emits it from r->gzip_vary)",
           strstr(buf, "Accept-Encoding") == NULL);
        OK("gzip_vary=on/want_dcz=1: combined dcz line pushed",
           strstr(buf, "Available-Dictionary, Sec-Fetch-Site") != NULL);
    }

    /* ---- gzip_vary OFF, want_dcz 1, no pre-existing Vary ---- */
    {
        ngx_http_request_t  *r = make_request(0);

        OK("gzip_vary=off/want_dcz=1: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 1) == NGX_OK);

        collect_vary(r, buf, sizeof(buf));
        OK("gzip_vary=off/want_dcz=1: exactly one Accept-Encoding line",
           count_token_occurrences(buf, "Accept-Encoding") == 1);
        OK("gzip_vary=off/want_dcz=1: combined dcz line pushed",
           strstr(buf, "Available-Dictionary, Sec-Fetch-Site") != NULL);
    }

    /*
     * ---- want_dcz 0 (dcz_dicts NOT configured): the guard this whole
     * item exists to preserve. A fused helper that drops the guard and
     * always emits the dcz tokens makes this FAIL.
     * ---- */
    {
        ngx_http_request_t  *r = make_request(0);

        OK("want_dcz=0: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 0) == NGX_OK);

        collect_vary(r, buf, sizeof(buf));
        OK("want_dcz=0: Accept-Encoding line still pushed",
           strstr(buf, "Accept-Encoding") != NULL);
        OK("case_no_dcz_when_disabled: no Available-Dictionary token "
           "when want_dcz=0",
           strstr(buf, "Available-Dictionary") == NULL);
        OK("case_no_dcz_when_disabled: no Sec-Fetch-Site token "
           "when want_dcz=0",
           strstr(buf, "Sec-Fetch-Site") == NULL);
    }

    /*
     * ---- pre-existing "Vary: Accept-Encoding" (the zstd_bypass_vary
     * shape, or any upstream/operator-pushed line naming the same
     * token): must not double it.
     * ---- */
    {
        ngx_http_request_t  *r = make_request(0);

        push_vary_line(r, "X-No-Compression, Accept-Encoding");

        OK("pre-existing AE line: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 1) == NGX_OK);

        collect_vary(r, buf, sizeof(buf));
        OK("pre-existing AE line: exactly one Accept-Encoding token "
           "across all Vary lines",
           count_token_occurrences(buf, "Accept-Encoding") == 1);
        OK("pre-existing AE line: dcz tokens still pushed",
           strstr(buf, "Available-Dictionary, Sec-Fetch-Site") != NULL);
    }

    /* ---- want_dcz=1 but Available-Dictionary already present ---- */
    {
        ngx_http_request_t  *r = make_request(0);

        push_vary_line(r, "Available-Dictionary");

        OK("Available-Dictionary already present: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 1) == NGX_OK);

        collect_vary(r, buf, sizeof(buf));
        OK("Available-Dictionary already present: only Sec-Fetch-Site "
           "pushed for the dcz half, not the combined line",
           strstr(buf, "Available-Dictionary, Sec-Fetch-Site") == NULL
           && strstr(buf, "Sec-Fetch-Site") != NULL);
        OK("Available-Dictionary already present: token still appears "
           "exactly once",
           count_token_occurrences(buf, "Available-Dictionary") == 1);
    }

    /* ---- hash==0 (deleted) Vary line must be ignored, not counted ---- */
    {
        ngx_http_request_t  *r = make_request(0);

        push_vary_line(r, "Accept-Encoding");
        {
            ngx_table_elt_t  *h = r->headers_out.headers.part.elts;
            h[0].hash = 0;
        }

        OK("deleted Vary line: returns NGX_OK",
           ngx_http_zstd_vary_ae_dcz(r, 0) == NGX_OK);

        collect_vary(r, buf, sizeof(buf));
        OK("deleted Vary line: a fresh Accept-Encoding line is pushed "
           "(the deleted one does not count as present)",
           count_token_occurrences(buf, "Accept-Encoding") == 1);
    }

    printf("\n%d/%d checks passed\n", checks - failures, checks);

    return failures ? 1 : 0;
}
