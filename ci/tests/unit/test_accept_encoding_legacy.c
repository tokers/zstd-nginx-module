/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * nginx 1.22.1-shaped regression checks.  Its ngx_table_elt_t has no next
 * member; repeated request headers remain in headers_in.headers.
 *
 * This TU is compiled twice by ci/tests/unit/run.sh: once with
 * -DNGX_ZSTD_LEGACY_SHIM (the pre-1.23.0 shape, exercising the #else branch
 * of ngx_http_zstd_request_coding_weight() that walks headers_in.headers),
 * and once without it (the >= 1.23.0 shape, exercising the ->next chain via
 * ngx_http_zstd_chain_coding_weight()). Every case below therefore runs
 * under both branches and must agree -- branch-equivalence is the oracle
 * for A30-F1 ("repeated Accept-Encoding fields must not be dropped on
 * old-nginx"), since a real second implementation of RFC 9110 comma-joining
 * does not exist to diff against.
 */
#include "../../fuzz/ngx_shim.h"

#define NGX_HTTP_ZSTD_TEST_COUNT_CODING_WEIGHT
static ngx_uint_t  ngx_http_zstd_test_coding_weight_calls;

#include "../../fuzz/generated_parser.inc"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HEADERS 8

static int failures;
static int checks;

static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
    } else {
        printf("FAIL %s\n", what);
        failures++;
    }
}

/*
 * Build a headers_in.headers list from `n` (name, value) pairs and decide
 * ngx_http_zstd_accepts() over it. A NULL name defaults to "Accept-Encoding"
 * -- pass an explicit non-AE name to interleave an unrelated header, or a
 * case-varied spelling ("accept-encoding" / "ACCEPT-ENCODING") to prove the
 * match is case-insensitive (ngx_strncasecmp, matching upstream).
 */
static ngx_int_t
request_decide_named(const char *names[], const char *values[], size_t n)
{
    ngx_table_elt_t     headers[MAX_HEADERS];
    ngx_http_request_t  r;
    size_t               i;
#if !defined(NGX_ZSTD_LEGACY_SHIM)
    ngx_table_elt_t     *first_ae = NULL;
    ngx_table_elt_t     *prev_ae = NULL;
#endif

    if (n > MAX_HEADERS) {
        /*
         * A fixture bug, not a parser result: silently truncating would let
         * a future over-sized table test fewer headers than the case
         * claims and still report a pass. Fail loudly instead.
         */
        fprintf(stderr, "test fixture error: %zu headers exceeds "
                "MAX_HEADERS (%d)\n", n, MAX_HEADERS);
        abort();
    }

    memset(&r, 0, sizeof(r));
    memset(headers, 0, sizeof(headers));

    for (i = 0; i < n; i++) {
        const char *name = names[i] ? names[i] : "Accept-Encoding";

        headers[i].key.data = (u_char *) name;
        headers[i].key.len = strlen(name);
        headers[i].value.data = (u_char *) values[i];
        headers[i].value.len = strlen(values[i]);

#if !defined(NGX_ZSTD_LEGACY_SHIM)
        headers[i].next = NULL;

        if (headers[i].key.len == sizeof("Accept-Encoding") - 1
            && ngx_strncasecmp(headers[i].key.data,
                                (u_char *) "Accept-Encoding",
                                sizeof("Accept-Encoding") - 1) == 0)
        {
            if (first_ae == NULL) {
                first_ae = &headers[i];
            } else {
                prev_ae->next = &headers[i];
            }
            prev_ae = &headers[i];
        }
#endif
    }

    r.main = &r;
#if !defined(NGX_ZSTD_LEGACY_SHIM)
    r.headers_in.accept_encoding = first_ae;
#endif
    r.headers_in.headers.part.elts = headers;
    r.headers_in.headers.part.nelts = n;
    r.headers_in.headers.part.next = NULL;

    return ngx_http_zstd_accepts(&r);
}

static ngx_int_t
request_decide(const char *first, const char *second)
{
    const char *names[2]  = { NULL, NULL };
    const char *values[2] = { first, second };

    return request_decide_named(names, values, 2);
}

int
main(void)
{
    ngx_http_zstd_test_coding_weight_calls = 0;
    check(request_decide("gzip", "br") == NGX_DECLINED,
          "two non-matching fields decline");
    check(ngx_http_zstd_test_coding_weight_calls == 2,
          "each field is parsed exactly once");

    check(request_decide("gzip", "zstd") == NGX_OK,
          "legacy list: gzip then zstd accepts");
    check(request_decide("*", "zstd;q=0") == NGX_DECLINED,
          "legacy list: explicit zstd;q=0 overrides wildcard");
    check(request_decide("zstd;q=0", "zstd;q=1") == NGX_OK,
          "later explicit zstd allowance wins");
    check(request_decide("zstd;q=1", "zstd;q=0") == NGX_DECLINED,
          "later explicit zstd refusal wins");

    /* A30-F1: reversed order of the named case. */
    check(request_decide("zstd;q=0", "*") == NGX_DECLINED,
          "A30-F1 reversed: explicit zstd;q=0 first, wildcard second, still declines");

    /* A30-F1: partial q rather than exact zero. */
    check(request_decide("zstd;q=0.5", "zstd;q=0") == NGX_DECLINED,
          "A30-F1: zstd;q=0.5 then zstd;q=0 -- later explicit weight wins, declines");
    check(request_decide("zstd;q=0", "zstd;q=0.5") == NGX_OK,
          "A30-F1: zstd;q=0 then zstd;q=0.5 -- later explicit weight wins, accepts");

    /* Wildcard only, no explicit token anywhere. */
    check(request_decide("*", "gzip") == NGX_OK,
          "A30-F1: wildcard-only field (no explicit zstd token) accepts via '*'");

    /* Explicit token only, no wildcard anywhere. */
    check(request_decide("zstd", "gzip") == NGX_OK,
          "A30-F1: explicit-token-only field accepts, no wildcard involved");

    /* Three occurrences. */
    {
        const char *names3[3]  = { NULL, NULL, NULL };
        const char *values3[3] = { "*", "gzip", "zstd;q=0" };

        check(request_decide_named(names3, values3, 3) == NGX_DECLINED,
              "A30-F1: three occurrences, explicit zstd;q=0 last overrides "
              "earlier wildcard");
    }

    /* Four occurrences, zstd only on the last one. */
    {
        const char *names4[4]  = { NULL, NULL, NULL, NULL };
        const char *values4[4] = { "gzip", "br", "identity", "zstd" };

        check(request_decide_named(names4, values4, 4) == NGX_OK,
              "A30-F1: four occurrences, explicit zstd on the fourth accepts");
    }

    /* An occurrence with an empty value interleaved. */
    {
        const char *namesE[3]  = { NULL, NULL, NULL };
        const char *valuesE[3] = { "", "zstd;q=0", "*" };

        check(request_decide_named(namesE, valuesE, 3) == NGX_DECLINED,
              "A30-F1: empty-value occurrence contributes nothing; explicit "
              "zstd;q=0 still overrides the later wildcard");
    }

    /* A non-Accept-Encoding header interleaved between two AE occurrences. */
    {
        const char *namesX[3]  = { NULL, "X-Requested-With", NULL };
        const char *valuesX[3] = { "*", "XMLHttpRequest", "zstd;q=0" };

        check(request_decide_named(namesX, valuesX, 3) == NGX_DECLINED,
              "A30-F1: named case with an unrelated header interleaved "
              "between the two Accept-Encoding lines still declines");
    }

    /* Case-varied header names must still be recognised as Accept-Encoding. */
    {
        const char *namesC[2]  = { "accept-encoding", "ACCEPT-ENCODING" };
        const char *valuesC[2] = { "*", "zstd;q=0" };

        check(request_decide_named(namesC, valuesC, 2) == NGX_DECLINED,
              "A30-F1: case-varied header names ('accept-encoding' / "
              "'ACCEPT-ENCODING') still match and the named case declines");
    }

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
