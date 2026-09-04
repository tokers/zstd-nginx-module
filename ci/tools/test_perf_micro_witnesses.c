/*
 * Deterministic behavior and work-count witnesses for A33 P7/P9/P10.
 * test_perf_micro_witnesses.sh extracts the production helpers verbatim.
 */

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <time.h>

typedef unsigned char  u_char;
typedef long           ngx_int_t;
typedef unsigned long  ngx_uint_t;
typedef unsigned long  ngx_file_uniq_t;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};

typedef struct {
    ngx_list_part_t  part;
} ngx_list_t;

typedef struct {
    ngx_uint_t  hash;
    ngx_str_t   key;
    ngx_str_t   value;
} ngx_table_elt_t;

typedef struct {
    ngx_list_t  headers;
} ngx_http_headers_out_t;

typedef struct {
    ngx_http_headers_out_t  headers_out;
} ngx_http_request_t;

typedef struct {
    ngx_file_uniq_t  uniq;
    time_t           mtime;
    off_t            size;
} ngx_open_file_info_t;

#define ngx_inline  inline
#define ngx_strncasecmp(s1, s2, n)  \
    strncasecmp((const char *) (s1), (const char *) (s2), (n))

#define NGX_MAX_PATH                               256
#define NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS  64
#define NGX_HTTP_ZSTD_STATIC_VERDICT_NONE         0
#define NGX_HTTP_ZSTD_STATIC_VERDICT_BAD          1
#define NGX_HTTP_ZSTD_STATIC_VERDICT_GOOD         2

typedef struct {
    ngx_file_uniq_t  uniq;
    time_t           mtime;
    time_t           checked;
    off_t            size;
    size_t           len;
    ngx_uint_t       valid;
    u_char           path[NGX_MAX_PATH];
} ngx_http_zstd_static_verdict_cache_t;

static ngx_http_zstd_static_verdict_cache_t
    ngx_http_zstd_static_verdict_cache[
        NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS];
static ngx_uint_t  ngx_http_zstd_static_verdict_cache_next;
static ngx_uint_t  ngx_http_zstd_static_verdict_cache_count;
static ngx_uint_t  memcmp_calls;

static int
counted_memcmp(const void *a, const void *b, size_t n)
{
    memcmp_calls++;
    return memcmp(a, b, n);
}

#define ngx_memcmp  counted_memcmp
#define ngx_memcpy  memcpy

#ifdef TEST_VERDICT_CACHE_MUTANT
#include "generated_verdict_cache_work_mutant.inc"
#else
#include "generated_verdict_cache_work.inc"
#endif

#include "generated_vary_find_tokens.inc"
#include "../../src/ngx_http_zstd_cache_control.h"

static int failures;

static void
check(int condition, const char *name)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        failures++;
    }
}

static int
ascii_equal(const u_char *p, size_t len, const char *token)
{
    size_t  i;

    if (len != strlen(token)) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (tolower((unsigned char) p[i])
            != tolower((unsigned char) token[i]))
        {
            return 0;
        }
    }
    return 1;
}

/* Independent, deliberately simple Vary-list oracle for one field value. */
static void
reference_vary(const char *value, const char *a, const char *b,
    ngx_uint_t *has_a, ngx_uint_t *has_b)
{
    const u_char  *p, *last, *start, *end;

    *has_a = 0;
    *has_b = 0;
    p = (const u_char *) value;
    last = p + strlen(value);

    while (p < last) {
        while (p < last && (*p == ',' || *p == ' ' || *p == '\t')) {
            p++;
        }
        start = p;
        while (p < last && *p != ',') {
            p++;
        }
        end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        *has_a |= ascii_equal(start, (size_t) (end - start), a);
        *has_b |= ascii_equal(start, (size_t) (end - start), b);
    }
}

static void
test_vary_behavior(void)
{
    static const char *cases[] = {
        "", "gzip", "foo   , bar", "  available-dictionary\t, x",
        ",,Sec-Fetch-Site,,Available-Dictionary  ",
        "AVAILABLE-DICTIONARY, sec-fetch-site", "foo,bar   "
    };
    ngx_http_request_t  r;
    ngx_table_elt_t     h;
    ngx_uint_t          got_a, got_b, want_a, want_b;
    size_t              i;

    memset(&r, 0, sizeof(r));
    memset(&h, 0, sizeof(h));
    h.hash = 1;
    h.key.data = (u_char *) "Vary";
    h.key.len = sizeof("Vary") - 1;
    r.headers_out.headers.part.elts = &h;
    r.headers_out.headers.part.nelts = 1;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        h.value.data = (u_char *) cases[i];
        h.value.len = strlen(cases[i]);
        reference_vary(cases[i], "Available-Dictionary", "Sec-Fetch-Site",
                       &want_a, &want_b);
        ngx_http_zstd_vary_find_tokens(
            &r, "Available-Dictionary", sizeof("Available-Dictionary") - 1,
            "Sec-Fetch-Site", sizeof("Sec-Fetch-Site") - 1,
            NULL, 0, &got_a, &got_b, NULL);
        check(got_a == want_a && got_b == want_b,
              "Vary helper agrees with independent token oracle");
    }
}

static const u_char *
reference_directive_end(const u_char *p, const u_char *last,
    const u_char **name_end)
{
    int  quoted;

    *name_end = NULL;
    quoted = 0;
    while (p < last) {
        if (*p == '\\' && quoted && p + 1 < last) {
            p += 2;
            continue;
        }
        if (*p == '"') {
            quoted = !quoted;
        } else if (!quoted && *p == ',') {
            break;
        } else if (!quoted && *name_end == NULL
                   && (*p == ';' || *p == '='))
        {
            *name_end = p;
        }
        p++;
    }
    if (*name_end == NULL) {
        *name_end = p;
    }
    return p;
}

/* Independent quote-aware Cache-Control oracle. */
static int
reference_no_transform(const char *value)
{
    const u_char  *p, *last, *start, *name_end;

    p = (const u_char *) value;
    last = p + strlen(value);
    while (p < last) {
        while (p < last && (*p == ' ' || *p == '\t' || *p == ',')) {
            p++;
        }
        start = p;
        p = reference_directive_end(p, last, &name_end);
        while (name_end > start
               && (name_end[-1] == ' ' || name_end[-1] == '\t'))
        {
            name_end--;
        }
        if (ascii_equal(start, (size_t) (name_end - start), "no-transform")) {
            return 1;
        }
        if (p < last) {
            p++;
        }
    }
    return 0;
}

static void
test_cache_control_behavior(void)
{
    static const char *cases[] = {
        "", "max-age=60", "no-transform", " NO-TRANSFORM = arg",
        "extension=\"no-transform\"", "foo=\"a,b\", no-transform",
        "foo=\"a,\\\"b\", public", "no-transform; x=y", ",, private"
    };
    ngx_table_elt_t  cc;
    size_t           i;

    memset(&cc, 0, sizeof(cc));
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cc.value.data = (u_char *) cases[i];
        cc.value.len = strlen(cases[i]);
        check(ngx_http_zstd_cache_control_value_no_transform(&cc)
                  == reference_no_transform(cases[i]),
              "Cache-Control helper agrees with independent directive oracle");
    }
}

static void
fill_verdict_entry(ngx_uint_t i, const ngx_str_t *path,
    const ngx_open_file_info_t *of)
{
    ngx_http_zstd_static_verdict_cache[i].valid =
        NGX_HTTP_ZSTD_STATIC_VERDICT_BAD;
    ngx_http_zstd_static_verdict_cache[i].uniq = of->uniq;
    ngx_http_zstd_static_verdict_cache[i].mtime = of->mtime;
    ngx_http_zstd_static_verdict_cache[i].size = of->size;
    ngx_http_zstd_static_verdict_cache[i].len = path->len;
    memcpy(ngx_http_zstd_static_verdict_cache[i].path, "other", path->len);
}

static void
test_verdict_cache_work_count(void)
{
    ngx_open_file_info_t  of;
    ngx_str_t             path;
    ngx_uint_t            i;

    memset(ngx_http_zstd_static_verdict_cache, 0,
           sizeof(ngx_http_zstd_static_verdict_cache));
    path.data = (u_char *) "target";
    path.len = sizeof("target") - 1;
    of.uniq = 7;
    of.mtime = 11;
    of.size = 13;

    /* Poison every slot beyond count. A count-bounded implementation must
     * not inspect them; the former fixed-64 walk makes 64 memcmp calls. */
    for (i = 0; i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS; i++) {
        fill_verdict_entry(i, &path, &of);
    }
    ngx_http_zstd_static_verdict_cache_count = 0;
    memcmp_calls = 0;
    check(ngx_http_zstd_static_cached_verdict(&path, &of, 100, 60)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "empty verdict cache misses");
    check(memcmp_calls == 0, "empty verdict cache inspects zero slots");

    ngx_http_zstd_static_verdict_cache_count = 3;
    memcmp_calls = 0;
    check(ngx_http_zstd_static_cached_verdict(&path, &of, 100, 60)
              == NGX_HTTP_ZSTD_STATIC_VERDICT_NONE,
          "partially populated verdict cache misses");
    check(memcmp_calls == 3,
          "partial verdict cache inspects only populated slots");

    memset(ngx_http_zstd_static_verdict_cache, 0,
           sizeof(ngx_http_zstd_static_verdict_cache));
    ngx_http_zstd_static_verdict_cache_count = 0;
    ngx_http_zstd_static_verdict_cache_next = 0;
    for (i = 0; i < NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS + 2; i++) {
        ngx_http_zstd_static_remember(&path, &of,
            NGX_HTTP_ZSTD_STATIC_VERDICT_BAD, 100, 60);
    }
    check(ngx_http_zstd_static_verdict_cache_count
              == NGX_HTTP_ZSTD_STATIC_VERDICT_CACHE_SLOTS,
          "remember count saturates at the ring bound");
    check(ngx_http_zstd_static_verdict_cache_next == 2,
          "remember cursor wraps independently of populated count");
}

int
main(void)
{
    test_vary_behavior();
    test_cache_control_behavior();
    test_verdict_cache_work_count();

    if (failures != 0) {
        fprintf(stderr, "FAILED: %d performance witness check(s)\n", failures);
        return 1;
    }
    puts("OK: production helpers match references and bounded-work witnesses");
    return 0;
}
