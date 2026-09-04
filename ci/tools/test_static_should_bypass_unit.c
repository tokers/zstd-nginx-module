/*
 * Unit fixture for ngx_http_zstd_static_should_bypass() (A33-F3).
 *
 * The routine is `static` inside ngx_http_zstd_static_module.c, so
 * test_static_should_bypass_unit.sh extracts it VERBATIM by line range and
 * #includes it here. Extraction, not duplication: a hand-copied body would
 * drift from the shipped code and keep passing while the real predicate
 * regressed.
 *
 * What is under test: the predicate must detect a second
 * Available-Dictionary request header and stand aside only when exactly one
 * is present. The
 * dynamic filter refuses dcz outright on duplicates
 * (avail_dict_count > 1 in ngx_http_zstd_filter_module.c), so a static
 * routing predicate that bypassed on the first line would hand a
 * duplicate-header request to a filter that then declines, forfeiting a
 * usable .zst sidecar for identity.
 *
 * Only the header list walk and the count are exercised. The dcz
 * coding-weight lookup is stubbed, because Accept-Encoding parsing is
 * covered by its own fixtures; here it is a controlled input.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/* --- minimal nginx surface the extracted function touches --- */

typedef unsigned char   u_char;
typedef unsigned long   ngx_uint_t;

typedef struct {
    size_t    len;
    u_char   *data;
} ngx_str_t;

typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts;
    ngx_uint_t        nelts;
    ngx_list_part_t  *next;
};

typedef struct {
    ngx_list_part_t   part;
} ngx_list_t;

typedef struct {
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;

typedef struct {
    ngx_list_t        headers;
} ngx_http_headers_in_t;

typedef struct {
    ngx_http_headers_in_t  headers_in;
} ngx_http_request_t;

static int  stub_memcmp_calls;
static int  stub_strncasecmp_calls;

static int
stub_memcmp(const void *s1, const void *s2, size_t n)
{
    stub_memcmp_calls++;
    return memcmp(s1, s2, n);
}

static int
stub_strncasecmp(const u_char *s1, const u_char *s2, size_t n)
{
    stub_strncasecmp_calls++;
    return strncasecmp((const char *) s1, (const char *) s2, n);
}

#define ngx_strncasecmp(s1, s2, n)  stub_strncasecmp((s1), (s2), (n))
#define ngx_memcmp(s1, s2, n)       stub_memcmp((s1), (s2), (n))

/* Stubbed: what the dcz coding weight would report. Set per test case. */
static ngx_uint_t   stub_dcz_weight;
static int          stub_weight_calls;
static int          stub_supply_lowcase = 1;

static ngx_uint_t
ngx_http_zstd_request_coding_weight(ngx_http_request_t *r, const char *coding,
    size_t len, ngx_uint_t allow_star)
{
    (void) r; (void) coding; (void) len; (void) allow_star;
    stub_weight_calls++;
    return stub_dcz_weight;
}

/* --- the code under test, extracted verbatim from the module --- */

#include "generated_static_should_bypass.inc"

/* --- harness --- */

static int failures;

static void
check(const char *name, ngx_uint_t got, ngx_uint_t want)
{
    if (got == want) {
        printf("ok   %-58s (got %lu)\n", name, (unsigned long) got);
    } else {
        printf("FAIL %-58s got %lu, want %lu\n", name,
               (unsigned long) got, (unsigned long) want);
        failures++;
    }
}

/* Fills `all` with `total` headers: the FIRST Available-Dictionary at index 0
 * and any remaining ones at the tail, with unrelated headers between.
 *
 * That spread is deliberate. A walk that stops at the first match sees index 0
 * and never reaches the tail entries, so a duplicate case can only pass if the
 * duplicate was detected. Split across several list parts, the tail entry
 * also lands in a non-first part, exercising the part-chaining advance. */
static void
fill_headers(ngx_table_elt_t *all, ngx_uint_t total, ngx_uint_t n_avail,
    ngx_uint_t n_noise)
{
    ngx_uint_t   i, first_tail = n_noise + (n_avail > 0 ? 1 : 0);

    for (i = 0; i < total; i++) {
        if ((n_avail > 0 && i == 0) || i >= first_tail) {
            all[i].key.data = (u_char *) "Available-Dictionary";
            all[i].key.len = sizeof("Available-Dictionary") - 1;
            all[i].lowcase_key = stub_supply_lowcase
                                     ? (u_char *) "available-dictionary"
                                     : NULL;

        } else {
            all[i].key.data = (u_char *) "Accept";
            all[i].key.len = sizeof("Accept") - 1;
            all[i].lowcase_key = stub_supply_lowcase
                                     ? (u_char *) "accept"
                                     : NULL;
        }
    }
}


/* Splits `total` headers across `parts` ngx_list_part_t links, so the walk's
 * part-advance path is exercised rather than only the first part. */
static void
chain_parts(ngx_list_part_t *chain, ngx_table_elt_t *all, ngx_uint_t total,
    ngx_uint_t parts)
{
    ngx_uint_t   p, off = 0, per = (total + parts - 1) / parts;

    if (per == 0) {
        per = 1;
    }

    for (p = 0; p < parts; p++) {
        ngx_uint_t take = (total - off > per) ? per : (total - off);

        chain[p].elts = all + off;
        chain[p].nelts = take;
        chain[p].next = NULL;
        off += take;

        if (off >= total) {
            break;
        }

        chain[p].next = &chain[p + 1];
    }
}


static void *
xcalloc(size_t n, size_t size)
{
    void   *p = calloc(n ? n : 1, size);

    if (p == NULL) {
        fprintf(stderr, "calloc failed\n");
        exit(2);
    }

    return p;
}


/* Builds a request carrying `n_avail` Available-Dictionary headers plus
 * `n_noise` unrelated ones, spread over `parts` list parts, and runs the
 * predicate against it with the dcz coding weight stubbed to `weight`. */
static ngx_uint_t
run_case(ngx_uint_t n_avail, ngx_uint_t n_noise, ngx_uint_t parts,
    ngx_uint_t weight)
{
    ngx_http_request_t   r;
    ngx_table_elt_t     *all;
    ngx_list_part_t     *chain;
    ngx_uint_t           total = n_avail + n_noise;
    ngx_uint_t           result;

    memset(&r, 0, sizeof(r));
    stub_dcz_weight = weight;
    stub_weight_calls = 0;
    stub_memcmp_calls = 0;
    stub_strncasecmp_calls = 0;

    if (parts < 1) {
        parts = 1;
    }

    all = xcalloc(total, sizeof(ngx_table_elt_t));
    chain = xcalloc(parts, sizeof(ngx_list_part_t));

    fill_headers(all, total, n_avail, n_noise);
    chain_parts(chain, all, total, parts);

    r.headers_in.headers.part = chain[0];

    result = ngx_http_zstd_static_should_bypass(&r);
    free(chain);
    free(all);

    return result;
}


static ngx_uint_t
run_case_without_lowcase(ngx_uint_t n_avail, ngx_uint_t n_noise,
    ngx_uint_t parts, ngx_uint_t weight)
{
    ngx_uint_t  result;

    stub_supply_lowcase = 0;
    result = run_case(n_avail, n_noise, parts, weight);
    stub_supply_lowcase = 1;

    return result;
}

int
main(void)
{
    printf("ngx_http_zstd_static_should_bypass() -- A33-F3 duplicate "
           "Available-Dictionary\n\n");

    /* The finding: two lines must NOT bypass. This is the assertion that
     * goes red if the predicate returns on the first match again. */
    check("2 Available-Dictionary, weight>0 -> no bypass",
          run_case(2, 0, 1, 1), 0);
    check("3 Available-Dictionary, weight>0 -> no bypass",
          run_case(3, 0, 1, 1), 0);
    check("2 Available-Dictionary among noise -> no bypass",
          run_case(2, 4, 1, 1), 0);
    check("2 Available-Dictionary across list parts -> no bypass",
          run_case(2, 4, 3, 1), 0);

    /* Unchanged behaviour: exactly one line still defers to the weight. */
    check("1 Available-Dictionary, weight>0 -> bypass",
          run_case(1, 0, 1, 1), 1);
    check("1 Available-Dictionary among noise -> bypass",
          run_case(1, 5, 1, 1), 1);
    check("1 Available-Dictionary across list parts -> bypass",
          run_case(1, 5, 3, 1), 1);
    check("1 Available-Dictionary, weight==0 -> no bypass",
          run_case(1, 0, 1, 0), 0);

    /* Module-inserted headers may omit lowcase_key; the mixed-case original
     * key must retain the same case-insensitive behavior on that path. */
    check("1 Available-Dictionary, NULL lowcase key -> bypass",
          run_case_without_lowcase(1, 2, 2, 1), 1);
    check("2 Available-Dictionary, NULL lowcase keys -> no bypass",
          run_case_without_lowcase(2, 2, 2, 1), 0);
    check("NULL lowcase path does not use memcmp",
          (ngx_uint_t) stub_memcmp_calls, 0);
    check("NULL lowcase path uses case folding",
          (ngx_uint_t) stub_strncasecmp_calls, 2);

    check("1 populated lowcase key still bypasses",
          run_case(1, 2, 2, 1), 1);
    check("populated lowcase path uses memcmp",
          (ngx_uint_t) stub_memcmp_calls, 1);
    check("populated lowcase path skips case folding",
          (ngx_uint_t) stub_strncasecmp_calls, 0);

    /* No header at all: nothing to serve dcz for. */
    check("0 Available-Dictionary -> no bypass", run_case(0, 3, 1, 1), 0);
    check("empty header list -> no bypass", run_case(0, 0, 1, 1), 0);

    /* The weight lookup must not run when the count disqualifies the
     * request; otherwise "fail closed" would still be paying for parsing
     * and, worse, a future refactor could let the weight decide. */
    (void) run_case(2, 0, 1, 1);
    check("weight not consulted when duplicates present",
          (ngx_uint_t) stub_weight_calls, 0);

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
