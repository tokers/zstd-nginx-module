/*
 * Differential fixture for ngx_http_zstd_dcz_dict_lookup() -- A33-P4.
 *
 * ngx_http_zstd_dcz_dict_lookup() switches from a linear ngx_memcmp scan
 * to a binary search over a hash-sorted array once the configured
 * dictionary count exceeds NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD. This
 * fixture asserts the extracted, CURRENT shipped implementation (see
 * test_dcz_dict_lookup_unit.sh for the extraction) returns identical
 * results to a naive, always-correct brute-force linear scan, for every
 * array size in {1, threshold, threshold+1, 64, 256, 737} and for:
 *
 *   - a HIT on the first, middle and last element (post-sort position);
 *   - a MISS with a key that would sort before the first entry;
 *   - a MISS with a key that would sort after the last entry;
 *   - a MISS with a key that would sort in the middle (no entry matches).
 *
 * A deliberately broken comparator is used to prove this fixture is
 * ARMED -- see main(): it must make at least one above-threshold lookup
 * diverge (because ngx_http_zstd_dcz_dict_lookup()'s
 * bsearch branch is sorted with the same comparator used to search, a
 * broken order produces wrong verdicts for any input that requires
 * following the correct direction past the first probe).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uintptr_t      ngx_uint_t;
typedef intptr_t       ngx_int_t;
typedef unsigned char  u_char;
typedef struct {
    void        *elts;
    ngx_uint_t   nelts;
    size_t       size;
    ngx_uint_t   nalloc;
    void        *pool;
} ngx_array_t;

typedef struct {
    unsigned char  *data;
    size_t          len;
} ngx_str_t;

#define ngx_memcmp(s1, s2, n)  memcmp(s1, s2, n)
#define ngx_qsort               qsort
#define ngx_libc_cdecl

#include "generated_dcz_dict_lookup.inc"

#define HLEN  NGX_HTTP_ZSTD_SHA256_DIGEST_LEN

static int checks_run = 0;
static int checks_failed = 0;
static int quiet_failures = 0;

#define CHECK(cond, msg)                                              \
    do {                                                               \
        checks_run++;                                                  \
        if (!(cond)) {                                                 \
            checks_failed++;                                           \
            if (!quiet_failures) {                                      \
                fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__,   \
                        __LINE__);                                      \
            }                                                          \
        }                                                               \
    } while (0)

/* Reference oracle: brute-force linear scan, independent of the sort
 * order or the threshold, always correct by construction. */
static ngx_http_zstd_dcz_dict_t *
ref_lookup(ngx_http_zstd_dcz_dict_t *dicts, ngx_uint_t n,
    const unsigned char *key)
{
    ngx_uint_t  i;

    for (i = 0; i < n; i++) {
        if (memcmp(dicts[i].hash, key, HLEN) == 0) {
            return &dicts[i];
        }
    }

    return NULL;
}

static void
fill_unique_sorted(ngx_http_zstd_dcz_dict_t *dicts, ngx_uint_t n,
    unsigned seed)
{
    ngx_uint_t  i;
    size_t      j;

    /* Fill with deterministic varied bytes, then force strict ordering
     * by writing the index into the leading bytes big-endian. This
     * guarantees n distinct, strictly increasing 32-byte keys; the real
     * merge-time duplicate-hash rejection guarantees the same invariant
     * on dcz_dicts. */
    for (i = 0; i < n; i++) {
        for (j = 0; j < HLEN; j++) {
            dicts[i].hash[j] = (unsigned char)
                               ((seed + i * 131u + j * 17u) & 0xffu);
        }

        dicts[i].hash[0] = (unsigned char) ((i >> 24) & 0xff);
        dicts[i].hash[1] = (unsigned char) ((i >> 16) & 0xff);
        dicts[i].hash[2] = (unsigned char) ((i >> 8) & 0xff);
        dicts[i].hash[3] = (unsigned char) (i & 0xff);
        /* leave hash[4] at 0x01 so index 0's key never collides with
         * the all-zero "before first" miss key below */
        dicts[i].hash[4] = 0x01;

        dicts[i].file.len = 0;
        dicts[i].file.data = NULL;
    }
}

static void
reverse_dicts(ngx_http_zstd_dcz_dict_t *dicts, ngx_uint_t n)
{
    ngx_http_zstd_dcz_dict_t  tmp;
    ngx_uint_t                 i;

    for (i = 0; i < n / 2; i++) {
        tmp = dicts[i];
        dicts[i] = dicts[n - i - 1];
        dicts[n - i - 1] = tmp;
    }
}

/* Runs the differential check for one array size n, using `cmp` (the
 * real comparator, or a deliberately broken one) to sort. Returns 1 if
 * every sub-case matched the oracle, 0 if any diverged. */
static int
run_size(ngx_uint_t n, int (*cmp)(const void *, const void *))
{
    ngx_http_zstd_dcz_dict_t  *dicts;
    ngx_array_t                arr;
    unsigned char               key[HLEN];
    ngx_http_zstd_dcz_dict_t  *got, *want;
    int                         ok;
    ngx_uint_t                  before;

    dicts = calloc(n, sizeof(*dicts));
    if (dicts == NULL) {
        fprintf(stderr, "calloc failed for n=%lu\n", (unsigned long) n);
        exit(1);
    }

    fill_unique_sorted(dicts, n, 0xC0FFEEu + (unsigned) n);
    arr.elts = dicts;
    arr.nelts = n;
    arr.size = sizeof(*dicts);
    arr.nalloc = n;
    arr.pool = NULL;

    if (cmp == ngx_http_zstd_dcz_dict_cmp) {
        /* Exercise the production wrapper with deliberately wrong input
         * order. Feeding it fill_unique_sorted()'s original ascending
         * order would let a no-op sort implementation remain green. */
        reverse_dicts(dicts, n);
        ngx_http_zstd_dcz_dict_sort(&arr);
    } else {
        qsort(dicts, n, sizeof(*dicts), cmp);
    }

    ok = 1;
    before = checks_failed;

    /* HIT: first, middle, last (post-sort positions). */
    memcpy(key, dicts[0].hash, HLEN);
    got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
    want = ref_lookup(dicts, n, key);
    CHECK(got == want, "HIT(first) diverges from oracle");

    memcpy(key, dicts[n / 2].hash, HLEN);
    got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
    want = ref_lookup(dicts, n, key);
    CHECK(got == want, "HIT(mid) diverges from oracle");

    memcpy(key, dicts[n - 1].hash, HLEN);
    got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
    want = ref_lookup(dicts, n, key);
    CHECK(got == want, "HIT(last) diverges from oracle");

    /* MISS: sorts before the first entry (all-zero hash; index 0's
     * hash[4] is forced to 0x01, so index 0 never equals this key). */
    memset(key, 0x00, HLEN);
    got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
    want = ref_lookup(dicts, n, key);
    CHECK(got == want && got == NULL,
          "MISS(<first) diverges from oracle or unexpectedly hit");

    /* MISS: sorts after the last entry. */
    memset(key, 0xff, HLEN);
    got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
    want = ref_lookup(dicts, n, key);
    CHECK(got == want && got == NULL,
          "MISS(>last) diverges from oracle or unexpectedly hit");

    /* MISS: a key that sorts in the middle of the range but matches
     * nothing -- take the middle element's key and flip a trailing
     * byte that fill_unique_sorted() populated (not the forced index
     * prefix), so it lands near the middle in sort order without
     * colliding with any real entry. */
    if (n > 0) {
        memcpy(key, dicts[n / 2].hash, HLEN);
        key[HLEN - 1] ^= 0xff;
        got = ngx_http_zstd_dcz_dict_lookup(&arr, key);
        want = ref_lookup(dicts, n, key);
        CHECK(got == want, "MISS(mid) diverges from oracle");
    }

    if ((ngx_uint_t) checks_failed != before) {
        ok = 0;
    }

    free(dicts);
    return ok;
}

static int
run_all(int (*cmp)(const void *, const void *))
{
    static const ngx_uint_t sizes[] = {
        1,
        NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD,
        NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD + 1,
        64,
        256,
        737
    };
    ngx_uint_t  i;
    int         all_ok;

    all_ok = 1;

    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        if (!run_size(sizes[i], cmp)) {
            all_ok = 0;
        }
    }

    return all_ok;
}

/* Deliberately broken comparator: inverted sign, so qsort() produces
 * descending order while ngx_http_zstd_dcz_dict_lookup()'s bsearch
 * branch still assumes ascending order. Used only to prove the fixture
 * is armed (main() below). */
static int
broken_cmp(const void *one, const void *two)
{
    return -ngx_http_zstd_dcz_dict_cmp(one, two);
}

int
main(void)
{
    int  real_ok;

    real_ok = run_all(ngx_http_zstd_dcz_dict_cmp);

    if (!real_ok) {
        fprintf(stderr,
                "%d/%d checks failed against the REAL comparator "
                "(should be 0)\n",
                checks_failed, checks_run);
        return 1;
    }

    printf("%d/%d checks passed against the real comparator\n",
           checks_run - checks_failed, checks_run);

    /* Armed proof: re-run with a broken comparator and require at
     * least one divergence above the threshold (bsearch relies on
     * ascending order; a linear scan below the threshold does not sort
     * at all, so small n cannot be expected to fail here -- the armed
     * assertion targets sizes that exercise the bsearch branch). */
    {
        int  checks_before, failed_before;

        checks_before = checks_run;
        failed_before = checks_failed;

        quiet_failures = 1;
        run_size(NGX_HTTP_ZSTD_DCZ_BSEARCH_THRESHOLD + 1, broken_cmp);
        run_size(256, broken_cmp);
        run_size(737, broken_cmp);
        quiet_failures = 0;

        if (checks_failed == failed_before) {
            fprintf(stderr,
                    "FAIL: fixture is NOT armed -- broken comparator "
                    "produced zero divergences (checks_run %d->%d)\n",
                    checks_before, checks_run);
            return 1;
        }

        printf("armed: broken comparator produced %d divergent "
               "check(s) as expected\n",
               checks_failed - failed_before);
    }

    printf("OK: dcz dict lookup fixture\n");
    return 0;
}
