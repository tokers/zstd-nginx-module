/*
 * Unit fixture for ngx_http_zstd_sha256.h — issue #100 item 3.
 *
 * Compiled twice by tools/test_sha256_unit.sh against the shim headers
 * in tools/sha256-unit/ (no nginx tree, no OpenSSL needed):
 *
 *   1. Portable build (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO undefined): the
 *      local SHA-256 against NIST FIPS 180-4 vectors, plus
 *      incremental-vs-one-shot equivalence at block-boundary split
 *      sizes (the update() partial-block paths).
 *
 *   2. EVP-fallback build (-DNGX_HTTP_ZSTD_HAVE_LIBCRYPTO=1): the
 *      <openssl/evp.h> include resolves to the FAKE header in the shim
 *      directory, and this file supplies EVP_Digest()/EVP_sha256()
 *      implementations with scripted behaviour. Exercises the wrapper's
 *      three paths deterministically: EVP failure after a PARTIAL
 *      digest write (the fallback must overwrite all 32 bytes with the
 *      correct value), EVP "success" with a wrong output length (the
 *      mdlen guard must reject it and fall back), and EVP success
 *      (whose scripted digest must be returned verbatim, proving the
 *      EVP path is actually taken).
 */

#include <stdio.h>
#include <stdlib.h>

#include "../../src/ngx_http_zstd_sha256.h"

static int failures = 0;

/* TAP-style assertion: print ok/FAIL for `name` and count failures for
   the process exit code; `detail` (may be NULL) is appended to
   failures to aid diagnosis. */
static void
check(const char *name, int cond, const char *detail)
{
    if (cond) {
        printf("ok - %s\n", name);
    } else {
        printf("FAIL - %s %s\n", name, detail ? detail : "");
        failures++;
    }
}

/* Render a 32-byte digest as 64 lowercase hex characters plus NUL, for
   comparison against the published vector strings. */
static void
to_hex(const u_char digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN], char out[65])
{
    static const char  hex[] = "0123456789abcdef";
    int                i;

    for (i = 0; i < NGX_HTTP_ZSTD_SHA256_DIGEST_LEN; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
}


#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)

/*
 * Scripted fake EVP. Modes 0/1/2 fail init/update/final, mode 3 reports a
 * wrong digest length, and mode 4 succeeds.
 */
static int  fake_evp_mode;
static int  fake_evp_calls;
static unsigned char fake_evp_ctx;

/* Fake EVP_sha256(): an opaque non-NULL token — the wrapper under test
   only passes it through, never dereferences it. */
const EVP_MD *
EVP_sha256(void)
{
    return (const EVP_MD *) "fake-sha256";
}

int
EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    (void) ctx;
    (void) type;
    (void) impl;
    fake_evp_calls++;
    return fake_evp_mode != 0;
}

int
EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    (void) ctx;
    (void) data;
    (void) count;
    fake_evp_calls++;
    return fake_evp_mode != 1;
}

int
EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    (void) ctx;
    fake_evp_calls++;
    if (fake_evp_mode == 2) {
        memset(md, 0x5a, 17);
        return 0;
    }
    if (fake_evp_mode == 3) {
        memset(md, 0x5a, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
        *size = 16;
        return 1;
    }
    memset(md, 0xaa, NGX_HTTP_ZSTD_SHA256_DIGEST_LEN);
    *size = NGX_HTTP_ZSTD_SHA256_DIGEST_LEN;
    return 1;
}

/* EVP-fallback build: drive the wrapper through the three scripted EVP
   behaviours and assert the digest that comes out of each. */
int
main(void)
{
    u_char  digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    char    hexdigest[65];
    int     i, all_aa;

    static const char  abc[] = "abc";
    static const char  abc_hex[] =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    fake_evp_calls = 0;
    memset(digest, 0, sizeof(digest));
    ngx_http_zstd_sha256((const u_char *) abc, 3, digest, NULL);
    to_hex(digest, hexdigest);
    check("missing cycle EVP context falls back to portable SHA-256",
          strcmp(hexdigest, abc_hex) == 0, hexdigest);
    check("missing cycle EVP context makes no EVP calls",
          fake_evp_calls == 0, NULL);

    for (fake_evp_mode = 0; fake_evp_mode < 4; fake_evp_mode++) {
        fake_evp_calls = 0;
        memset(digest, 0, sizeof(digest));
        ngx_http_zstd_sha256((const u_char *) abc, 3, digest,
                             (EVP_MD_CTX *) &fake_evp_ctx);
        to_hex(digest, hexdigest);
        check("EVP failure falls back to the portable implementation",
              strcmp(hexdigest, abc_hex) == 0, hexdigest);
        check("fallback consulted the expected EVP stages",
              fake_evp_calls == (fake_evp_mode < 3 ? fake_evp_mode + 1 : 3),
              NULL);
    }

    /* Mode 2: scripted success -> the EVP digest is used verbatim,
       proving the accelerated path is actually taken on success. */
    fake_evp_mode = 4;
    memset(digest, 0, sizeof(digest));
    ngx_http_zstd_sha256((const u_char *) abc, 3, digest,
                         (EVP_MD_CTX *) &fake_evp_ctx);
    all_aa = 1;
    for (i = 0; i < NGX_HTTP_ZSTD_SHA256_DIGEST_LEN; i++) {
        if (digest[i] != 0xaa) {
            all_aa = 0;
        }
    }
    check("successful EVP digest is returned verbatim", all_aa, NULL);

    if (failures) {
        printf("FAILED: %d EVP-fallback check(s)\n", failures);
        return 1;
    }

    printf("OK: EVP failure-injection fixture\n");
    return 0;
}

#else /* portable build */

typedef struct {
    const char  *input;
    size_t       len;
    const char  *hex;
} sha256_vector_t;

/* NIST FIPS 180-4 / SHA-2 test vectors. */
static const sha256_vector_t  vectors[] = {
    { "", 0,
      "e3b0c44298fc1c149afbf4c8996fb924"
      "27ae41e4649b934ca495991b7852b855" },
    { "abc", 3,
      "ba7816bf8f01cfea414140de5dae2223"
      "b00361a396177a9cb410ff61f20015ad" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
      "248d6a61d20638b8e5c026930c3e6039"
      "a33ce45964ff2167f6ecedd419db06c1" },
};

/* Portable build: the local SHA-256 against the published vectors,
   then incremental-vs-one-shot equivalence at block-boundary splits. */
int
main(void)
{
    u_char                    digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    u_char                    ref[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN];
    char                      hexdigest[65];
    char                      name[128];
    size_t                    i, off, n;
    u_char                   *buf;
    uint32_t                  lcg;
    ngx_http_zstd_sha256_t    c;

    static const size_t       buf_len = 100000;
    static const size_t       splits[] = { 1, 7, 63, 64, 65, 4096 };

    /* One-shot API against the published vectors. */
    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        ngx_http_zstd_sha256((const u_char *) vectors[i].input,
                             vectors[i].len, digest, NULL);
        to_hex(digest, hexdigest);
        snprintf(name, sizeof(name), "NIST vector (%zu bytes)",
                 vectors[i].len);
        check(name, strcmp(hexdigest, vectors[i].hex) == 0, hexdigest);
    }

    /* Remainder 55 mod 64 — the one residue the other totals (0, 3,
       56, 32 mod 64) never reach, and chunked updates cannot change a
       total's residue. It pins final()'s padding boundary exactly:
       55 content bytes + the 0x80 pad byte fill block_len to 56, the
       largest value that must still fit the 8-byte length in the same
       block ("block_len > 56" spills; mutating it to ">= 56" corrupts
       precisely this residue and nothing else in this file — review
       planted that mutation and the prior vectors all survived). */
    {
        u_char  a55[55];

        static const char  a55_hex[] =
            "9f4390f8d30c2dd92ec9f095b65e2b9a"
            "e9b0a925a5258e241c9f1e910f734318";

        memset(a55, 'a', sizeof(a55));
        ngx_http_zstd_sha256(a55, sizeof(a55), digest, NULL);
        to_hex(digest, hexdigest);
        check("padding-boundary vector (55 x 'a', remainder 55 mod 64)",
              strcmp(hexdigest, a55_hex) == 0, hexdigest);
    }

    /* The million-'a' vector, fed in 1000-byte updates: exercises the
       full-block fast path and the length accounting at scale. */
    {
        u_char  a1000[1000];

        static const char  million_hex[] =
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0";

        memset(a1000, 'a', sizeof(a1000));
        ngx_http_zstd_sha256_init(&c);
        for (i = 0; i < 1000; i++) {
            ngx_http_zstd_sha256_update(&c, a1000, sizeof(a1000));
        }
        ngx_http_zstd_sha256_final(&c, digest);
        to_hex(digest, hexdigest);
        check("NIST vector (1,000,000 x 'a', incremental)",
              strcmp(hexdigest, million_hex) == 0, hexdigest);
    }

    /* Incremental updates at block-boundary split sizes must agree with
       the one-shot digest of the same pseudo-random buffer (fixed LCG,
       so the input is deterministic without external files). */
    buf = malloc(buf_len);
    if (buf == NULL) {
        printf("FAIL - malloc(%zu)\n", buf_len);
        return 1;
    }

    lcg = 0x12345678;
    for (i = 0; i < buf_len; i++) {
        lcg = lcg * 1664525 + 1013904223;
        buf[i] = (u_char) (lcg >> 24);
    }

    ngx_http_zstd_sha256(buf, buf_len, ref, NULL);

    for (i = 0; i < sizeof(splits) / sizeof(splits[0]); i++) {
        ngx_http_zstd_sha256_init(&c);
        for (off = 0; off < buf_len; off += n) {
            n = splits[i];
            if (n > buf_len - off) {
                n = buf_len - off;
            }
            ngx_http_zstd_sha256_update(&c, buf + off, n);
        }
        ngx_http_zstd_sha256_final(&c, digest);
        snprintf(name, sizeof(name),
                 "incremental chunks of %zu match one-shot", splits[i]);
        check(name, memcmp(digest, ref,
                           NGX_HTTP_ZSTD_SHA256_DIGEST_LEN) == 0, NULL);
    }

    free(buf);

    if (failures) {
        printf("FAILED: %d portable check(s)\n", failures);
        return 1;
    }

    printf("OK: portable SHA-256 fixture (vectors + incremental)\n");
    return 0;
}

#endif
