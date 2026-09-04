/*
 * SHA-256 (FIPS 180-4) for hashing dcz dictionaries at config load.
 *
 * Why a local implementation: RFC 9842 keys dictionary negotiation on the
 * SHA-256 of the dictionary bytes (the client's Available-Dictionary hash
 * and the 32-byte hash embedded in the dcz frame header), but nginx core
 * ships only MD5/SHA-1 and OpenSSL is present only when nginx is built
 * with an SSL module — which this module must not require. The hash runs
 * once per configured dictionary at config load, never per request, so a
 * compact byte-at-a-time implementation is an acceptable floor.
 *
 * When filter/config detects libcrypto at build time
 * (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO), the one-shot entry point uses
 * OpenSSL's EVP SHA-256 instead — hardware-accelerated where the CPU
 * allows, and roughly an order of magnitude faster than the portable
 * loop either way. That matters at real dictionary counts: config load
 * (and so nginx -t and every reload) hashes each registered file, which
 * at hundreds of entries turns into seconds of pure CPU with the
 * portable code. The portable implementation stays compiled in as the
 * runtime fallback: context allocation or any incremental EVP stage may fail,
 * and falling back keeps this a total function.
 *
 * Only the filter TU uses these today. The one-shot entry point
 * ngx_http_zstd_sha256() is static ngx_inline; the four helpers it drives
 * (_compress, _init, _update, _final) are plain static and are reached only
 * through it, so they carry no -Werror=unused-function exemption of their
 * own. A second TU including this header would need them marked
 * ngx_inline too, or would have to use every one of them.
 */

#ifndef NGX_HTTP_ZSTD_SHA256_H
#define NGX_HTTP_ZSTD_SHA256_H


#include <ngx_config.h>
#include <ngx_core.h>

#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
#include <openssl/evp.h>
#endif


#define NGX_HTTP_ZSTD_SHA256_DIGEST_LEN  32


typedef struct {
    uint32_t  state[8];
    uint64_t  total;            /* message length so far, in bytes */
    u_char    block[64];        /* pending partial block */
    size_t    block_len;
} ngx_http_zstd_sha256_t;


static const uint32_t  ngx_http_zstd_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static void
ngx_http_zstd_sha256_compress(ngx_http_zstd_sha256_t *c, const u_char *p)
{
    uint32_t    w[64], a, b, d, e, f, g, h, s0, s1, cc;
    ngx_uint_t  i;

#define ngx_http_zstd_rotr(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t) p[i * 4] << 24) | ((uint32_t) p[i * 4 + 1] << 16)
               | ((uint32_t) p[i * 4 + 2] << 8) | (uint32_t) p[i * 4 + 3];
    }

    for (i = 16; i < 64; i++) {
        s0 = ngx_http_zstd_rotr(w[i - 15], 7)
             ^ ngx_http_zstd_rotr(w[i - 15], 18)
             ^ (w[i - 15] >> 3);
        s1 = ngx_http_zstd_rotr(w[i - 2], 17) ^ ngx_http_zstd_rotr(w[i - 2], 19)
             ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->state[0];
    b = c->state[1];
    cc = c->state[2];   /* "c" is taken by the context parameter */
    d = c->state[3];
    e = c->state[4];
    f = c->state[5];
    g = c->state[6];
    h = c->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t  t1, ch, maj;

        s1 = ngx_http_zstd_rotr(e, 6) ^ ngx_http_zstd_rotr(e, 11)
             ^ ngx_http_zstd_rotr(e, 25);
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + ngx_http_zstd_sha256_k[i] + w[i];
        s0 = ngx_http_zstd_rotr(a, 2) ^ ngx_http_zstd_rotr(a, 13)
             ^ ngx_http_zstd_rotr(a, 22);
        maj = (a & b) ^ (a & cc) ^ (b & cc);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + s0 + maj;
    }

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
    c->state[5] += f;
    c->state[6] += g;
    c->state[7] += h;

#undef ngx_http_zstd_rotr
}


static void
ngx_http_zstd_sha256_init(ngx_http_zstd_sha256_t *c)
{
    c->state[0] = 0x6a09e667;
    c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372;
    c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f;
    c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab;
    c->state[7] = 0x5be0cd19;
    c->total = 0;
    c->block_len = 0;
}


static void
ngx_http_zstd_sha256_update(ngx_http_zstd_sha256_t *c, const u_char *data,
    size_t len)
{
    c->total += len;

    if (c->block_len) {
        size_t  n;

        n = 64 - c->block_len;
        if (n > len) {
            n = len;
        }

        ngx_memcpy(c->block + c->block_len, data, n);
        c->block_len += n;
        data += n;
        len -= n;

        if (c->block_len < 64) {
            return;
        }

        ngx_http_zstd_sha256_compress(c, c->block);
        c->block_len = 0;
    }

    while (len >= 64) {
        ngx_http_zstd_sha256_compress(c, data);
        data += 64;
        len -= 64;
    }

    if (len) {
        ngx_memcpy(c->block, data, len);
        c->block_len = len;
    }
}


static void
ngx_http_zstd_sha256_final(ngx_http_zstd_sha256_t *c,
    u_char digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN])
{
    uint64_t    bits;
    ngx_uint_t  i;

    bits = c->total * 8;

    /*
     * padding: 0x80, zeros, then the 64-bit big-endian bit length.
     *
     * The append below is unguarded because update() never returns with a
     * full block: it compresses and resets block_len to 0 the moment the
     * block fills, so block_len is in [0, 63] on entry here and writing
     * block[block_len] stays in bounds. Keep that invariant if update()
     * is ever restructured -- an entry with block_len == 64 would write
     * one past the array before the bounds test below runs.
     */
    c->block[c->block_len++] = 0x80;

    if (c->block_len > 56) {
        ngx_memzero(c->block + c->block_len, 64 - c->block_len);
        ngx_http_zstd_sha256_compress(c, c->block);
        c->block_len = 0;
    }

    ngx_memzero(c->block + c->block_len, 56 - c->block_len);

    for (i = 0; i < 8; i++) {
        c->block[56 + i] = (u_char) (bits >> (56 - i * 8));
    }

    ngx_http_zstd_sha256_compress(c, c->block);

    for (i = 0; i < 8; i++) {
        digest[i * 4]     = (u_char) (c->state[i] >> 24);
        digest[i * 4 + 1] = (u_char) (c->state[i] >> 16);
        digest[i * 4 + 2] = (u_char) (c->state[i] >> 8);
        digest[i * 4 + 3] = (u_char) c->state[i];
    }
}


/* One-shot convenience for the config-load call site. */
static ngx_inline void
ngx_http_zstd_sha256(const u_char *data, size_t len,
    u_char digest[NGX_HTTP_ZSTD_SHA256_DIGEST_LEN], void *evp_md_ctx)
{
    ngx_http_zstd_sha256_t  c;

#if (NGX_HTTP_ZSTD_HAVE_LIBCRYPTO)
    unsigned int  mdlen;

    mdlen = NGX_HTTP_ZSTD_SHA256_DIGEST_LEN;

    if (evp_md_ctx != NULL
        && EVP_DigestInit_ex(evp_md_ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(evp_md_ctx, data, len) == 1
        && EVP_DigestFinal_ex(evp_md_ctx, digest, &mdlen) == 1
        && mdlen == NGX_HTTP_ZSTD_SHA256_DIGEST_LEN)
    {
        return;
    }

    /* Fall through when the cycle context is unavailable or a stage fails. */
#endif

    (void) evp_md_ctx;

    ngx_http_zstd_sha256_init(&c);
    ngx_http_zstd_sha256_update(&c, data, len);
    ngx_http_zstd_sha256_final(&c, digest);
}


#endif /* NGX_HTTP_ZSTD_SHA256_H */
