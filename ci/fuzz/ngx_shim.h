/*
 * Minimal nginx shim for fuzzing ngx_http_zstd_accept_encoding().
 *
 * The real ngx_http_zstd_common.h pulls in <ngx_config.h>/<ngx_core.h>/
 * <ngx_http.h> — the entire nginx tree. The Accept-Encoding parser only
 * touches a tiny, well-defined slice of that surface, so we reproduce just
 * that slice here with the EXACT upstream semantics. The fuzz target then
 * includes the real, shipped header unmodified, so we are fuzzing production
 * code — not a re-implementation.
 *
 * If nginx ever changes the semantics of ngx_strcasestrn / ngx_tolower this
 * shim must be updated to match; the comments below cite the upstream source
 * (src/core/ngx_string.{h,c}) these are copied from.
 */

#ifndef NGX_ZSTD_FUZZ_SHIM_H
#define NGX_ZSTD_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>

/* Guard against the real nginx headers being pulled in alongside the shim. */
#define NGX_HTTP_ZSTD_COMMON_H_SHIMMED 1

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_DECLINED -5

/* src/ngx_http_zstd_sha256.h */
#define NGX_HTTP_ZSTD_SHA256_DIGEST_LEN  32

/* src/ngx_http_zstd_filter_module.c: ngx_http_zstd_dcz_decode_digest()'s
 * output buffer size -- see that macro's definition for why it must
 * exceed NGX_HTTP_ZSTD_SHA256_DIGEST_LEN. */
#define NGX_HTTP_ZSTD_DCZ_DECODE_BUF_LEN  48

/* src/ngx_http_zstd_filter_module.c: padded base64 length of a 32-byte
 * digest, the length ceiling dcz_decode_digest() rejects above. */
#define NGX_HTTP_ZSTD_DCZ_DIGEST_B64_LEN  44

typedef struct {
    size_t  len;
    u_char *data;
} ngx_str_t;

/* src/core/ngx_string.h: ngx_tolower(c) — ASCII-only, no locale. */
#define ngx_tolower(c) (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)

/*
 * src/core/ngx_config.h defines ngx_inline as the platform's inline
 * keyword (`inline` on every compiler this suite builds with). The sliced
 * parser uses it on ngx_http_zstd_accept_encoding(), which the module TUs
 * no longer reference -- inline is what keeps a plain `static` from
 * tripping -Werror=unused-function there. The extracted .inc carries the
 * keyword verbatim, so this layer has to spell it too.
 */
#define ngx_inline  inline

/*
 * ngx_table_elt_t, reduced to the two fields the chained-Accept-Encoding
 * walker and legacy request path touch.  The legacy shape deliberately has
 * no ->next member, matching nginx 1.22.x.
 */
typedef struct ngx_table_elt_s  ngx_table_elt_t;

struct ngx_table_elt_s {
    ngx_str_t         key;
    ngx_str_t         value;
#if !defined(NGX_ZSTD_LEGACY_SHIM)
    ngx_table_elt_t  *next;
#endif
};

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
    ngx_table_elt_t  *accept_encoding;
    ngx_list_t        headers;
} ngx_http_headers_in_t;

typedef struct ngx_http_request_s  ngx_http_request_t;
struct ngx_http_request_s {
    ngx_http_request_t   *main;
    ngx_http_headers_in_t headers_in;
};

/*
 * The production header selects between (ae)->next and a NULL stub on
 * `nginx_version >= 1023000`, because ngx_table_elt_t.next does not
 * exist before 1.23.0. This layer has no nginx tree and no
 * nginx_version, so the default shim pins the modern chained shape. The
 * NGX_ZSTD_LEGACY_SHIM variant instead pins nginx 1.22.1: it removes ->next
 * and lets the request-field helper walk headers_in.headers. The dedicated
 * legacy unit test populates that list with repeated Accept-Encoding fields.
 */
#if defined(NGX_ZSTD_LEGACY_SHIM)
#define nginx_version  1022001
#else
#define nginx_version  1023000
#endif

/*
 * The chain step, mirrored from src/ngx_http_zstd_common.h. The macro is
 * defined OUTSIDE any function body there, so extract_parser.sh -- which
 * slices function bodies -- does not carry it into the .inc and this
 * layer has to supply it. Kept byte-identical to the production
 * nginx_version >= 1023000 arm; the pre-1.23 arm is the NULL stub because
 * ngx_http_zstd_request_coding_weight() walks headers_in.headers instead.
 */
#if (nginx_version >= 1023000)
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) (ae)->next)
#else
#define NGX_HTTP_ZSTD_AE_NEXT(ae)  ((const ngx_table_elt_t *) NULL)
#endif

/*
 * src/core/ngx_string.c: ngx_strncasecmp() — faithful upstream copy.
 * Compares up to n bytes case-insensitively; stops early on NUL in s1.
 */
static inline ngx_int_t
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

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

/*
 * src/core/ngx_string.c: ngx_strcasestrn().
 *
 * Case-insensitive search for a NUL-terminated needle inside a
 * NUL-terminated haystack. `n` is strlen(needle) - 1 (the function does
 * the +1 internally), exactly as the upstream contract — and exactly how
 * ngx_http_zstd_accept_encoding() calls it with sizeof("zstd") - 2.
 *
 * This is a faithful copy of the upstream implementation. It relies on
 * s1 (the haystack, == ae->data) being NUL-terminated, which is the
 * property the fuzz target deliberately stresses.
 */
static inline u_char *
ngx_strcasestrn(u_char *s1, char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    c2 = (ngx_uint_t) *s2++;
    c2 = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

    do {
        do {
            c1 = (ngx_uint_t) *s1++;

            if (c1 == 0) {
                return NULL;
            }

            c1 = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;

        } while (c1 != c2);

    } while (ngx_strncasecmp(s1, (u_char *) s2, n) != 0);

    return --s1;
}

/*
 * src/core/ngx_string.c: ngx_decode_base64() and its shared decode core
 * ngx_decode_base64_internal() (standard alphabet variant only, i.e. the
 * "+/" table -- this module never calls the base64url or basic64
 * NGX_ESCAPE variants). Faithful upstream copy: rejects the input up
 * front unless its length is a multiple of 4 (dst->len is set from that
 * check, exactly mirroring ngx_base64_decoded_length()'s ((len + 3) / 4)
 * * 3 for a 4-aligned len), decodes 4 source bytes to 3 destination bytes
 * per group, and treats '=' padding and any byte outside the alphabet as
 * a hard decode failure (NGX_ERROR) rather than skipping it -- unlike
 * some non-nginx base64 decoders, this is NOT lenient about embedded
 * whitespace or padding placement. ngx_http_zstd_dcz_decode_digest()
 * relies on exactly this strictness: a malformed byte sequence must
 * decode-fail, not silently produce wrong bytes.
 */
static ngx_int_t
ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis)
{
    size_t          len;
    u_char         *d, *s;

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis[src->data[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    dst->len = (size_t) (d - dst->data);

    return NGX_OK;
}

static const u_char ngx_base64_decode_table[] = {
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
    77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
    77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
    77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
};

static inline ngx_int_t
ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src)
{
    /*
     * src/core/ngx_string.c: ngx_decode_base64() rejects input whose
     * length is not a multiple of 4 -- the "=" padding is REQUIRED, not
     * optional (unlike the "url" variant). This is exactly the strict
     * gate the dcz Available-Dictionary path relies on: the fuzz seeds
     * cover both the padded-32-byte-digest case (which is a multiple of
     * 4) and unpadded/misaligned lengths (rejected here).
     */
    if (src->len % 4 != 0) {
        return NGX_ERROR;
    }

    return ngx_decode_base64_internal(dst, src, ngx_base64_decode_table);
}

#endif /* NGX_ZSTD_FUZZ_SHIM_H */
