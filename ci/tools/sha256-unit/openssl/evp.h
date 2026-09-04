/*
 * FAKE OpenSSL EVP header for the unit fixture: declarations only, no
 * OpenSSL required. tools/test_sha256_unit.c supplies implementations
 * whose failure modes are scripted (partial digest write + failure
 * return, wrong output length, scripted success), so the EVP-to-
 * portable fallback in ngx_http_zstd_sha256.h can be exercised
 * deterministically. This directory is passed with -I ahead of the
 * system paths, so this header shadows the real <openssl/evp.h> for
 * the fixture build only.
 */

#ifndef NGX_SHIM_FAKE_EVP_H
#define NGX_SHIM_FAKE_EVP_H

#include <stddef.h>

typedef struct fake_evp_md_st  EVP_MD;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct engine_st ENGINE;

const EVP_MD *EVP_sha256(void);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size);

#endif /* NGX_SHIM_FAKE_EVP_H */
