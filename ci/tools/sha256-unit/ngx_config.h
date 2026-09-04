/*
 * Minimal ngx type surface for compiling ngx_http_zstd_sha256.h outside
 * nginx (tools/test_sha256_unit.c). The header's only ngx dependencies
 * are these types and memory helpers. Keeping the shim this small means
 * a NEW dependency taken by the header shows up as a compile error
 * here; it does not guard against compatible surface drift (the fake
 * EVP already declares `void *impl` where real OpenSSL has `ENGINE *`,
 * and both compile) — real-header compatibility is what the production
 * builds verify.
 */

#ifndef NGX_SHIM_CONFIG_H
#define NGX_SHIM_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef unsigned char  u_char;
typedef uintptr_t      ngx_uint_t;
typedef intptr_t       ngx_int_t;

#define ngx_inline               inline
#define ngx_memcpy(dst, src, n)  memcpy(dst, src, n)
#define ngx_memzero(buf, n)      memset(buf, 0, n)

#endif /* NGX_SHIM_CONFIG_H */
