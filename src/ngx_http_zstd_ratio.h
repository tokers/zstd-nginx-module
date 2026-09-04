/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * THE authoritative copy of the overflow-safe ratio split behind
 * $zstd_ratio (#294): ngx_http_zstd_ratio_parts(). Pure arithmetic --
 * no logging, no allocation, no request state -- so every consumer
 * (the filter module, the unit fixture, and the compression branch's
 * $compression_ratio) includes THIS file instead of carrying a
 * synchronized copy. Within a day of #294 merging the same function
 * existed three times across the two trees and the brotli fork; a
 * fix to the arithmetic would have been ported three times.
 *
 * CONSUMER CONTRACT. Inside nginx, include after the nginx headers
 * and everything below resolves. Outside nginx (the unit fixture),
 * provide before including:
 *     typedef uintptr_t  ngx_uint_t;
 * When nginx has not defined ngx_inline it expands to nothing: the
 * definition is already `static`, and an empty fallback keeps a
 * conforming C89 compile valid, where `inline` is not a keyword.
 * The function body is the filter module's, moved verbatim.
 */

#ifndef NGX_HTTP_ZSTD_RATIO_H
#define NGX_HTTP_ZSTD_RATIO_H

#include <stdint.h>

#ifndef ngx_inline
#define ngx_inline
#endif


/*
 * Split bytes_in/bytes_out into an integer part and a three-decimal
 * fractional part (*ratio_int, *ratio_frac) without ever overflowing
 * uint64_t. bytes_in is a running total of streamed input and bytes_out a
 * running total of compressed output; either can approach UINT64_MAX on a
 * long-lived connection, and bytes_out may exceed bytes_in whenever zstd
 * expands incompressible input.
 *
 * Neither obvious form is safe. `bytes_in * 1000 / bytes_out` wraps in the
 * multiply. Dividing first and scaling only the remainder still wraps when
 * bytes_out > bytes_in, because the remainder is then bytes_in itself: for
 * bytes_in = UINT64_MAX - 1, bytes_out = UINT64_MAX it reports 0.000
 * instead of 0.999.
 *
 * Extract the three fractional digits by exact long division instead. Per
 * digit the remainder (always < divisor) is multiplied by 10, which is the
 * only growth step. When that product would not fit, compute it as
 * q * divisor + r with q = remainder / (divisor / 10) so the multiply stays
 * in range -- no value is ever approximated, so the result matches an
 * exact 128-bit bytes_in * 1000 / bytes_out for every input pair.
 */
static ngx_inline void
ngx_http_zstd_ratio_parts(uint64_t bytes_in, uint64_t bytes_out,
    ngx_uint_t *ratio_int, ngx_uint_t *ratio_frac)
{
    uint64_t  remainder, frac;
    int       i;

    *ratio_int = (ngx_uint_t) (bytes_in / bytes_out);

    remainder = bytes_in % bytes_out;
    frac      = 0;

    for (i = 0; i < 3; i++) {

        if (remainder <= UINT64_MAX / 10) {
            remainder *= 10;
            frac       = frac * 10 + remainder / bytes_out;
            remainder %= bytes_out;
            continue;
        }

        /*
         * remainder * 10 would overflow. Since remainder < bytes_out, that
         * only happens for a very large divisor; then remainder * 10 is at
         * most 10 * bytes_out, so the quotient digit is in [0, 10) and can
         * be found exactly without forming the product: peel off whole
         * multiples of bytes_out from remainder * 10 one at a time, each
         * step staying inside uint64_t.
         */
        {
            uint64_t  acc = remainder;
            uint64_t  digit = 0;
            int       k;

            /* acc accumulates remainder * 10 modulo bytes_out. */
            for (k = 0; k < 9; k++) {
                acc += remainder;

                if (acc >= bytes_out || acc < remainder) {
                    /* wrapped past, or reached, one whole bytes_out */
                    acc -= bytes_out;
                    digit++;
                }
            }

            frac      = frac * 10 + digit;
            remainder = acc;
        }
    }

    *ratio_frac = (ngx_uint_t) frac;
}


#endif /* NGX_HTTP_ZSTD_RATIO_H */
