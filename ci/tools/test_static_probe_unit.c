/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit fixture for ngx_http_zstd_static_probe_frame().
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef uintptr_t      ngx_uint_t;
typedef unsigned char  u_char;

#define ngx_memcpy  memcpy

#ifdef TEST_BIG_ENDIAN_FALLBACK
#undef __BYTE_ORDER__
#define __BYTE_ORDER__  __ORDER_BIG_ENDIAN__
#endif

/* The shipped probe itself (#270) -- no generated extraction. */
#include "../../src/ngx_http_zstd_frame_probe.h"

static int failures;

static void
check(const char *name, int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s: %s\n", name, what);
        failures++;
    }
}

static void
case_reserved_descriptor_bit(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x08, 0x00, 0x00
    };
    uint64_t window = 0xdeadbeefU;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("reserved-bit", rc == NGX_HTTP_ZSTD_STATIC_FRAME_RESERVED,
          "expected reserved descriptor verdict");
    check("reserved-bit", window == 0xdeadbeefU,
          "reserved verdict must not write the window out-param");
}

static void
case_valid_streaming_header(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00
    };
    uint64_t window = 0;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("valid-streaming", rc == NGX_HTTP_ZSTD_STATIC_FRAME_OK,
          "expected a small streaming frame header to pass");
}

static void
case_big_window_header(void)
{
    static const u_char hdr[] = {
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88
    };
    uint64_t window = 0;
    ngx_int_t rc;

    rc = ngx_http_zstd_static_probe_frame(hdr, sizeof(hdr), &window);

    check("big-window", rc == NGX_HTTP_ZSTD_STATIC_FRAME_WINDOW_BIG,
          "expected oversized-window verdict");
    check("big-window", window == 134217728U,
          "expected decoded 128 MiB window");
}

int
main(void)
{
    case_reserved_descriptor_bit();
    case_valid_streaming_header();
    case_big_window_header();

    if (failures) {
        return 1;
    }

    puts("OK: static probe frame unit");
    return 0;
}
