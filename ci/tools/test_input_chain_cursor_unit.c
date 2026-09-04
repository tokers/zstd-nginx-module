/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Deterministic ownership oracle for the body-filter input cursor.  The
 * production functions are included verbatim from generated_input_cursor.inc;
 * only the nginx types and pool operations are shimmed here.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;

#define NGX_OK        0
#define NGX_ERROR    -1
#define NGX_AGAIN    -2
#define NGX_DECLINED -5

typedef struct ngx_buf_s ngx_buf_t;
typedef struct ngx_chain_s ngx_chain_t;
typedef struct ngx_pool_s ngx_pool_t;

struct ngx_buf_s {
    unsigned char  *pos;
    unsigned char  *last;
    unsigned         flush;
    unsigned         last_buf;
};

struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};

struct ngx_pool_s {
    size_t        calls;
    size_t        fail_at;
    size_t        frees;
    ngx_chain_t  *free;
};

typedef struct {
    const void  *src;
    size_t       size;
    size_t       pos;
} ZSTD_inBuffer;

typedef struct {
    ngx_chain_t   *in;
    ngx_chain_t  **last_in;
    ngx_buf_t     *in_buf;
    ZSTD_inBuffer  buffer_in;
    uint64_t       bytes_in;
    unsigned       flush;
    unsigned       last;
    unsigned       redo;
} ngx_http_zstd_ctx_t;

typedef struct {
    ngx_pool_t  *pool;
} ngx_http_request_t;

static ngx_chain_t *
mock_alloc_chain_link(ngx_pool_t *pool)
{
    ngx_chain_t  *cl;

    pool->calls++;
    if (pool->fail_at != 0 && pool->calls == pool->fail_at) {
        return NULL;
    }

    if (pool->free != NULL) {
        cl = pool->free;
        pool->free = cl->next;
        return cl;
    }

    return calloc(1, sizeof(*cl));
}
static void
mock_free_chain(ngx_pool_t *pool, ngx_chain_t *cl)
{
    pool->frees++;
    cl->next = pool->free;
    pool->free = cl;
}

#define ngx_http_zstd_alloc_chain_link(pool) mock_alloc_chain_link(pool)
#define ngx_free_chain(pool, cl) mock_free_chain(pool, cl)
#define ngx_buf_size(buf) ((size_t) ((buf)->last - (buf)->pos))
#define ngx_log_debug1(...) ((void) 0)

#include "generated_input_cursor.inc"

static unsigned char storage[8192];
static int failures;

static void
check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void
init_ctx(ngx_http_zstd_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->last_in = &ctx->in;
}

static void
make_chain(ngx_chain_t *links, ngx_buf_t *bufs, size_t count, size_t width)
{
    size_t  i;

    for (i = 0; i < count; i++) {
        bufs[i].pos = storage + (i % (sizeof(storage) - width));
        bufs[i].last = bufs[i].pos + width;
        bufs[i].flush = 0;
        bufs[i].last_buf = 0;
        links[i].buf = &bufs[i];
        links[i].next = i + 1 < count ? &links[i + 1] : NULL;
    }
}

static void
test_fully_drained_no_copy(void)
{
    ngx_buf_t             bufs[8];
    ngx_chain_t           links[8];
    ngx_chain_t          *cursor;
    ngx_http_request_t    r;
    ngx_http_zstd_ctx_t   ctx;
    ngx_pool_t            pool = {0};
    size_t                i;

    make_chain(links, bufs, 8, 3);
    cursor = links;
    r.pool = &pool;
    init_ctx(&ctx);

    for (i = 0; i < 8; i++) {
        check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
              "fully drained caller link loads");
        check(ctx.in_buf == &bufs[i], "caller links stay in order");
        ctx.buffer_in.pos = ctx.buffer_in.size;
    }

    check(cursor == NULL, "fully drained local cursor reaches NULL");
    check(ngx_http_zstd_filter_copy_input(&r, &ctx, cursor) == NGX_OK,
          "empty lazy copy succeeds");
    check(pool.calls == 0, "fully drained path allocates zero chain links");
    check(pool.frees == 0, "caller-owned links are never freed");
    for (i = 0; i < 7; i++) {
        check(links[i].next == &links[i + 1],
              "caller-owned next pointers remain unchanged");
    }
}

static void
test_partial_backpressure_and_retained_first(void)
{
    ngx_buf_t             bufs[4];
    ngx_chain_t           links[4];
    ngx_chain_t          *cursor;
    ngx_http_request_t    r;
    ngx_http_zstd_ctx_t   ctx;
    ngx_pool_t            pool = {0};

    make_chain(links, bufs, 4, 4);
    cursor = links;
    r.pool = &pool;
    init_ctx(&ctx);

    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
          "partial case loads first caller buffer");
    ctx.buffer_in.pos = 1;
    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
          "backpressure leaves partial input selected");
    check(cursor == &links[1], "partial input does not advance the tail cursor");

    check(ngx_http_zstd_filter_copy_input(&r, &ctx, cursor) == NGX_OK,
          "unconsumed tail is copied lazily");
    check(pool.calls == 3, "only the three-link tail is copied");
    check(ctx.in != NULL && ctx.in->buf == &bufs[1],
          "copied tail begins after active buffer");

    cursor = &links[0];
    ctx.buffer_in.pos = ctx.buffer_in.size;
    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
          "next callback drains retained input first");
    check(ctx.in_buf == &bufs[1] && cursor == &links[0],
          "retained link wins over new caller input");
    check(pool.frees == 1, "consumed retained wrapper returns to pool");
}

static void
test_many_links_and_lazy_failure(void)
{
    enum { MANY = 2048 };
    ngx_buf_t            *bufs;
    ngx_chain_t          *links, *cl;
    ngx_http_request_t    r;
    ngx_http_zstd_ctx_t   ctx;
    ngx_pool_t            pool = {0};
    size_t                i, copied;

    bufs = calloc(MANY, sizeof(*bufs));
    links = calloc(MANY, sizeof(*links));
    check(bufs != NULL && links != NULL, "many-link fixture allocation");
    if (bufs == NULL || links == NULL) {
        free(bufs);
        free(links);
        return;
    }

    make_chain(links, bufs, MANY, 1);
    r.pool = &pool;
    init_ctx(&ctx);
    check(ngx_http_zstd_filter_copy_input(&r, &ctx, links) == NGX_OK,
          "many-link lazy copy succeeds");
    copied = 0;
    for (cl = ctx.in; cl != NULL; cl = cl->next) {
        check(cl->buf == &bufs[copied], "many-link copy preserves order");
        copied++;
    }
    check(copied == MANY, "many-link copy retains every tail link");

    pool.calls = 0;
    pool.fail_at = 4;
    pool.free = NULL;
    init_ctx(&ctx);
    check(ngx_http_zstd_filter_copy_input(&r, &ctx, links) == NGX_ERROR,
          "lazy tail allocation failure is reported");
    copied = 0;
    for (cl = ctx.in; cl != NULL; cl = cl->next) {
        copied++;
    }
    check(copied == 3, "failure retains only pool-owned prefix copies");
    check(pool.calls == 4, "fault fires at the requested lazy allocation");
    for (i = 0; i + 1 < MANY; i++) {
        check(links[i].next == &links[i + 1],
              "lazy failure never rewrites caller-owned links");
    }

    free(bufs);
    free(links);
}

static void
test_flush_and_last_carriers(void)
{
    ngx_buf_t             bufs[3];
    ngx_chain_t           links[3];
    ngx_chain_t          *cursor;
    ngx_http_request_t    r;
    ngx_http_zstd_ctx_t   ctx;
    ngx_pool_t            pool = {0};

    make_chain(links, bufs, 3, 0);
    r.pool = &pool;

    init_ctx(&ctx);
    bufs[0].flush = 1;
    cursor = links;
    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
          "zero-size flush carrier schedules compression");
    check(ctx.flush == 1 && ctx.last == 0,
          "flush carrier sets flush without last");

    init_ctx(&ctx);
    bufs[0].flush = 1;
    bufs[0].last_buf = 1;
    cursor = links;
    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_OK,
          "zero-size terminal carrier schedules compression");
    check(ctx.last == 1 && ctx.flush == 0,
          "last_buf keeps priority over a co-carried flush");

    init_ctx(&ctx);
    cursor = links;
    bufs[0].flush = 0;
    bufs[0].last_buf = 0;
    check(ngx_http_zstd_filter_add_data(&r, &ctx, &cursor) == NGX_AGAIN,
          "ordinary empty carrier is skipped");
    check(cursor == &links[1], "empty carrier advances only its local link");
}

int
main(void)
{
    test_fully_drained_no_copy();
    test_partial_backpressure_and_retained_first();
    test_many_links_and_lazy_failure();
    test_flush_and_last_carriers();

    if (failures != 0) {
        fprintf(stderr, "FAIL: %d input-cursor assertions failed\n", failures);
        return 1;
    }

    puts("OK: input cursor (fully drained, partial/backpressure, retained-first, "
         "lazy-failure, many-link, flush/last carrier)");
    return 0;
}
