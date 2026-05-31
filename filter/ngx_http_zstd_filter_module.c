
/*
 * Copyright (C) Alex Zhang
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zstd.h>


#if ZSTD_VERSION_NUMBER < 10400
#error "libzstd 1.4.0 or later required for ZSTD_compressStream2"
#endif


typedef struct {
    ngx_str_t                    dict_file;
} ngx_http_zstd_main_conf_t;


typedef struct {
    ngx_flag_t                   enable;
    ngx_int_t                    level;
    ssize_t                      min_length;

    ngx_hash_t                   types;

    ngx_bufs_t                   bufs;

    ngx_array_t                 *types_keys;

    ZSTD_CDict                  *dict;
} ngx_http_zstd_loc_conf_t;


typedef struct {
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;
    ngx_chain_t                 *out;
    ngx_chain_t                **last_out;

    ngx_buf_t                   *in_buf;
    ngx_buf_t                   *out_buf;
    ngx_int_t                    bufs;

    ZSTD_inBuffer                buffer_in;
    ZSTD_outBuffer               buffer_out;

    ZSTD_CStream                *cstream;

    ngx_http_request_t          *request;

    size_t                       bytes_in;
    size_t                       bytes_out;

    /*
     * Sticky-finish flags (per-call-op pattern, modelled on ngx_brotli's
     * ngx_http_brotli_filter_module.c):
     *
     * - ctx->last  : set in add_data when consuming a buf with last_buf=1;
     *                drives op = ZSTD_e_end on subsequent compress calls
     *                until libzstd reports rc==0 (frame footer drained),
     *                then cleared after the terminal downstream buf is
     *                enqueued with b->last_buf=1.
     * - ctx->flush : set in add_data when consuming a buf with flush=1;
     *                drives op = ZSTD_e_flush on subsequent compress calls
     *                until libzstd reports rc==0 (internal buffer drained),
     *                then cleared after the downstream buf is enqueued
     *                with b->flush=1.
     *
     * The flags are sticky to guarantee flush/end propagation even when
     * libzstd swallows a small input chunk without producing output (rc==0
     * on the first call). The previous action state machine (the
     * NGX_HTTP_ZSTD_FILTER_COMPRESS/FLUSH/END enum + redo) failed in that
     * case: it only promoted COMPRESS->FLUSH when rc>0, leaving small
     * flush'd chunks stranded in libzstd's internal buffer. See issue #23.
     */
    unsigned                     last:1;
    unsigned                     flush:1;
    unsigned                     done:1;
    unsigned                     nomem:1;
} ngx_http_zstd_ctx_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_http_zstd_comp_level_bounds_t;


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;

static ngx_str_t  ngx_http_zstd_ratio = ngx_string("zstd_ratio");


static ngx_int_t ngx_http_zstd_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_zstd_filter_add_data(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_get_buf(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ZSTD_CStream *ngx_http_zstd_filter_create_cstream(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_filter_compress(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx);
static ngx_int_t ngx_http_zstd_accept_encoding(ngx_str_t *ae);
static ngx_int_t ngx_http_zstd_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_zstd_filter_init(ngx_conf_t *cf);
static void * ngx_http_zstd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_zstd_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_zstd_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data);
static void * ngx_http_zstd_filter_alloc(void *opaque, size_t size);
static void ngx_http_zstd_filter_free(void *opaque, void *address);
static char *ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data);
static char *ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_http_zstd_comp_level_bounds_t  ngx_http_zstd_comp_level_bounds = {
    ngx_http_zstd_comp_level
};


static ngx_command_t  ngx_http_zstd_filter_commands[] = {

    { ngx_string("zstd"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
      |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, enable),
      NULL },

    { ngx_string("zstd_comp_level"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_zstd_set_num_slot_with_negatives,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, level),
      &ngx_http_zstd_comp_level_bounds },

    { ngx_string("zstd_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

    { ngx_string("zstd_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, bufs),
      NULL },

    { ngx_string("zstd_min_length"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_zstd_loc_conf_t, min_length),
      NULL },

    { ngx_string("zstd_dict_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zstd_main_conf_t, dict_file),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_zstd_filter_module_ctx = {
    ngx_http_zstd_add_variables,            /* preconfiguration */
    ngx_http_zstd_filter_init,              /* postconfiguration */

    ngx_http_zstd_create_main_conf,         /* create main configuration */
    ngx_http_zstd_init_main_conf,           /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_zstd_create_loc_conf,          /* create location configuration */
    ngx_http_zstd_merge_loc_conf,           /* merge location configuration */
};


ngx_module_t  ngx_http_zstd_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_zstd_filter_module_ctx,       /* module context */
    ngx_http_zstd_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_zstd_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t           *h;
    ngx_http_zstd_loc_conf_t  *zlcf;
    ngx_http_zstd_ctx_t       *ctx;

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (!zlcf->enable
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
       || (r->headers_out.content_encoding
           && r->headers_out.content_encoding->value.len)
       || (r->headers_out.content_length_n != -1
           && r->headers_out.content_length_n < zlcf->min_length)
       || ngx_http_test_content_type(r, &zlcf->types) == NULL
       || r->header_only)
    {
        return ngx_http_next_header_filter(r);
    }

    r->gzip_vary = 1;

    if (ngx_http_zstd_ok(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_zstd_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_zstd_filter_module);

    ctx->request = r;
    ctx->last_out = &ctx->out;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Content-Encoding");
    ngx_str_set(&h->value, "zstd");
    r->headers_out.content_encoding = h;

    r->main_filter_need_in_memory = 1;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);
    ngx_http_weak_etag(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_zstd_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                rv;
    ngx_int_t             flush, rc;
    ngx_chain_t          *cl;
    ngx_http_zstd_ctx_t  *ctx;


    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);

    if (ctx == NULL || ctx->done || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http zstd filter");

    if (ctx->cstream == NULL) {
        ctx->cstream = ngx_http_zstd_filter_create_cstream(r, ctx);
        if (ctx->cstream == NULL) {
            goto failed;
        }
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            goto failed;
        }

        r->connection->buffered |= NGX_HTTP_GZIP_BUFFERED;
    }

    if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            goto failed;
        }

        cl = NULL;

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &cl,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        flush = 0;
        ctx->nomem = 0;

    } else {
        flush = ctx->busy ? 1 : 0;
    }

    for ( ;; ) {

        /* cycle while we can write to a client */

        for ( ;; ) {

            rc = ngx_http_zstd_filter_add_data(r, ctx);

            if (rc == NGX_DECLINED) {
                break;
            }

            if (rc == NGX_AGAIN) {
                continue;
            }

            rc = ngx_http_zstd_filter_get_buf(r, ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DECLINED) {
                break;
            }

            rc = ngx_http_zstd_filter_compress(r, ctx);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_OK) {
                break;
            }

            /* rc == NGX_AGAIN */
        }

        if (ctx->out == NULL && !flush) {
            return ctx->busy ? NGX_AGAIN : NGX_OK;
        }

        rc = ngx_http_next_body_filter(r, ctx->out);

        if (rc == NGX_ERROR) {
            goto failed;
        }

        ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_zstd_filter_module);

        ctx->last_out = &ctx->out;
        ctx->nomem = 0;
        flush = 0;

        if (ctx->done) {
            rv = ZSTD_freeCStream(ctx->cstream);
            if (ZSTD_isError(rv)) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              "ZSTD_freeCStream() failed: %s",
                              ZSTD_getErrorName(rc));

                rc = NGX_ERROR;
            }

            return rc;
        }
    }

failed:

    ctx->done = 1;
    rv = ZSTD_freeCStream(ctx->cstream);
    if (ZSTD_isError(rv)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeCStream() failed: %s", ZSTD_getErrorName(rv));
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_zstd_filter_compress(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    size_t             rc, pos_in, pos_out;
    ngx_chain_t       *cl;
    ngx_buf_t         *b;
    ngx_uint_t         has_bytes, has_signal;
    ZSTD_EndDirective  op;

    /*
     * Per-call-op pattern (ngx_brotli model): derive the libzstd endOp
     * directive from the sticky-finish flags set in add_data when the
     * upstream buf had last_buf=1 / flush=1. last takes precedence over
     * flush (terminal finish overrides intermediate flush).
     */
    if (ctx->last) {
        op = ZSTD_e_end;

    } else if (ctx->flush) {
        op = ZSTD_e_flush;

    } else {
        op = ZSTD_e_continue;
    }

    ngx_log_debug8(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress in: src:%p pos:%ud size: %ud, "
                   "dst:%p pos:%ud size:%ud flush:%d last:%d",
                   ctx->buffer_in.src, ctx->buffer_in.pos, ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size, ctx->flush, ctx->last);

    pos_in = ctx->buffer_in.pos;
    pos_out = ctx->buffer_out.pos;

    rc = ZSTD_compressStream2(ctx->cstream, &ctx->buffer_out,
                              &ctx->buffer_in, op);

    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_compressStream2(%s) failed: %s",
                      (op == ZSTD_e_end) ? "end"
                        : (op == ZSTD_e_flush) ? "flush" : "continue",
                      ZSTD_getErrorName(rc));

        return NGX_ERROR;
    }

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd compress out: src:%p pos:%ud size: %ud, "
                   "dst:%p pos:%ud size:%ud",
                   ctx->buffer_in.src, ctx->buffer_in.pos, ctx->buffer_in.size,
                   ctx->buffer_out.dst, ctx->buffer_out.pos,
                   ctx->buffer_out.size);

    /*
     * Skip the pointer arithmetic when the compressor didn't consume / emit
     * anything. buffer_in.src may be NULL on a flush-only call (sentinel
     * buffer with no payload); C says NULL+0 is undefined behaviour even
     * when the delta is zero, which UBSan reports. Same logic for
     * out_buf->last on a continue op that produced no output.
     */
    if (ctx->buffer_in.pos != pos_in) {
        ctx->in_buf->pos += ctx->buffer_in.pos - pos_in;
    }
    if (ctx->buffer_out.pos != pos_out) {
        ctx->out_buf->last += ctx->buffer_out.pos - pos_out;
    }

    /*
     * Zero-progress guard (see ngx_brotli's body-filter loop): in
     * ZSTD_e_continue mode the encoder is required to make forward
     * progress (per the ZSTD_compressStream2 contract in zstd.h). If it
     * consumed no input and produced no output, treat this as a fatal
     * tripwire to avoid spinning the body-filter loop indefinitely.
     * Flush/end ops may legitimately make no progress once the buffer is
     * fully drained (rc==0), so guard only the continue case.
     */
    if (op == ZSTD_e_continue
        && ctx->buffer_in.pos == pos_in
        && ctx->buffer_out.pos == pos_out
        && rc == 0)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "zstd compress made no progress, aborting");
        return NGX_ERROR;
    }

    /*
     * Unified post-compress handling. Two orthogonal axes decide what
     * we emit downstream:
     *
     *   has_signal -- is there a finish-op boundary to deliver? Yes iff
     *                 rc == 0 and op is ZSTD_e_flush / ZSTD_e_end
     *                 (libzstd reports the op as fully drained).
     *
     *   has_bytes  -- are there compressed bytes in out_buf?
     *
     * Cases:
     *   * !has_signal && !has_bytes -- return NGX_AGAIN. Either rc > 0
     *     (encoder still has bytes pending; outer loop will call back
     *     with a fresh out_buf via get_buf) or op was ZSTD_e_continue
     *     with rc == 0 (input consumed without spill; outer loop will
     *     call back with the next chain link). The zero-progress guard
     *     above already caught the pathological no-progress continue.
     *   * has_bytes (with or without signal) -- enqueue ctx->out_buf,
     *     attaching b->flush=1 / b->last_buf=1 if has_signal.
     *   * has_signal && !has_bytes -- enqueue a *separate* zero-size
     *     sync buf (NOT ctx->out_buf, which is a recycled temporary; the
     *     write filter rejects zero-size temporary bufs via
     *     ngx_buf_special; see ngx_buf.h). Without this branch the
     *     flush/end boundary is invisible to the writer -- the
     *     flush-promotion bug (issue #23) this migration targets.
     */
    has_bytes  = (ngx_buf_size(ctx->out_buf) != 0);
    has_signal = (rc == 0 && (op == ZSTD_e_flush || op == ZSTD_e_end));

    if (!has_bytes && !has_signal) {
        return NGX_AGAIN;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (has_bytes) {
        b = ctx->out_buf;
        ctx->bytes_out += ngx_buf_size(b);

    } else {
        /*
         * Zero-size signal-only buf. No memory flags; the writer's
         * ngx_buf_special() accepts (flush || last_buf || sync) only
         * when !in_memory && !in_file (see ngx_buf.h).
         */
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->sync = 1;
    }

    /*
     * Shared finalize: when libzstd has fully drained the current finish
     * op (has_signal), attach the matching downstream marker and clear the
     * sticky flag so add_data can dequeue the next chain link on the
     * subsequent outer-loop pass.
     */
    if (has_signal) {
        r->connection->buffered &= ~NGX_HTTP_GZIP_BUFFERED;

        if (op == ZSTD_e_end) {
            b->last_buf = 1;
            ctx->done = 1;
            ctx->last = 0;

        } else {
            b->flush = 1;
            ctx->flush = 0;
        }
    }

    cl->next = NULL;
    cl->buf = b;

    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    if (has_bytes) {
        ngx_memzero(&ctx->buffer_out, sizeof(ZSTD_outBuffer));
    }

    return ctx->done ? NGX_OK : NGX_AGAIN;
}


static ngx_int_t
ngx_http_zstd_filter_add_data(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    /*
     * Sticky-flag head-of-line: while ctx->last or ctx->flush is set we
     * have an in-flight finish op (ZSTD_e_end / ZSTD_e_flush) that has not
     * yet drained (rc > 0 from the previous compress call). Stay on the
     * current buffer_in (typically empty) so the caller re-enters
     * filter_compress to drain libzstd's internal buffer.
     */
    if (ctx->buffer_in.pos < ctx->buffer_in.size
        || ctx->flush
        || ctx->last)
    {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "zstd in: %p", ctx->in);

    if (ctx->in == NULL) {
        return NGX_DECLINED;
    }

    ctx->in_buf = ctx->in->buf;
    ctx->in = ctx->in->next;

    /*
     * Drop empty non-control bufs (brotli pattern). An empty buf with
     * neither last_buf nor flush carries no information but would otherwise
     * still drive a useless ZSTD_e_continue call. Return NGX_AGAIN so the
     * outer add_data loop pulls the next link.
     */
    if (ngx_buf_size(ctx->in_buf) == 0
        && !ctx->in_buf->last_buf
        && !ctx->in_buf->flush)
    {
        return NGX_AGAIN;
    }

    /*
     * Set sticky flags immediately on consuming the buf. last_buf takes
     * precedence: a buf with both flags set transitions us directly to the
     * terminal end-of-stream op.
     */
    if (ctx->in_buf->last_buf) {
        ctx->last = 1;

    } else if (ctx->in_buf->flush) {
        ctx->flush = 1;
    }

    ctx->buffer_in.src = ctx->in_buf->pos;
    ctx->buffer_in.pos = 0;
    ctx->buffer_in.size = ngx_buf_size(ctx->in_buf);

    ctx->bytes_in += ngx_buf_size(ctx->in_buf);

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_filter_get_buf(ngx_http_request_t *r, ngx_http_zstd_ctx_t *ctx)
{
    ngx_chain_t               *cl;
    ngx_http_zstd_loc_conf_t  *zlcf;

    if (ctx->buffer_out.pos < ctx->buffer_out.size) {
        return NGX_OK;
    }

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    if (ctx->free) {
        cl = ctx->free;
        ctx->free = ctx->free->next;
        ctx->out_buf = cl->buf;
        ngx_free_chain(r->pool, cl);

    } else if (ctx->bufs < zlcf->bufs.num) {
        ctx->out_buf = ngx_create_temp_buf(r->pool, zlcf->bufs.size);
        if (ctx->out_buf == NULL) {
            return NGX_ERROR;
        }

        ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_zstd_filter_module;
        ctx->out_buf->recycled = 1;
        ctx->bufs++;

    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->buffer_out.dst = ctx->out_buf->pos;
    ctx->buffer_out.pos = 0;
    ctx->buffer_out.size = ctx->out_buf->end - ctx->out_buf->start;

    return NGX_OK;
}


static ZSTD_CStream *
ngx_http_zstd_filter_create_cstream(ngx_http_request_t *r,
    ngx_http_zstd_ctx_t *ctx)
{
    size_t                      rc;
    ZSTD_CStream               *cstream;
    ZSTD_customMem              cmem;
    ngx_http_zstd_loc_conf_t   *zlcf;

    zlcf = ngx_http_get_module_loc_conf(r, ngx_http_zstd_filter_module);

    cmem.customAlloc = ngx_http_zstd_filter_alloc;
    cmem.customFree = ngx_http_zstd_filter_free;
    cmem.opaque = ctx;

    cstream = ZSTD_createCStream_advanced(cmem);
    if (cstream == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_createCStream_advanced() failed");

        return NULL;
    }

    /*
     * Modern (libzstd >= 1.4.0) init sequence: explicit session-only reset
     * followed by either a CDict ref or an explicit compression level
     * parameter. Replaces the legacy ZSTD_initCStream /
     * ZSTD_initCStream_usingCDict path (and the >= 1.5.0 version gate around
     * the deprecated usingCDict call); equivalent on a freshly created CCtx
     * with no advanced parameters set.
     */
    rc = ZSTD_CCtx_reset(cstream, ZSTD_reset_session_only);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_CCtx_reset() failed: %s",
                      ZSTD_getErrorName(rc));

        goto failed;
    }

    if (zlcf->dict) {
        rc = ZSTD_CCtx_refCDict(cstream, zlcf->dict);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_CCtx_refCDict() failed: %s",
                          ZSTD_getErrorName(rc));

            goto failed;
        }

    } else {
        rc = ZSTD_CCtx_setParameter(cstream, ZSTD_c_compressionLevel,
                                    (int) zlcf->level);
        if (ZSTD_isError(rc)) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "ZSTD_CCtx_setParameter(compressionLevel) "
                          "failed: %s",
                          ZSTD_getErrorName(rc));

            goto failed;
        }
    }

    return cstream;

failed:
    rc = ZSTD_freeCStream(cstream);
    if (ZSTD_isError(rc)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ZSTD_freeCStream() failed: %s", ZSTD_getErrorName(rc));
    }

    return NULL;
}


static ngx_int_t
ngx_http_zstd_accept_encoding(ngx_str_t *ae)
{
    u_char  *p;

    p = ngx_strcasestrn(ae->data, "zstd", sizeof("zstd") - 2);
    if (p == NULL) {
        return NGX_DECLINED;
    }

    if (p == ae->data || (*(p - 1) == ',' || *(p - 1) == ' ')) {

        p += sizeof("zstd") - 1;

        if (p == ae->data + ae->len || *p == ',' || *p == ' ' || *p == ';') {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_zstd_ok(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    ae = r->headers_in.accept_encoding;
    if (ae == NULL) {
        return NGX_DECLINED;
    }

    if (ae->value.len < sizeof("zstd") - 1) {
        return NGX_DECLINED;
    }

    if (ngx_memcmp(ae->value.data, "zstd", 4) != 0
        && ngx_http_zstd_accept_encoding(&ae->value) != NGX_OK)
    {
        return NGX_DECLINED;
    }


    r->gzip_tested = 1;
    r->gzip_ok = 0;

    return NGX_OK;
}


static void *
ngx_http_zstd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_main_conf_t  *zmcf;

    zmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_main_conf_t));
    if (zmcf == NULL) {
        return NULL;
    }

    return zmcf;
}


static char *
ngx_http_zstd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_zstd_main_conf_t *zmcf = conf;

    if (zmcf->dict_file.len == 0) {
        return NGX_CONF_OK;
    }

    if (ngx_conf_full_name(cf->cycle, &zmcf->dict_file, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_zstd_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_zstd_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zstd_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *    conf->bufs.num = 0;
     *    conf->types = { NULL };
     *    conf->types_keys = NULL;
     *    conf->dict = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->level = NGX_CONF_UNSET;
    conf->min_length = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_zstd_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_zstd_loc_conf_t *prev = parent;
    ngx_http_zstd_loc_conf_t *conf = child;

    ngx_fd_t                    fd;
    size_t                      size;
    ssize_t                     n;
    char                       *rc;
    u_char                     *buf;
    ngx_file_info_t             info;
    ngx_http_zstd_main_conf_t  *zmcf;

    rc = NGX_OK;
    buf = NULL;
    fd = NGX_INVALID_FILE;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->level, prev->level, 1);
    ngx_conf_merge_value(conf->min_length, prev->min_length, 20);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             ngx_http_html_default_types))
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_ptr_value(conf->dict, prev->dict, NULL);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_zstd_filter_module);

    if (conf->enable && zmcf->dict_file.len > 0) {

        if (conf->level == prev->level) {
            conf->dict = prev->dict;

        } else {
            /*
             * compression level is different from the outer block,
             * so we should create a seperate dict object.
             */

            fd = ngx_open_file(zmcf->dict_file.data, NGX_FILE_RDONLY,
                               NGX_FILE_OPEN, 0);

            if (fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_open_file_n " \"%V\" failed",
                                   &zmcf->dict_file);

                return NGX_CONF_ERROR;
            }

            if (ngx_fd_info(fd, &info) == NGX_FILE_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_fd_info_n " \"%V\" failed",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            size = ngx_file_size(&info);
            buf = ngx_palloc(cf->pool, size);
            if (buf == NULL) {
                rc = NGX_CONF_ERROR;
                goto close;
            }

            n = ngx_read_fd(fd, (void *) buf, size);
            if (n < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_read_fd_n " %V\" failed",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;

            } else if ((size_t) n != size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_read_fd_n "\"%V incomplete\"",
                                   &zmcf->dict_file);

                rc = NGX_CONF_ERROR;
                goto close;
            }

            conf->dict = ZSTD_createCDict_byReference(buf, size, conf->level);
            if (conf->dict == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ZSTD_createCDict_byReference() failed");
                rc = NGX_CONF_ERROR;
                goto close;
            }
        }
    }

close:

    if (fd != NGX_INVALID_FILE && ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed",
                           &zmcf->dict_file);

        rc = NGX_CONF_ERROR;
    }

    return rc;
}


static ngx_int_t
ngx_http_zstd_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_zstd_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_zstd_body_filter;

    return NGX_OK;
}


static void *
ngx_http_zstd_filter_alloc(void *opaque, size_t size)
{
    ngx_http_zstd_ctx_t *ctx = opaque;

    void  *p;

    p = ngx_palloc(ctx->request->pool, size);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "zstd alloc: %p, size: %uz", p, size);

    return p;
}


static ngx_int_t
ngx_http_zstd_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *v;

    v = ngx_http_add_variable(cf, &ngx_http_zstd_ratio,
                              NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_zstd_ratio_variable;

    return NGX_OK;
}


static ngx_int_t
ngx_http_zstd_ratio_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *vv, uintptr_t data)
{
    ngx_uint_t            ratio_int, ratio_frac;
    ngx_http_zstd_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_zstd_filter_module);
    if (ctx == NULL || !ctx->done || ctx->bytes_out == 0) {
        vv->not_found = 1;
        return NGX_OK;
    }

    vv->data = ngx_pnalloc(r->pool, NGX_INT32_LEN + 3);
    if (vv->data == NULL) {
        return NGX_ERROR;
    }

    ratio_int = (ngx_uint_t) ctx->bytes_in / ctx->bytes_out;
    ratio_frac = (ngx_uint_t) (ctx->bytes_in * 1000 / ctx->bytes_out % 1000);

    vv->len = ngx_sprintf(vv->data, "%ui.%03ui", ratio_int, ratio_frac)
              - vv->data;

    vv->valid = 1;
    vv->no_cacheable = 1;

    return NGX_OK;
}


static void
ngx_http_zstd_filter_free(void *opaque, void *address)
{
#if (NGX_DEBUG)

    ngx_http_zstd_ctx_t *ctx = opaque;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "zstd free: %p", address);

#endif
}


static char *
ngx_http_zstd_comp_level(ngx_conf_t *cf, void *post, void *data)
{
    ngx_int_t  *np = data;

    if (*np == 0 || *np < (ngx_int_t)ZSTD_minCLevel() || *np > ZSTD_maxCLevel()) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zstd compress level must between %i and %i excluding 0",
                           (ngx_int_t)ZSTD_minCLevel(), ZSTD_maxCLevel());

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_conf_zstd_set_num_slot_with_negatives(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_int_t        *np;
    ngx_str_t        *value;
    ngx_conf_post_t  *post;


    np = (ngx_int_t *) (p + cmd->offset);

    if (*np != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (*(value[1].data) == '-') {
        // Parse ignoring the leading '-' character
        *np = ngx_atoi(value[1].data + 1, value[1].len - 1);

        // NGX_ERROR is -1 so we need to check for that before making the parsed
        // result negative
        if (*np == NGX_ERROR) {
            return "invalid number";
        }

        *np = -*np;
    } else {
        *np = ngx_atoi(value[1].data, value[1].len);

        if (*np == NGX_ERROR) {
            return "invalid number";
        }
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, np);
    }

    return NGX_CONF_OK;
}
