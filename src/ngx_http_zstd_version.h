#ifndef _NGX_HTTP_ZSTD_VERSION_H_INCLUDED_
#define _NGX_HTTP_ZSTD_VERSION_H_INCLUDED_

typedef enum {
    NGX_HTTP_ZSTD_VERSION_OK = 0,
    NGX_HTTP_ZSTD_VERSION_WARN,
    NGX_HTTP_ZSTD_VERSION_REFUSE_TARGET_CBLOCK,
    NGX_HTTP_ZSTD_VERSION_REFUSE_NEGATIVE_LEVEL
} ngx_http_zstd_version_result_t;


static ngx_http_zstd_version_result_t
ngx_http_zstd_version_policy(unsigned build, unsigned runtime,
    int any_target_cblock_size, int any_negative_level)
{
    if (build == runtime) {
        return NGX_HTTP_ZSTD_VERSION_OK;
    }

    if (build >= 10506 && runtime < 10506 && any_target_cblock_size) {
        return NGX_HTTP_ZSTD_VERSION_REFUSE_TARGET_CBLOCK;
    }

    if (build >= 10400 && runtime < 10400 && any_negative_level) {
        return NGX_HTTP_ZSTD_VERSION_REFUSE_NEGATIVE_LEVEL;
    }

    return NGX_HTTP_ZSTD_VERSION_WARN;
}

#endif /* _NGX_HTTP_ZSTD_VERSION_H_INCLUDED_ */
