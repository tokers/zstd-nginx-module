#include <assert.h>

#include "../../../src/ngx_http_zstd_version.h"


int
main(void)
{
    assert(ngx_http_zstd_version_policy(10507, 10507, 1, 1)
           == NGX_HTTP_ZSTD_VERSION_OK);
    assert(ngx_http_zstd_version_policy(10507, 10506, 0, 0)
           == NGX_HTTP_ZSTD_VERSION_WARN);
    assert(ngx_http_zstd_version_policy(10507, 10505, 0, 0)
           == NGX_HTTP_ZSTD_VERSION_WARN);
    assert(ngx_http_zstd_version_policy(10507, 10505, 1, 0)
           == NGX_HTTP_ZSTD_VERSION_REFUSE_TARGET_CBLOCK);
    assert(ngx_http_zstd_version_policy(10507, 10309, 0, 1)
           == NGX_HTTP_ZSTD_VERSION_REFUSE_NEGATIVE_LEVEL);
    assert(ngx_http_zstd_version_policy(10309, 10308, 1, 1)
           == NGX_HTTP_ZSTD_VERSION_WARN);

    return 0;
}
