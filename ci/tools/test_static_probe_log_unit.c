#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

typedef unsigned long  ngx_uint_t;
typedef int            ngx_err_t;

#define NGX_LOG_ERR   4
#define NGX_LOG_CRIT  2
#define ngx_errno     errno

#include "generated_probe_log.inc"

static int failures;

static void
check(const char *name, ssize_t n, ngx_uint_t directio, ngx_uint_t want_level,
    ngx_err_t want_err)
{
    ngx_err_t   got_err = -1;
    ngx_uint_t  got_level;

    errno = EIO;
    got_level = ngx_http_zstd_static_probe_read_log_level(n, directio,
                                                          &got_err);
    if (got_level != want_level || got_err != want_err) {
        fprintf(stderr, "FAIL: %s: level=%lu errno=%d\n", name,
                (unsigned long) got_level, got_err);
        failures++;
    }
}

int
main(void)
{
    check("ordinary EOF", 0, 0, NGX_LOG_ERR, 0);
    check("directio short read", 3, 1, NGX_LOG_ERR, 0);
    check("ordinary failure", -1, 0, NGX_LOG_CRIT, EIO);
    check("directio failure", -1, 1, NGX_LOG_ERR, EIO);

    return failures ? 1 : 0;
}
