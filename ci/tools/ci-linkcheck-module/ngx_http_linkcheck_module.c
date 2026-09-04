
/*
 * CI-only stub module. Built as an unrelated dynamic module in the same
 * nginx configure as the zstd modules so the linkage-isolation CI job
 * can assert libzstd does not leak onto its DT_NEEDED (see ../../auto/zstd:
 * link flags must flow through ngx_module_libs, never the build-global
 * NGX_LD_OPT). No directives, no handlers, no behaviour.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_http_module_t  ngx_http_linkcheck_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL,                                   /* merge location configuration */
};


static ngx_command_t  ngx_http_linkcheck_commands[] = {
    ngx_null_command
};


ngx_module_t  ngx_http_linkcheck_module = {
    NGX_MODULE_V1,
    &ngx_http_linkcheck_module_ctx,         /* module context */
    ngx_http_linkcheck_commands,            /* module directives */
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
