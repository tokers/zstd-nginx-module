# shellcheck shell=sh disable=SC2006,SC2154

ngx_http_zstd_reorder_static_filter() {
    if ! echo " $HTTP_FILTER_MODULES " | grep " $next " >/dev/null; then
        echo "$0: error: cannot order $ngx_module_name before absent $next" >&2
        return 1
    fi

    HTTP_FILTER_MODULES=`echo " $HTTP_FILTER_MODULES " \
                         | sed "s/ $ngx_module_name / /" \
                         | sed "s/ $next / $next $ngx_module_name /" \
                         | sed "s/^ *//;s/ *\$//"`

    case " $HTTP_FILTER_MODULES " in
        *" $next $ngx_module_name "*) ;;
        *)
            echo "$0: error: failed to order $ngx_module_name after $next" >&2
            return 1
        ;;
    esac
}

# Select the filter that zstd must be ordered immediately after on the static
# path. Sourced by filter/config (the production caller) and exercised directly
# by ci/tools/test_build_config_policy.sh, so the test evaluates this policy
# rather than a copy of it.
#
# Reads: $HTTP_FILTER_MODULES, $HTTP_GZIP. Echoes the chosen anchor.
ngx_http_zstd_static_next() {
    if echo " $HTTP_FILTER_MODULES " | grep ngx_http_brotli_filter_module >/dev/null; then
        echo ngx_http_brotli_filter_module
    elif [ "${HTTP_GZIP:-}" = YES ]; then
        echo ngx_http_gzip_filter_module
    elif echo " $HTTP_FILTER_MODULES " | grep pagespeed_etag_filter >/dev/null; then
        echo ngx_pagespeed_etag_filter
    else
        echo ngx_http_range_header_filter_module
    fi
}
