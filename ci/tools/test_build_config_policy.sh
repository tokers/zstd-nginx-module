#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)

# The advisory must be a real compiler decision, not parsed -E output.
grep -q 'ngx_feature="libzstd 1.5.6 or newer"' "$root/auto/zstd"
if grep -q -- '-x c -E -' "$root/auto/zstd"; then
    exit 1
fi

# Static OpenSSL integration is optional even when nginx requested OpenSSL:
# headers/functions must be compile-probed before the macro is defined.
grep -q 'ngx_feature="OpenSSL EVP SHA-256 headers"' "$root/filter/config"
grep -Fq 'ngx_feature_path="$CORE_INCS"' "$root/filter/config"
grep -q 'OPENSSL/.openssl/include' "$root/filter/config"
grep -Fq '${USE_OPENSSL:-NO}' "$root/filter/config"
if grep -Fq '[ "$USE_OPENSSL" = YES -a ' "$root/filter/config"; then
    exit 1
fi
"$root/ci/tools/test_evp_prepared_tree_probe.sh"

# Exercise the authoritative reorder helper and its hard-failure control.
grep -Fq '. "$_ngx_zstd_root/filter/reorder-static.sh"' "$root/filter/config"
# The next= anchor must come from the shared helper, not an inline copy.
grep -Fq 'next=`ngx_http_zstd_static_next`' "$root/filter/config"
if grep -q 'next=ngx_http_brotli_filter_module' "$root/filter/config"; then
    echo 'filter/config still inlines the next= matrix; it must use ngx_http_zstd_static_next' >&2
    exit 1
fi
. "$root/filter/reorder-static.sh"
# Consumed by the sourced helper.
# shellcheck disable=SC2034
ngx_module_name=ngx_http_zstd_filter_module
# shellcheck disable=SC2034
next=ngx_http_gzip_filter_module
HTTP_FILTER_MODULES='ngx_http_gzip_filter_module ngx_http_range_header_filter_module'
ngx_http_zstd_reorder_static_filter
[ "$HTTP_FILTER_MODULES" = 'ngx_http_gzip_filter_module ngx_http_zstd_filter_module ngx_http_range_header_filter_module' ]

HTTP_FILTER_MODULES=ngx_http_range_header_filter_module
if ngx_http_zstd_reorder_static_filter >/dev/null 2>&1; then
    echo 'absent reorder anchor unexpectedly succeeded' >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Cross-mode equivalence: dynamic ngx_module_order vs. static reorder-static.sh
#
# nginx idiom (verified against src/core/ngx_module.c:ngx_add_module and every
# *_filter_module.c postconfiguration): each filter's postconfiguration does
#   next = ngx_http_top_body_filter; ngx_http_top_body_filter = this_filter;
# so modules are chained in cycle->modules[] init order, and the LAST filter
# *initialized* is the FIRST filter to *run* at request time.
#
# For a DYNAMIC module, ngx_add_module() walks its declared ngx_module_order
# starting just after the module's own name, and inserts the module in
# cycle->modules[] immediately before the first *already-loaded* module named
# in the remainder of that list ("before" stays cycle->modules_n, i.e. append
# at the end, if none of the remaining names are loaded yet).
#
# zstd's ngx_module_order (filter/config:111-127) starts with:
#   ngx_http_zstd_filter_module, ngx_pagespeed,
#   ngx_http_postpone_filter_module, ...
# It never names ngx_http_gzip_filter_module. But nginx's own stock
# HTTP_FILTER_MODULES order (auto/modules) always registers gzip (when
# HTTP_GZIP=YES) strictly before ngx_http_postpone_filter_module. So zstd's
# insertion point search lands on "postpone_filter_module" and inserts zstd
# immediately before it -- i.e. zstd is *initialized after* gzip whenever
# gzip is present, with no direct comparison ever performed. Combined with
# the last-initialized-runs-first idiom above, this means: dynamic mode
# initializes zstd after gzip, so zstd RUNS BEFORE gzip at request time.
#
# The static path achieves the identical *runtime* relationship by a
# different mechanism: reorder-static.sh splices zstd immediately AFTER
# gzip in HTTP_FILTER_MODULES (the static init-order array), which by the
# same last-initialized-runs-first idiom also means zstd RUNS BEFORE gzip.
#
# Scope limit: the two checks below are PREMISE GUARDS, not a derivation of
# the dynamic insertion index. ngx_add_module() inserts at the lowest index
# among loaded modules named in order[], so postpone's presence alone does not
# by itself fix the position; fully deriving it would mean modelling the module
# loader here. What these guards do assert is that the two facts the argument
# above rests on -- gzip absent from the list, postpone present as the anchor --
# still hold, so the argument is re-checked rather than assumed on every run.
#
# Property under test: both paths initialize zstd strictly after gzip in
# their respective init-order arrays (dynamic: implicitly, via the shared
# postpone anchor; static: explicitly, via reorder-static.sh's splice
# target), so both agree that zstd is the codec that wins when a client
# accepts both encodings. This test locks that agreement; it does not
# claim the ordering is "correct" in any absolute sense.

# --- dynamic path: parse ngx_module_order out of filter/config -------------
ngx_dyn_order=$(sed -n '/^ngx_module_order="\$ngx_module_name \\$/,/"$/p' \
    "$root/filter/config" | tr -d '\\"' | tr -s ' \t\n' ' ')

case " $ngx_dyn_order " in
    *' ngx_http_gzip_filter_module '*)
        echo 'FAIL: dynamic ngx_module_order now names gzip directly -- re-derive the cross-mode property, do not assume it still holds' >&2
        exit 1
        ;;
esac
case " $ngx_dyn_order " in
    *' ngx_http_postpone_filter_module '*) ;;
    *)
        echo 'FAIL: dynamic ngx_module_order no longer anchors on postpone_filter_module -- the gzip-precedes-postpone argument no longer applies' >&2
        exit 1
        ;;
esac

# --- static path: exercise the full next= decision matrix ------------------
# Mirrors filter/config:132-140 verbatim so drift in that matrix is caught.
# No local reimplementation of the next= matrix: a test that copies the policy
# it checks cannot catch drift in the original. Call the same
# ngx_http_zstd_static_next() that filter/config uses in production.
zstd_static_next() {
    # $1 = HTTP_FILTER_MODULES, $2 = HTTP_GZIP
    HTTP_FILTER_MODULES=$1
    # Consumed by the sourced reorder helper.
    # shellcheck disable=SC2034
    HTTP_GZIP=$2
    ngx_http_zstd_static_next
}

assert_static_case() {
    # $1=label $2=HTTP_FILTER_MODULES $3=HTTP_GZIP $4=expected anchor
    _label=$1
    _hfm=$2
    _gz=$3
    _expect=$4

    _got=$(zstd_static_next "$_hfm" "$_gz")
    if [ "$_got" != "$_expect" ]; then
        echo "FAIL: $_label: next= matrix gave '$_got', expected '$_expect'" >&2
        exit 1
    fi

    # Consumed by the sourced helper.
    # shellcheck disable=SC2034
    ngx_module_name=ngx_http_zstd_filter_module
    # shellcheck disable=SC2034
    next=$_got
    HTTP_FILTER_MODULES=$_hfm
    ngx_http_zstd_reorder_static_filter
    case " $HTTP_FILTER_MODULES " in
        *" $_expect ngx_http_zstd_filter_module "*) ;;
        *)
            echo "FAIL: $_label: zstd not spliced immediately after $_expect (got: $HTTP_FILTER_MODULES)" >&2
            exit 1
            ;;
    esac
}

# 1. brotli present -> zstd goes after brotli, regardless of HTTP_GZIP.
assert_static_case brotli-present \
    'ngx_http_brotli_filter_module ngx_http_gzip_filter_module ngx_http_range_header_filter_module' \
    YES ngx_http_brotli_filter_module

# 2. no brotli, HTTP_GZIP=YES -> zstd goes after gzip.
assert_static_case gzip-yes \
    'ngx_http_gzip_filter_module ngx_http_range_header_filter_module' \
    YES ngx_http_gzip_filter_module

# 3. no brotli, HTTP_GZIP!=YES, pagespeed_etag present -> zstd goes after it.
assert_static_case pagespeed-etag-fallback \
    'ngx_pagespeed_etag_filter ngx_http_range_header_filter_module' \
    NO ngx_pagespeed_etag_filter

# 4. no brotli, no gzip, no pagespeed -> fallback anchor is range_header.
assert_static_case bare-fallback \
    'ngx_http_range_header_filter_module' \
    NO ngx_http_range_header_filter_module

# --- negative control: prove the assertion above can go red ----------------
# Deliberately assert the WRONG expected anchor for the gzip-yes case (the
# stale pre-brotli fallback, range_header, instead of the correct gzip) and
# require assert_static_case to fail closed. Run in a subshell so its `exit 1`
# does not abort this script; capture stderr to show the real failure text.
_neg_status=0
_neg_out=$(
    assert_static_case gzip-yes-WRONG-on-purpose \
        'ngx_http_gzip_filter_module ngx_http_range_header_filter_module' \
        YES ngx_http_range_header_filter_module 2>&1
) || _neg_status=$?
if [ "$_neg_status" -eq 0 ]; then
    echo 'FAIL: negative control did not go red (deliberately wrong anchor was accepted)' >&2
    exit 1
fi
case "$_neg_out" in
    *"next= matrix gave 'ngx_http_gzip_filter_module', expected 'ngx_http_range_header_filter_module'"*) ;;
    *)
        echo "FAIL: negative control failed for the wrong reason: $_neg_out" >&2
        exit 1
        ;;
esac
echo "negative control observed red: $_neg_out"

echo 'build config policy: PASS'
