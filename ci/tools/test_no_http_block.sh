#!/bin/sh
# An nginx that carries this module must still start without an http{}
# block: a stream-only or mail-only deployment compiles the module in
# (distribution builds enable every module) and configures none of it.
# The #284 init-module hook treated the absent http main conf as an
# error, so such a binary failed nginx -t -- and, because init-module
# failures are silent, with no diagnostic at all.
set -eu

nginx_bin=${1:?usage: test_no_http_block.sh <path-to-nginx-binary>}

work=$(mktemp -d "${TMPDIR:-/tmp}/no-http-block.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/logs"

printf '%s\n' \
    'pid logs/nginx.pid; error_log logs/error.log; events {}' \
    > "$work/nohttp.conf"

# The regression gate: an http-less configuration must validate.
if ! "$nginx_bin" -t -p "$work" -c nohttp.conf; then
    echo 'FAIL: an http-less configuration was refused' >&2
    exit 1
fi

# Sanity control on the same binary: a configured http block still
# validates, so the pass above is the no-op branch, not a disabled
# check. (The refusal arms themselves need a runtime libzstd older
# than the build headers; ci/tests/unit/test_version_policy.c covers
# the policy table.)
printf '%s\n' \
    'pid logs/nginx.pid; error_log logs/error.log; events {}' \
    'http { zstd on; }' \
    > "$work/http.conf"
"$nginx_bin" -t -p "$work" -c http.conf

echo 'OK: http-less configuration validates'
