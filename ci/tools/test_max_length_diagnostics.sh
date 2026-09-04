#!/usr/bin/env bash
# Pin distinct, truthful diagnostics for known- and unknown-length overruns.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
src="$root/src/ngx_http_zstd_filter_module.c"

assert_contract() {
    local file=$1
    grep -Fq 'if (ctx->pledged_size >= 0)' "$file" || return 1
    grep -Fq 'after %uL bytes on a response with declared ' "$file" || return 1
    grep -Fq 'Content-Length %O; aborting to protect the ' "$file" || return 1
    grep -Fq 'after %uL bytes on a response with no ' "$file" || return 1
    grep -Fq 'ctx->bytes_in,' "$file" || return 1
    grep -Fq 'ctx->pledged_size);' "$file" || return 1
}

assert_contract "$src"

work=$(mktemp -d "${TMPDIR:-/tmp}/max-length-diagnostics.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$src" "$work/filter.c"
sed -i 's/after %uL bytes on a response with declared /after %uL bytes on a response with no /' "$work/filter.c"
if assert_contract "$work/filter.c" >/dev/null 2>&1; then
    echo 'FAIL: lying-known-length diagnostic mutant did not make contract red' >&2
    exit 1
fi

echo 'OK: known/unknown max-length abort diagnostics and negative control'
