#!/usr/bin/env bash
# Build the Vary-fusion fixture against the configured nginx tree supplied by
# the validation job. Missing generated headers are a hard coverage failure.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
nginx_tree=${NGINX_SRC_TREE:?NGINX_SRC_TREE must name a configured nginx source tree}
cc=${CC:-cc}
out=$(mktemp -d "${TMPDIR:-/tmp}/zstd-vary-fusion.XXXXXX")
trap 'rm -rf "$out"' EXIT HUP INT TERM

test -f "$nginx_tree/objs/ngx_auto_config.h"
includes=(-I"$nginx_tree/objs")
while IFS= read -r inc_dir; do
    includes+=(-I"$inc_dir")
done < <(find "$nginx_tree/src" -type d ! -path '*/os/win32*')

"$cc" -std=c11 -Wall -Wextra -Werror "${includes[@]}" \
    -I"$root/src" "$root/ci/tests/unit/test_vary_fusion.c" \
    -o "$out/test_vary_fusion"
timeout 60s "$out/test_vary_fusion"
