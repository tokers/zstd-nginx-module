#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mkdir -p "$tmp/auto"
cat >"$tmp/auto/feature" <<'EOF'
ngx_found=no
ngx_test_incs=
for ngx_test_path in $ngx_feature_path; do
    ngx_test_incs="$ngx_test_incs -I$ngx_test_path"
done
cat >"$ngx_test_dir/probe.c" <<PROBE
$ngx_feature_incs
int main(void) { $ngx_feature_test; return 0; }
PROBE
# Paths in nginx's generated build tree cannot contain shell metacharacters.
# shellcheck disable=SC2086
if ${CC:-cc} -nostdinc -Werror $ngx_test_incs "$ngx_test_dir/probe.c" \
    -o "$ngx_test_dir/probe" >/dev/null 2>&1; then
    ngx_found=yes
    printf '#define %s 1\n' "$ngx_feature_name" >"$ngx_test_result"
else
    : >"$ngx_test_result"
fi
EOF
cat >"$tmp/auto/module" <<'EOF'
:
EOF

run_probe() (
    config=$1
    prepared=$2
    result=$3
    case_dir=$tmp/$result
    mkdir -p "$case_dir"
    cd "$tmp"

    ngx_addon_dir=$root/filter
    ngx_zstd_incs=
    ngx_zstd_opt_L=
    ngx_module_link=ADDON
    USE_OPENSSL=YES
    OPENSSL=$prepared
    CORE_INCS=
    HTTP_FILTER_MODULES=ngx_http_range_header_filter_module
    HTTP_GZIP=NO
    _ngx_zstd_root=$root
    ngx_test_dir=$case_dir
    ngx_test_result=$case_dir/result
    export ngx_addon_dir ngx_zstd_incs ngx_zstd_opt_L ngx_module_link
    export USE_OPENSSL OPENSSL CORE_INCS HTTP_FILTER_MODULES HTTP_GZIP
    export _ngx_zstd_root ngx_test_dir ngx_test_result

    # shellcheck source=/dev/null
    . "$config" >/dev/null
    cp "$ngx_test_result" "$tmp/$result.out"
)

prepared=$tmp/prepared
mkdir -p "$prepared/openssl/include/openssl"
cat >"$prepared/openssl/include/openssl/evp.h" <<'EOF'
#define EVP_MAX_MD_SIZE 64
const void *EVP_sha256(void);
EOF

run_probe "$root/filter/config" "$prepared" prepared
grep -q '^#define NGX_HTTP_ZSTD_HAVE_LIBCRYPTO 1$' "$tmp/prepared.out"

run_probe "$root/filter/config" "$tmp/missing" missing
if grep -q NGX_HTTP_ZSTD_HAVE_LIBCRYPTO "$tmp/missing.out"; then
    echo 'missing prepared OpenSSL tree unexpectedly enabled EVP' >&2
    exit 1
fi

# Negative control: the prepared MSVC layout must stop probing successfully if
# its include spelling is removed from the production config.
# The single quotes deliberately preserve the config's literal shell variable.
# shellcheck disable=SC2016
sed 's| $OPENSSL/openssl/include||' "$root/filter/config" >"$tmp/config-mutated"
run_probe "$tmp/config-mutated" "$prepared" mutated
if grep -q NGX_HTTP_ZSTD_HAVE_LIBCRYPTO "$tmp/mutated.out"; then
    echo 'negative control still enabled EVP without the MSVC include path' >&2
    exit 1
fi

echo 'prepared OpenSSL EVP probe: PASS'
