#!/usr/bin/env bash
# Regression coverage for the canonical persistent-build input manifest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
HASHER="$SCRIPT_DIR/build-input-hash.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# This list is deliberately independent of the manifest under test. Without a
# separate oracle, deleting an input from the manifest also deletes its test.
required_inputs=(
    ci/build-inputs.manifest
    ci/tools/build-input-hash.sh
    ci/tools/ci-build.sh
    config
    auto/zstd
    filter/config
    filter/reorder-static.sh
    static/config
    src
)

for required in "${required_inputs[@]}"; do
    if ! grep -Fxq "$required" "$MODULE_DIR/ci/build-inputs.manifest"; then
        echo "FAIL: required build input missing from manifest: $required" >&2
        exit 1
    fi
done

copy_inputs() {
    local input

    mkdir -p "$WORK/module"
    while IFS= read -r input || [ -n "$input" ]; do
        case "$input" in
            '' | \#*) continue ;;
        esac
        mkdir -p "$WORK/module/$(dirname "$input")"
        cp -a "$MODULE_DIR/$input" "$WORK/module/$input"
    done < "$MODULE_DIR/ci/build-inputs.manifest"
}

assert_mutation_changes_hash() {
    local input="$1"
    local file="$WORK/module/$input"
    local relative="$input"
    local before after

    if [ -d "$file" ]; then
        file="$(find "$file" -type f -print -quit)"
        relative="${file#"$WORK/module/"}"
    fi
    before="$(bash "$HASHER" "$WORK/module")"
    printf '\n# manifest regression mutation\n' >> "$file"
    after="$(bash "$HASHER" "$WORK/module")"
    if [ "$before" = "$after" ]; then
        echo "FAIL: $input mutation did not change build-input hash" >&2
        exit 1
    fi
    cp -a "$MODULE_DIR/$relative" "$WORK/module/$relative"
}

copy_inputs

while IFS= read -r input || [ -n "$input" ]; do
    case "$input" in
        '' | \#*) continue ;;
    esac
    assert_mutation_changes_hash "$input"
done < "$MODULE_DIR/ci/build-inputs.manifest"

before="$(bash "$HASHER" "$WORK/module")"
printf 'documentation only\n' > "$WORK/module/README.md"
after="$(bash "$HASHER" "$WORK/module")"
if [ "$before" != "$after" ]; then
    echo "FAIL: docs-only mutation changed build-input hash" >&2
    exit 1
fi

for specification in \
    '.github/workflows/build-test.yml:1' \
    '.github/workflows/ci-deep.yml:2'; do
    workflow="${specification%:*}"
    expected="${specification##*:}"
    actual="$(grep -c 'key: .*steps.build-inputs.outputs.hash' \
        "$MODULE_DIR/$workflow" || true)"
    if [ "$actual" -ne "$expected" ]; then
        echo "FAIL: $workflow uses the canonical hash in $actual/$expected cache keys" >&2
        exit 1
    fi
done

echo "✓ every manifest fragment invalidates build caches; docs-only changes do not"

# Exercise ci-build.sh itself with a tiny offline server tarball. The fake
# Makefile records a compile/link input in the addon object, making a stale
# tree directly observable without downloading and compiling nginx.
integration="$WORK/integration"
module="$integration/module"
root="$integration/build"
source="$integration/angie-9.9.9"
mkdir -p "$module" "$root" "$source"
cp -a "$WORK/module/." "$module/"
cat > "$source/configure" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
    case "$argument" in
        --add-dynamic-module=*) module="${argument#*=}" ;;
    esac
done
: "${module:?missing addon module path}"
cat > Makefile <<MAKEFILE
all:
	mkdir -p objs
	sha256sum "$module/filter/config" > objs/ngx_http_zstd_filter_module.o
	cp objs/ngx_http_zstd_filter_module.o objs/ngx_http_zstd_filter_module.so
	touch objs/ngx_http_zstd_static_module.so objs/angie
MAKEFILE
EOF
chmod +x "$source/configure"
tar -czf "$root/angie-9.9.9.tar.gz" -C "$integration" angie-9.9.9
rm -rf "$source"
digest="$(sha256sum "$root/angie-9.9.9.tar.gz" | cut -d' ' -f1)"
sed -i "/declare -A ANGIE_SHA256=(/a\\    [\"9.9.9\"]=\"$digest\"" \
    "$module/ci/tools/ci-build.sh"

BUILD_ROOT="$root" bash "$module/ci/tools/ci-build.sh" angie 9.9.9 coverage \
    > "$integration/first.log"
object="$root/angie-9.9.9-coverage/objs/ngx_http_zstd_filter_module.o"
first_object="$(cat "$object")"
printf '\n# compile/link mutation\n' >> "$module/filter/config"
BUILD_ROOT="$root" bash "$module/ci/tools/ci-build.sh" angie 9.9.9 coverage \
    > "$integration/second.log"
second_object="$(cat "$object")"

if [ "$first_object" = "$second_object" ]; then
    echo "FAIL: compile/link-input mutation reused the stale addon object" >&2
    exit 1
fi
if ! grep -q 'Build inputs changed.*rebuilding from scratch' \
    "$integration/second.log"; then
    echo "FAIL: compile/link-input mutation did not invalidate the build tree" >&2
    exit 1
fi
echo "✓ compile/link-input mutation rebuilds the addon object"
