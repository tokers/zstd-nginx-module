#!/usr/bin/env bash
# Fast contract gate for the deterministic prefix and replayable random tail.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
src="$root/ci/tools/soak.sh"

assert_contract() {
    local file=$1
    grep -Fq 'SOAK_SEED="${SOAK_SEED:-' "$file" || return 1
    grep -Fq 'replay with SOAK_SEED=$SOAK_SEED' "$file" || return 1
    grep -Fq 'local prefix_paths=(/tiny /tiny /medium /medium /large /large' "$file" || return 1
    grep -Fq 'local prefix_aes=(gzip zstd gzip zstd gzip zstd zstd zstd zstd zstd dcz)' "$file" || return 1
    grep -Fq 'deterministic cell ${prefix_paths[$cell]}+${prefix_aes[$cell]} had no verified response' "$file" || return 1
    grep -Fq 'BAD compressed identity-only cell $p' "$file" || return 1
    ! grep -q '\$RANDOM' "$file" || return 1
}

assert_contract "$src"

work=$(mktemp -d "${TMPDIR:-/tmp}/soak-schedule-unit.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$src" "$work/soak.sh"
sed -i 's/zstd zstd dcz)/zstd zstd)/' "$work/soak.sh"
if assert_contract "$work/soak.sh" >/dev/null 2>&1; then
    echo 'FAIL: missing dcz prefix cell did not make schedule contract red' >&2
    exit 1
fi

set +e
SOAK_SEED=not-a-number bash "$src" /bin/false 0 1 >"$work/invalid.log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ] || ! grep -Fq 'SOAK_SEED must be an integer' "$work/invalid.log"; then
    echo "FAIL: invalid seed returned $rc without the validation diagnostic" >&2
    cat "$work/invalid.log" >&2
    exit 1
fi

set +e
SOAK_SEED=999999999999999999999999 bash "$src" /bin/false 0 1 \
    >"$work/overflow.log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ] || ! grep -Fq 'SOAK_SEED must be an integer' "$work/overflow.log"; then
    echo "FAIL: oversized seed returned $rc without the validation diagnostic" >&2
    cat "$work/overflow.log" >&2
    exit 1
fi

echo 'OK: deterministic soak prefix, seed replay, counts, and negative controls'
