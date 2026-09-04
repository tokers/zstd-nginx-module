#!/usr/bin/env bash
#
# Build the Accept-Encoding and dcz-digest libFuzzer targets.
# Usage: ci/fuzz/build.sh [accept-encoding-output-binary] [dcz-output-binary]
#
# Requires clang with libFuzzer (clang >= 6). CFLAGS/CC overridable for
# OSS-Fuzz / ClusterFuzzLite, which pass their own sanitizer flags.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$FUZZ_DIR/fuzz_accept_encoding}"
DCZ_OUT="${2:-$FUZZ_DIR/fuzz_dcz}"
CC="${CC:-clang}"

# OSS-Fuzz sets $LIB_FUZZING_ENGINE and its own $CFLAGS; honour them.
ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

bash "$FUZZ_DIR/extract_parser.sh"
bash "$FUZZ_DIR/extract_dcz.sh"

# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE \
    -I"$FUZZ_DIR" \
    "$FUZZ_DIR/fuzz_accept_encoding.c" \
    -o "$OUT"

echo "✓ built fuzz target: $OUT"

# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE \
    -I"$FUZZ_DIR" \
    "$FUZZ_DIR/fuzz_dcz.c" \
    -o "$DCZ_OUT"

echo "✓ built fuzz target: $DCZ_OUT"
