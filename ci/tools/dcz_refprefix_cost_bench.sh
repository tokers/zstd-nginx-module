#!/bin/bash
# Build-and-run wrapper for dcz_refprefix_cost_bench.c (A31b-F2 cost proof,
# A33-F1 byte-identity proof).
#
# Measures whether the dcz path's per-request ZSTD_CCtx_refPrefix() call
# (module :3870/:3874, reached after the unconditional per-request
# ZSTD_CCtx_reset() at :3694) pays a dictionary table-build cost the
# trained-dictionary CDict path (:3911) avoids by building once at config
# load. Read dcz_refprefix_cost_bench.c's header comment for the full
# method, sweep, and noise-floor rationale.
#
# It also runs an untimed byte-identity sweep over the level axis in two
# content modes, which is what shows that swapping refPrefix for a config-time
# CDict is a wire-format change rather than a transparent optimisation. An
# overlap mismatch is reported and exits 0; a disjoint mismatch is a regression
# and exits 1.
#
# No nginx tree needed: links libzstd directly. Bounded runtime (a few
# seconds).
set -euo pipefail

cd "$(dirname "$0")/../.."

CC="${CC:-cc}"
SRC="ci/tools/dcz_refprefix_cost_bench.c"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/zstd-dcz-refprefix-bench.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

if ! pkg-config --exists libzstd 2>/dev/null; then
    echo "SKIP: libzstd not found via pkg-config" >&2
    exit 0
fi

read -r -a CFLAGS <<<"$(pkg-config --cflags libzstd) -Wall -Wextra -O2"
read -r -a LIBS <<<"$(pkg-config --libs libzstd)"

"$CC" "${CFLAGS[@]}" -o "$OUT/dcz_refprefix_cost_bench" "$SRC" "${LIBS[@]}"

"$OUT/dcz_refprefix_cost_bench"
