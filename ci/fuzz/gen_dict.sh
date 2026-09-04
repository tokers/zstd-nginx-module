#!/usr/bin/env bash
#
# Generate the coding-name entries of fuzz.dict from the module's real
# parse surface, instead of a hand-maintained list that goes stale
# silently: a merely incomplete dictionary still produces a green
# crash-only fuzz run, so nothing else would ever catch the drift.
#
# This module has no single lookup table of coding names -- unlike a
# trie-walk scanner, the tokens are two literal call-site arguments to
# ngx_http_zstd_coding_weight(ae, "TOKEN", ...) in src/*.c and src/*.h (currently
# "zstd" and "dcz"). Extract THOSE, rather than hand-copying them, so a
# third coding name added to a future call site is picked up
# automatically and a forgotten dictionary update fails --check instead
# of silently shipping an incomplete dictionary.
#
# Usage:
#   ci/fuzz/gen_dict.sh           regenerate fuzz.dict's coding-token lines
#   ci/fuzz/gen_dict.sh --check   exit 1 if fuzz.dict's coding tokens have
#                                 drifted from the source (wired into
#                                 ci/linter/lint-c.sh)
#
# fuzz.dict also carries structural/grammar tokens (";q=", ",", etc.) that
# are not coding names and are NOT touched by this script -- only the
# quoted content-coding literals block, delimited by the markers below.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
DICT="$DIR/fuzz.dict"
# shellcheck source=ci/linter/lib.sh
. "$ROOT/ci/linter/lib.sh"

# The dictionary is byte-exact (its .gitattributes rule is -text), and
# every consumer of this script compares LINES: a CRLF-contaminated
# dict makes --check's marker match fail and report "stale tokens" --
# a misleading diagnosis for a line-ending problem -- while regeneration
# would faithfully preserve the CR bytes on the lines it rewrites
# around. Refuse CR up front, in both modes, with the real diagnosis.
if [ -f "$DICT" ] && grep -q $'\r' "$DICT"; then
	echo "✗ gen_dict: $DICT contains CRLF line endings. The dictionary" \
		"is byte-exact; restore the LF version (git checkout with its" \
		"-text attribute honored) before regenerating or checking." >&2
	exit 1
fi

START_MARK="# BEGIN generated coding tokens (ci/fuzz/gen_dict.sh)"
END_MARK="# END generated coding tokens"

# Extract every coding-name literal passed to a coding-weight entry point
# across src/*.c AND src/*.h: ngx_http_zstd_accept_encoding()'s own call
# ("zstd") lives in the ngx_http_zstd_common.h wrapper, not in a .c file, so
# both must be scanned. The functions' own DEFINITION lines (`const char
# *coding`, no string literal) never match this pattern, so there is
# nothing to exclude.
#
# Every entry point is matched: ngx_http_zstd_coding_weight() (one field
# value), ngx_http_zstd_chain_coding_weight() (the linked field chain), and
# ngx_http_zstd_request_coding_weight() (the complete request field).
# Matching the `chain_` and `request_` forms is load-bearing, not defensive
# tidiness: when the dcz call site moved to the request-field walker, a pattern
# anchored on
# the bare name stopped matching it and silently dropped "dcz" from the
# dictionary, which is a fuzz-coverage loss that no test would have failed
# on. Matching every form keeps a call site's token in the dictionary wherever
# the negotiation is evaluated from.
produce_tokens() {
	grep -hoE 'ngx_http_zstd_((chain|request)_)?coding_weight\([^,]+,[[:space:]]*"[A-Za-z0-9_-]+"' \
		"$ROOT"/src/*.c "$ROOT"/src/*.h |
		grep -oE '"[A-Za-z0-9_-]+"$' |
		sort -u
}
mapfile_checked TOKENS produce_tokens

if [ "${#TOKENS[@]}" -eq 0 ]; then
	echo "✗ gen_dict: no ngx_http_zstd_coding_weight(...) call sites found" \
		"in src/*.c or src/*.h -- parser call convention changed? update gen_dict.sh" >&2
	exit 1
fi

GENERATED="$START_MARK"$'\n'
for t in "${TOKENS[@]}"; do
	GENERATED+="$t"$'\n'
done
GENERATED+="$END_MARK"

if [ "${1:-}" = "--check" ]; then
	if [ ! -f "$DICT" ]; then
		echo "✗ gen_dict --check: $DICT does not exist" >&2
		exit 1
	fi
	CURRENT="$(awk -v start="$START_MARK" -v end="$END_MARK" '
        $0 == start { f=1 }
        f { print }
        $0 == end { if (f) exit }
    ' "$DICT")"
	if [ "$CURRENT" != "$GENERATED" ]; then
		echo "✗ fuzz.dict's generated coding-token block is stale." >&2
		echo "  Source call sites: ${TOKENS[*]}" >&2
		echo "  Run: ci/fuzz/gen_dict.sh" >&2
		exit 1
	fi
	echo "✓ fuzz.dict coding tokens match src/*.c + src/*.h call sites: ${TOKENS[*]}"
	exit 0
fi

# BOTH markers, in order. Checking only START is not enough: awk below sets
# skip=1 at START and only clears it at END, so a dict that lost its END marker
# has every line after START swallowed and the mv writes the truncation back.
# A later --check can still pass, because the generated block itself matches.
if [ ! -f "$DICT" ]; then
	echo "✗ $DICT does not exist" >&2
	exit 1
fi
start_n="$(grep -cFx "$START_MARK" "$DICT" || true)"
end_n="$(grep -cFx "$END_MARK" "$DICT" || true)"
if [ "$start_n" -ne 1 ] || [ "$end_n" -ne 1 ]; then
	echo "✗ $DICT needs exactly one '$START_MARK' and one '$END_MARK' line" \
		"(found $start_n and $end_n) -- add the marker block once by hand," \
		"see the file header" >&2
	exit 1
fi
if [ "$(grep -nFx "$START_MARK" "$DICT" | cut -d: -f1)" -ge \
	"$(grep -nFx "$END_MARK" "$DICT" | cut -d: -f1)" ]; then
	echo "✗ $DICT has '$END_MARK' before '$START_MARK'" >&2
	exit 1
fi

TMP="$(mktemp)"
awk -v start="$START_MARK" -v end="$END_MARK" -v gen="$GENERATED" '
    $0 == start { print gen; skip=1; next }
    $0 == end   { skip=0; next }
    skip { next }
    { print }
' "$DICT" >"$TMP"
mv "$TMP" "$DICT"

echo "✓ regenerated fuzz.dict coding tokens from src/*.c + src/*.h: ${TOKENS[*]}"
