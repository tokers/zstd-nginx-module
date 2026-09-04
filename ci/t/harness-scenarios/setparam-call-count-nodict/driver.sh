#!/usr/bin/env bash
#
# Scenario: ZSTD_CCtx_setParameter() CALL COUNT, NO-DICTIONARY MODE.
#
# Pins the per-mode instrumentation this item's done criterion asks for. The
# no-dict mode takes NEITHER the zlcf->dict (CDict) NOR the ctx->dcz_dict
# (raw prefix) branch in ngx_http_zstd_filter_init_cctx(), so every
# parameter the location configures is a live CCtx parameter and none of
# them is superseded-by-cdict: level, windowLog, and (with zstd_long on)
# enableLongDistanceMatching are all genuinely applied -> 3 calls.
#
# This is the reference count the dictionary-mode oracles in the sibling
# setparam-call-count scenario are measured AGAINST. Under a trained CDict
# only level drops out (ZSTD_CCtx_refCDict() supersedes compressionLevel
# from the CDict's own baked-in ZSTD_compressionParameters -- zstd.h).
# windowLog is NOT superseded: ZSTD_resetCCtx_byAttachingCDict()/
# ZSTD_resetCCtx_byCopyingCDict() (zstd_compress.c) both restore windowLog
# from the CCtx's own applied params right after copying the CDict's other
# cParams, and assert it is nonzero -- so init_cctx must keep setting it
# even in CDict mode, or the operator's zstd_window_log cap silently stops
# applying. This arm is what proves level and windowLog are both genuinely
# set when nothing supersedes either of them.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0
N=0

ok()    { N=$((N + 1)); echo "ok $N - $1"; }
notok() { N=$((N + 1)); echo "not ok $N - $1"; FAILED=1; }
diag()  { echo "# $1"; }

WWW="$PROBER_PREFIX/www"
mkdir -p "$WWW"

# Larger than 2**20 (zstd_window_log 20 in nginx.conf): a body smaller than
# the window cap lets zstd shrink the FRAME's encoded window to fit the
# content regardless of what ZSTD_c_windowLog was set to, which would make
# the window-cap assertion below pass whether or not the cap was actually
# applied. Random bytes, same construction as the sibling
# setparam-call-count scenario's fixture and for the same reason.
awk 'BEGIN {
    srand(43)
    n = 1200000
    for (i = 0; i < n; i++) {
        printf "%c", 97 + int(rand() * 26)
    }
}' >"$WWW/index.html"

reset_counter() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe?setparam_reset=1" \
        -o /dev/null
}

read_counter() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    prober_probe_field "$body" "setparam_calls" || return 1
}

echo "1..4"

if ! reset_counter; then
    notok "reset: probe did not answer setparam_reset"
    notok "response decodes byte-for-byte to the origin"
    notok "setParameter call count is 3"
    notok "frame window size is 1048576 B"
    exit 1
fi

RAW="$PROBER_PREFIX/tmp"
mkdir -p "$RAW"
HDRS="$RAW/nodict.hdrs"
BODY="$RAW/nodict.bin"

if curl -sS --max-time 15 -D "$HDRS" -o "$BODY" \
        -H 'Accept-Encoding: zstd' \
        "http://$HOST:$PORT/index.html" 2>"$RAW/nodict.err"; then
    ok "request succeeded"
else
    notok "request succeeded"
    diag "curl stderr: $(cat "$RAW/nodict.err" 2>/dev/null || true)"
fi

if grep -qi '^content-encoding:[[:space:]]*zstd' "$HDRS" 2>/dev/null; then
    :
else
    diag "headers: $(tr -d '\r' <"$HDRS" 2>/dev/null | tr '\n' ' ')"
fi

if zstd -d -q -f -o "$BODY.dec" "$BODY" 2>/dev/null \
   && cmp -s "$BODY.dec" "$WWW/index.html"; then
    ok "response decodes byte-for-byte to the origin"
else
    notok "response decodes byte-for-byte to the origin"
fi

GOT="$(read_counter || echo -1)"
if [ "$GOT" -eq 3 ]; then
    ok "setParameter call count is 3 (level, windowLog, LDM -- none superseded)"
else
    diag "setparam_calls=$GOT expected=3"
    notok "setParameter call count is 3 (got $GOT)"
fi

# Direct frame-level check, same reasoning as the sibling
# setparam-call-count scenario's assert_window_cap: the call count above
# proves windowLog was SET on the CCtx, not that the resulting frame
# carries the operator's actual cap. This arm establishes the reference
# window (1 MiB, 2**20) the dictionary-mode oracles are compared against.
WANT_WINDOW=$((1 << 20))
GOT_WINDOW="$(zstd -l -v "$BODY" 2>/dev/null \
    | grep -oP 'Window Size:.*\(\K[0-9]+(?= B\))' | head -1)"
if [ -z "$GOT_WINDOW" ]; then
    notok "frame window size is $WANT_WINDOW B (zstd -l -v produced no Window Size line)"
elif [ "$GOT_WINDOW" -eq "$WANT_WINDOW" ]; then
    ok "frame window size is $WANT_WINDOW B"
else
    diag "frame Window Size=$GOT_WINDOW B expected=$WANT_WINDOW B"
    notok "frame window size is $WANT_WINDOW B (got $GOT_WINDOW B)"
fi

if grep -qE '\[(crit|alert|emerg)\]' "$ELOG" 2>/dev/null; then
    diag "$(grep -E '\[(crit|alert|emerg)\]' "$ELOG" | head -3)"
fi

exit "$FAILED"
