#!/usr/bin/env bash
#
# Scenario: ZSTD_compressStream2() CALL COUNT AT THE END-OF-FRAME SITE.
#
# The filter picks its ZSTD_EndDirective once per compress call. END is
# selected as soon as `ctx->last && ctx->in == NULL` holds -- i.e. on the call
# that carries the response's final input -- instead of one iteration later,
# after a ZSTD_e_continue call had already drained that input and the state
# machine transitioned COMPRESS->END. libzstd accepts pending input under
# ZSTD_e_end, consumes what it can and closes the frame in the same call, so
# the earlier selection removes one ZSTD_compressStream2() call from every
# completed response.
#
# WHAT THIS SCENARIO ASSERTS, AND WHY IT IS NOT VACUOUS.
#
# A correct response proves nothing about the call count: the two-call and the
# one-call sequences both produce a valid frame that decodes to the same
# plaintext. That is the whole difficulty of covering this change -- the
# observable it turns on is the COUNT, not the bytes. So every oracle here is
# a PAIR:
#
#   (a) the response decodes byte-for-byte to the origin file  -- correctness,
#       which must hold under both the optimized and the unoptimized path; and
#   (b) codec_end_calls for that one request equals the expected count       --
#       the marker unique to the new path, which goes red the moment the extra
#       ZSTD_e_continue iteration comes back.
#
# Dropping (b) leaves a suite that a revert passes. Dropping (a) leaves a
# suite that a fast, truncating filter passes. Both halves are load-bearing.
#
# HOW A PER-REQUEST CALL COUNT IS READ. ngx_http_zstd_probe_codec_fault()
# advances a per-site counter on every call and fault_set_global ZEROES that
# counter whenever the site is armed OR disarmed. So `fault_codec_end=-1`
# (a disarm) is also a counter RESET that leaves no fault armed. Reset, issue
# exactly ONE request, read /__probe: the counter is that request's call count
# at that site. Both sites are reset before each measurement so neither can
# carry a previous case's traffic into this one.
#
# The probe request itself never runs the body filter over a compressible
# response (the probe handler renders its own JSON and the /__probe location
# has no zstd directive), so reading the counter does not perturb it.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0
N=0

ok()     { N=$((N + 1)); echo "ok $N - $1"; }
notok()  { N=$((N + 1)); echo "not ok $N - $1"; FAILED=1; }
diag()   { echo "# $1"; }

WWW="$PROBER_PREFIX/www"
mkdir -p "$WWW" "$PROBER_PREFIX/tmp"

# Compressible body, large enough that the filter takes its streaming path
# (several ZSTD_compressStream2 calls, more than one out_buf) rather than a
# single trivial frame. A one-buffer response would leave the multi-call END
# epilogue -- the part most at risk from selecting END earlier -- untested.
{
    printf '<html><body>\n'
    i=0
    while [ "$i" -lt 4000 ]; do
        printf '<p>the quick brown fox jumps over the lazy dog %d</p>\n' "$i"
        i=$((i + 1))
    done
    printf '</body></html>\n'
} >"$WWW/index.html"

# A genuinely EMPTY body: the terminal chain link carries last_buf and no
# data whatsoever, so the response's only codec call is the END one.
: >"$WWW/empty.txt"

# The dcz and trained-dictionary arms use a dictionary this scenario's
# `requires` gate stages into the build's objs/ dir (see there for why that
# is the only hook early enough). The dcz arm additionally has to NEGOTIATE:
# the client must send Available-Dictionary carrying the dictionary's raw
# SHA-256 in the ":<base64>:" structured-field form, or the module answers
# plain zstd and the arm would measure the wrong path -- which the
# Content-Encoding assertion inside measure() catches rather than passing.
# PROBER_SERVER_BIN is the exported <build>/objs/nginx, so its dirname is
# the same objs/ dir @BUILD_OBJS@ renders into the conf.
DICT_FILE="$(dirname "$PROBER_SERVER_BIN")/codec-call-count.dict"
# openssl(1) presence is already proven by this scenario's `requires` gate, so
# an empty result here means the dictionary FILE is unreadable, not that the
# tool is missing -- which is why the failure branch below says so.
DICT_SHA_B64="$(openssl dgst -sha256 -binary "$DICT_FILE" 2>/dev/null \
                | openssl base64 -A 2>/dev/null || true)"

# reset_counters: disarm BOTH codec sites. A disarm zeroes that site's call
# counter (fault_set_global does it on every arm and every disarm alike), so
# this is the "start counting from here" primitive. Returns non-zero if the
# probe did not answer, so a measurement can never silently proceed on a
# counter that was not actually reset.
reset_counters() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe?fault_codec=-1" \
        -o /dev/null || return 1
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe?fault_codec_end=-1" \
        -o /dev/null || return 1
}

# read_counter NAME: echo one integer field from a fresh probe document.
read_counter() {
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    prober_probe_field "$body" "$1" || return 1
}

# fetch PATH OUTFILE [EXTRA_HEADER...]: one bounded GET that asks for zstd and
# writes the raw (still compressed) body to OUTFILE. --fail is deliberately
# NOT used: an arm that ends up serving 200-but-identity must be caught by the
# encoding assertion below, not silently by curl.
#
# A caller-supplied Accept-Encoding REPLACES the default rather than adding a
# second one. curl sends every -H it is given, and two Accept-Encoding header
# lines are not the same request as one: RFC 9842 SS8.3 makes the module
# decline dcz on a duplicated negotiation header, so the dcz arm silently fell
# back to plain zstd and measured the wrong path. (Caught by measure()'s
# Content-Encoding assertion, which is exactly why that assertion is there.)
fetch() {
    local path="$1" out="$2"; shift 2
    local hdrs="$out.hdrs" rc=0
    local -a extra=()
    local h have_ae=0
    for h in "$@"; do
        case "$h" in
            [Aa]ccept-[Ee]ncoding:*) have_ae=1 ;;
        esac
        extra+=(-H "$h")
    done
    [ "$have_ae" -eq 1 ] || extra=(-H 'Accept-Encoding: zstd' "${extra[@]}")
    curl -sS --max-time 15 -D "$hdrs" -o "$out" "${extra[@]}" \
        "http://$HOST:$PORT$path" 2>"$out.err" || rc=$?
    return "$rc"
}

# encoded_as HDRFILE ENC: did the response actually carry Content-Encoding:
# ENC? Guards every oracle against the vacuous case where the filter declined
# and the body is plain -- a call count of 0 would then be "correct" for a
# response the scenario is not measuring at all.
encoded_as() {
    grep -qi "^content-encoding:[[:space:]]*$2" "$1"
}

# decodes_to RAWFILE ORIGINFILE: the compressed body decodes byte-for-byte to
# the origin. This is half (a) of every oracle pair.
decodes_to() {
    local raw="$1" origin="$2" dec="$1.dec"
    zstd -d -q -f -o "$dec" "$raw" 2>/dev/null || return 1
    cmp -s "$dec" "$origin"
}

# measure LABEL PATH ORIGIN ENC EXPECT_TOTAL_CALLS [EXTRA_HEADER...]
#
# The whole oracle pair in one place: reset both counters, issue exactly one
# request, then assert (a) it was encoded as ENC and decodes to ORIGIN and
# (b) the response made EXPECT_TOTAL_CALLS ZSTD_compressStream2() calls in
# total, summed across BOTH sites.
#
# THE SUM, NOT codec_end_calls. This was measured, not assumed, and the
# distinction is the entire value of the oracle. The call this change removes
# is the redundant ZSTD_e_continue that used to precede the frame close, and
# a ZSTD_e_continue lands at the STREAMING site (CODEC), not the end-of-frame
# site (CODEC_END) -- the fault-injection split is keyed on
# `directive == ZSTD_e_end`. Both the optimized and the reverted path close
# the frame in exactly one END call, so codec_end_calls is 1 either way and
# an oracle asserting it passes on both: a textbook vacuous control. Reverting
# the optimization and re-running showed codec_end_calls unchanged at 1 while
# codec_calls moved 6 -> 7. The sum is what actually discriminates.
#
# EXPECT_TOTAL_CALLS is exact except for the comma-separated flush-last values
# documented below. The deterministic arms remain exact because those are what
# distinguish the optimized and reverted paths.
measure() {
    local label="$1" path="$2" origin="$3" enc="$4" expect="$5"; shift 5
    local raw="$PROBER_PREFIX/tmp/${label//\//_}.bin"
    local got

    if ! reset_counters; then
        notok "$label: probe did not answer the counter reset"
        notok "$label: total codec calls (not measured -- reset failed)"
        return
    fi

    if ! fetch "$path" "$raw" "$@"; then
        notok "$label: request failed or timed out"
        notok "$label: total codec calls (not measured -- request failed)"
        return
    fi

    if ! encoded_as "$raw.hdrs" "$enc"; then
        diag "$label: headers were: $(tr -d '\r' <"$raw.hdrs" | tr '\n' ' ')"
        notok "$label: response carried Content-Encoding: $enc"
        notok "$label: total codec calls (not measured -- wrong encoding)"
        return
    fi

    if decodes_to "$raw" "$origin"; then
        ok "$label: response decodes byte-for-byte to the origin"
    else
        notok "$label: response decodes byte-for-byte to the origin"
    fi

    local ends
    if ! got="$(read_counter codec_calls)" \
       || ! ends="$(read_counter codec_end_calls)"; then
        notok "$label: codec call count (probe field absent)"
        return
    fi
    got=$((got + ends))

    if [[ "$expect" != *,* ]] && [ "$got" -eq "$expect" ]; then
        ok "$label: total codec calls is $expect"
    elif [[ ",$expect," == *",$got,"* ]] && [ "$ends" -eq 1 ]; then
        ok "$label: total codec calls is ${expect//,/ or } (got $got; one END call)"
    else
        if [[ "$expect" == *,* ]]; then
            diag "$label: codec_calls+codec_end_calls=$got expected=$expect; codec_end_calls=$ends expected=1"
        else
            diag "$label: codec_calls+codec_end_calls=$got expected=$expect"
        fi
        notok "$label: total codec calls is ${expect//,/ or } (got $got)"
    fi
}

# --- oracle plan --------------------------------------------------------
#  1,2  default arm: many-buffer streaming body, ONE END call
#  3,4  tiny configured output buffers (zstd_buffers 4 4k)
#  5,6  data-less final buffer (empty body)
#  7,8  dcz framing (40-byte skippable prefix in the first buffer)
#  9,10 flush + last (proxy_buffering off)
# 11    a completed response makes at least one NON-end codec call too, so
#       the split between the two sites is real and oracle 2 is not counting
#       the whole response
# 12    client abort mid-response does not wedge the worker
# 13    error log carries no crit/alert/emerg across the whole run
#
# There is no separate trained-dictionary arm: zstd_dict_file is MAIN_CONF
# only, so enabling it would load the CDict for EVERY location here and move
# every count in the table below rather than isolating one arm. The dcz arm
# above is this scenario's dictionary-loaded CCtx coverage -- it goes through
# the same CDict-backed compressor, plus the skippable-prefix framing. The
# non-dcz trained-dictionary path keeps its existing coverage in ci/t/03-dcz.t
# and tools/test_dcz.py.
echo "1..13"

# EVERY EXPECTED COUNT BELOW WAS MEASURED, on this conf, against both the
# optimized and the reverted filter. Each one is exactly one lower with the
# optimization than without it, which is the row's claim stated as a number:
#
#   arm            optimized   reverted   delta
#   default            7           8       -1
#   tiny-buffers       7           8       -1
#   empty-body         1           2       -1
#   dcz                7           8       -1
#   flush-last       56/57       57/58      -1
#
# The first four rows are exact and intentionally brittle. The flush-last
# count additionally depends on how the kernel segments upstream reads with
# proxy_buffering off; both 56 and 57 have been observed across CI runners.
# Its decode oracle and exactly-one-END requirement cover flush+last behavior,
# while the four deterministic rows keep the removed call from creeping back.
#
# The flush-last arm's 56/57 reflects proxy_buffering off chunking the body into
# many small upstream writes, each of which drives its own compress calls.
# Its absolute value is an artifact of that chunking; its DELTA of one is the
# part that carries meaning, and it is the arm where a pending ctx->flush
# coexists with last_buf.

measure "default" "/index.html" "$WWW/index.html" zstd 7

# Tiny output buffers: the compressed body still fits well inside one 4k
# buffer's remaining space at the point the frame closes, so this stays 1 --
# but it reaches that point having already cycled several output buffers,
# which is the property being covered. If a future libzstd needs more than
# one END call here, this is the oracle that will say so, loudly, rather
# than a range that hides it.
measure "tiny-buffers" "/tiny/index.html" "$WWW/index.html" zstd 7

# Data-less final buffer: an empty body's terminal link carries last_buf and
# nothing else. Under the old two-call sequence this response reached END
# via the state machine's transition; now the directive selection picks END
# on the first and only call.
measure "empty-body" "/empty" "$WWW/empty.txt" zstd 1

# flush + last. proxy_buffering off makes the upstream force flushes around
# chunks the encoder buffers internally, so ctx->flush can still be pending
# when last_buf arrives. END must win the directive selection there -- if
# the pending flush won instead, the frame would never be closed and this
# request would hang until the 15s deadline rather than decode.
if [ -n "$DICT_SHA_B64" ]; then
    measure "dcz" "/dcz/index.html" "$WWW/index.html" dcz 7 \
        "Accept-Encoding: zstd, dcz" \
        "Available-Dictionary: :$DICT_SHA_B64:"
else
    # NOT a SKIP. openssl(1) is a hard requires-gate for this scenario, so
    # reaching here means the hash derivation failed for some other reason --
    # an unreadable or truncated dictionary file. A SKIP would print
    # "ok ... # SKIP", which reads as a pass to anything grepping for the
    # oracle, so the dcz arm would assert nothing while the run stayed green.
    # Fail loudly instead, and say what actually broke rather than blaming a
    # missing tool the gate already proved is present.
    notok "dcz: response decodes byte-for-byte to the origin (could not derive the dictionary hash from $DICT_FILE)"
    notok "dcz: total codec calls is 7 (not measured -- no dictionary hash)"
fi

measure "flush-last" "/flushlast" "$WWW/index.html" zstd 56,57

# The two sites really are split. If the END selection had swallowed the
# whole response (every call landing at the END site), codec_calls would be
# 0 and oracle 2's "1" would be counting the entire compression rather than
# just the frame close -- a passing number for the wrong reason.
if reset_counters \
   && fetch "/index.html" "$PROBER_PREFIX/tmp/split.bin" \
   && encoded_as "$PROBER_PREFIX/tmp/split.bin.hdrs" zstd; then
    NONEND="$(read_counter codec_calls || echo -1)"
    if [ "$NONEND" -ge 1 ]; then
        ok "streaming site is still reached ($NONEND non-END calls)"
    else
        diag "codec_calls=$NONEND"
        notok "streaming site is still reached (got $NONEND non-END calls)"
    fi
else
    notok "streaming site is still reached (request or reset failed)"
fi

# Client abort: tear the connection down mid-response and require the worker
# to still serve a clean, decodable 200 afterwards. A terminal-frame change
# that leaks a half-closed frame or wedges ctx->done would show up here as a
# dead or wrong follow-up response.
(
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET /index.html HTTP/1.1\r\nHost: prober\r\n' >&3
    printf 'Accept-Encoding: zstd\r\nConnection: close\r\n\r\n' >&3
    head -c 64 <&3 >/dev/null 2>&1 || true
) >/dev/null 2>&1 || true

if fetch "/index.html" "$PROBER_PREFIX/tmp/after-abort.bin" \
   && encoded_as "$PROBER_PREFIX/tmp/after-abort.bin.hdrs" zstd \
   && decodes_to "$PROBER_PREFIX/tmp/after-abort.bin" "$WWW/index.html"; then
    ok "a full response still decodes after a mid-response client abort"
else
    notok "a full response still decodes after a mid-response client abort"
fi

# No crit/alert/emerg anywhere in this run. This scenario injects no faults,
# so any such line is a real defect -- and the terminal-frame bug class this
# change touches announces itself exactly there ("zero size buf in writer").
if grep -qE '\[(crit|alert|emerg)\]' "$ELOG" 2>/dev/null; then
    diag "$(grep -E '\[(crit|alert|emerg)\]' "$ELOG" | head -3)"
    notok "error log carries no crit/alert/emerg lines"
else
    ok "error log carries no crit/alert/emerg lines"
fi

exit "$FAILED"
