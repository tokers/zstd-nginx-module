#!/usr/bin/env bash
#
# Scenario: CODEC FAULT-INJECTION ARMS for ngx_http_zstd_filter_module.so.
#
# Reachable only through the harness's TEST_HARNESS build (see
# plan-testkit-integration.md Ground truth + Phase 3): the module's single
# ZSTD_compressStream2() call site at filter_module.c is preceded by a fault
# check keyed on `directive == ZSTD_e_end` (site CODEC_END) vs. every other
# directive (site CODEC). Armed via GET /__probe?fault_codec=<n> or
# fault_codec_end=<n>: 1..999 injects a ZSTD_isError()-true return on the
# n-th call at that site since the arm; 1000+n injects success-with-
# zero-output on the n-th call.
#
# The same scenario owns the dedicated dcz setup site immediately before
# ZSTD_CCtx_refPrefix(). GET /__probe?fault_refprefix=<n> injects an error on
# its n-th call; the separately rendered refprefix_calls counter proves a
# plain zstd request cannot consume that dcz-only arm.
#
# Non-vacuity discipline copied from consumer-zstd/driver.sh: if the basis a
# set of oracles needs (a probe reading, a completed request) is missing,
# those oracles FAIL rather than SKIP-to-green. See "if every oracle SKIPs,
# red" in Phase 4's task list.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../../harness/ci/prober/lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
VLOG="$PROBER_PREFIX/logs/zstd-vars.log"

FAILED=0

mkdir -p "$PROBER_PREFIX/www"
# 200 KB body: big enough that a single ZSTD_compressStream2 call does not
# necessarily drain it in one shot (module's own buffer sizing), which is
# what makes the CODEC (non-end) site reachable at all on a real request --
# not just the CODEC_END site every response also passes through.
head -c 204800 /dev/zero | tr '\0' 'a' >"$PROBER_PREFIX/www/body.bin"
printf 'irrelevant\n' >"$PROBER_PREFIX/www/index.html"

# arm SITE NTH: GET /__probe?fault_<site>=<nth>, discard the body, return 0
# only if the probe answered at all (arming and reading are the same request
# here -- see ngx_http_zstd_probe_handler's "arm-then-render" comment).
arm() {
    local site="$1" nth="$2"
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_${site}=${nth}" -o /dev/null
}

# disarm SITE: same shape, negative nth.
disarm() {
    local site="$1"
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_${site}=-1" -o /dev/null
}

# fetch PATH OUTFILE [EXTRA_HEADER...]: bounded GET, writes headers and body
# separately, and returns the exit status of curl. Uses -D to capture
# headers separately so an ERROR outcome (nginx tears the connection down
# with no body) is still observable via headers-vs-no-headers, not just via
# curl's exit status, which a transfer-encoding mismatch can also trip.
fetch() {
    local path="$1" out="$2" hdrs="$2.hdrs"; shift 2
    local -a extra=(-H 'Accept-Encoding: zstd')
    if [ "$#" -gt 0 ]; then
        extra=()
        while [ "$#" -gt 0 ]; do
            extra+=(-H "$1")
            shift
        done
    fi
    curl -sS --max-time 10 -D "$hdrs" -o "$out" "${extra[@]}" \
        "http://$HOST:$PORT$path" 2>"$out.stderr"
}

# Wait for the last /body.bin log record to change.  The completed warm-up is
# the negative control: it must expose all three values.  The faulted request
# then has to append a distinct all-not-found record; reading a stale warm-up
# line would otherwise let an unreachable fault path pass.
wait_body_var_line() {
    local previous="$1" line deadline

    deadline=$((SECONDS + 5))
    while [ "$SECONDS" -lt "$deadline" ]; do
        line="$(awk '$1 == "/body.bin" { value = $0 } END { print value }' "$VLOG" 2>/dev/null || true)"
        if [ -n "$line" ] && [ "$line" != "$previous" ]; then
            printf '%s\n' "$line"
            return 0
        fi
        sleep 0.05
    done

    return 1
}

read_probe_field() {
    local field="$1"
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    prober_probe_field "$body" "$field"
}

DICT_FILE="$(dirname "$PROBER_SERVER_BIN")/fault-arms.dict"
DICT_SHA_B64="$(openssl dgst -sha256 -binary "$DICT_FILE" 2>/dev/null \
                | openssl base64 -A 2>/dev/null || true)"
DCZ_HEADERS=(
    'Accept-Encoding: zstd, dcz'
    "Available-Dictionary: :$DICT_SHA_B64:"
)

# --- oracle plan --------------------------------------------------------
# 1  warm-up: plain request serves 200 and emits completed log variables
# 2  CODEC ERROR (fault_codec=1) on a plain compressing request: the request
#    fails closed (no 200, connection torn down) rather than serving
#    corrupt/truncated compressed bytes and emits no completed log variables
#    -- proves the central ZSTD_isError arm is reachable, fails safely, and
#    cannot fabricate a final ratio from its partial counters
# 3  CODEC_END ERROR (fault_codec_end=1) on the SAME plain request: same
#    fail-closed assertion at the end-of-frame site specifically
# 4  CODEC_END ZERO on the 2nd END call (fault_codec_end=1002): forces the
#    empty-out_buf suppression arm and the response still completes fully
#    -- not a hang, not a torn-down connection. Deliberately nth=2, not 1:
#    see the oracle's own comment for the separate, real defect nth=1 hits
#    on this body (ledgered, not fixed here)
# 5  CODEC ERROR on the 2nd call (fault_codec=2): proves the non-END
#    streaming site is reached MORE THAN ONCE per response (a body this
#    size needs several ZSTD_compressStream2 calls to drain), by failing
#    that 2nd call closed the same way oracle 2 proves the 1st call fails
#    closed
# 6  disarming restores normal (uncorrupted) compression -- proves the
#    fault state is per-arm, not sticky
# 8  an unfaulted negotiated dcz request succeeds (normal-path control)
# 9  the upper valid boundary (999) arms, while malformed/out-of-range values
#    leave that arm unchanged
# 10 negative disarm clears that boundary arm
# 11 REFPREFIX armed at its lower boundary does not affect plain zstd and
#    the dedicated counter remains zero (dcz-only negative control)
# 12 the SAME still-armed fault is consumed by a negotiated dcz request,
#    which fails closed and logs the existing refPrefix error branch
# 13 arm-then-disarm before consumption leaves the first dcz call clean
# 14 no worker died by signal across the whole run
#
# Mutation accounting for the deliberately broad mutant-parity matcher. It
# counts both halves of each TAP verdict (success and failure echoes) as
# separate gates even though they share one condition. The named manual
# controls below were run against this scenario on 2026-08-28.
# mutant-exempt: oracle 8 is the positive dcz setup control, not a regression assertion
# mutant-exempt: oracle 8's not-ok echo is the other half of that one setup control
# mutant-exempt: oracle 9 failed when invalid input was mutated to clear the boundary-999 arm
# mutant-exempt: oracle 9's not-ok echo shares the same observed parser mutant
# mutant-exempt: oracle 10 failed when negative-value disarming was removed
# mutant-exempt: oracle 10's not-ok echo shares the same observed disarm mutant
# mutant-exempt: oracle 11 failed when the fault decision was moved above the dcz guard
# mutant-exempt: oracle 11's not-ok echo shares the same observed dcz-only mutant
# mutant-exempt: oracle 12 failed when the armed outcome returned REFPREFIX_NONE
# mutant-exempt: oracle 12's not-ok echo shares the same observed outcome mutant
# mutant-exempt: oracle 13 failed when the pre-consumption disarm was removed
# mutant-exempt: oracle 13's not-ok echo shares the same observed disarm mutant
# mutant-exempt: oracle 14 is the pre-existing signal-death assertion, renumbered only
echo "1..14"

# --- 1: warm-up -----------------------------------------------------------
WARMUP="$PROBER_PREFIX/warmup.out"
WARMUP_VARS=""
if fetch /body.bin "$WARMUP" \
    && grep -q '^HTTP/1.1 200' "$WARMUP.hdrs" \
    && WARMUP_VARS="$(wait_body_var_line '')" \
    && [[ "$WARMUP_VARS" =~ ^/body.bin\ [0-9]+\.[0-9]{3}\ [1-9][0-9]*\ [1-9][0-9]*$ ]]
then
    echo "ok 1 - warm-up request served a clean 200 with completed zstd log variables"
else
    echo "not ok 1 - warm-up request did not serve a clean 200 with completed zstd log variables (vars=${WARMUP_VARS:-missing})"
    FAILED=$((FAILED + 1))
fi

# --- 2: CODEC ERROR fails closed -------------------------------------------
#
# arm must succeed on its own -- a curl failure to even reach /__probe means
# nothing was armed, and the request that follows would then simply succeed
# for an unrelated reason (never armed), which must NOT read as "failed
# closed, ok 2". Armed-then-either(no-200-headers, fetch itself errored) is
# the fail-closed signature.
ERR_OUT="$PROBER_PREFIX/codec-err.out"
ARM2_OK=0
GOT200_2=0
FAULT_VARS=""
if arm codec 1; then
    ARM2_OK=1
    if fetch /body.bin "$ERR_OUT" && grep -q '^HTTP/1.1 200' "$ERR_OUT.hdrs" 2>/dev/null; then
        GOT200_2=1
    fi
    FAULT_VARS="$(wait_body_var_line "$WARMUP_VARS" || true)"
fi
if [ "$ARM2_OK" -eq 1 ] && [ "$GOT200_2" -eq 0 ] \
    && [ "$FAULT_VARS" = '/body.bin - - -' ]
then
    echo "ok 2 - CODEC ERROR (fault_codec=1) failed closed and exposed no completed zstd log variables"
else
    echo "not ok 2 - CODEC ERROR did not fail closed without fabricated log variables (arm_ok=$ARM2_OK; vars=${FAULT_VARS:-missing})"
    FAILED=$((FAILED + 1))
fi
disarm codec || true

# --- 3: CODEC_END ERROR fails closed ---------------------------------------
END_ERR_OUT="$PROBER_PREFIX/codec-end-err.out"
ARM3_OK=0
GOT200_3=0
if arm codec_end 1; then
    ARM3_OK=1
    if fetch /body.bin "$END_ERR_OUT" && grep -q '^HTTP/1.1 200' "$END_ERR_OUT.hdrs" 2>/dev/null; then
        GOT200_3=1
    fi
fi
if [ "$ARM3_OK" -eq 1 ] && [ "$GOT200_3" -eq 0 ]; then
    echo "ok 3 - CODEC_END ERROR (fault_codec_end=1) made the terminal-frame call fail closed"
else
    echo "not ok 3 - CODEC_END ERROR did not fail the request (arm_ok=$ARM3_OK)"
    FAILED=$((FAILED + 1))
fi
disarm codec_end || true

# --- 4: CODEC_END ZERO (2nd END call) completes cleanly ---------------------
#
# nth MUST be 1002 (2nd call at the END site), never 1001 (the 1st): with
# this body size, forcing zero output on the very FIRST ZSTD_e_end call
# reaches an existing, independent defect -- a genuinely empty terminal
# buffer that is emitted with last_buf set trips nginx core's
# "zero size buf in writer" guard and the connection is torn down mid-
# response (reproduced manually, filed as issues.md: forcing zero output on
# the first END call truncates the frame). That is real and ledgered
# separately; it is NOT what this oracle exists to assert, and using nth=1
# here would make Phase 4 ship a permanently-red gate for an unrelated,
# unfixed bug. nth=2 lands on a LATER END call, once real streaming has
# already produced output, which is the suppression arm this oracle
# actually targets (documented ok-for-3+ manually: 1002-1999 all complete
# cleanly on this body).
#
# "Completes with a 200" alone would be vacuous -- a compressible 200-KB body
# of identical bytes and an unfaulted request both give the same ~26-byte
# frame -- so the response must also DECODE: a complete, parseable zstd frame
# whose plaintext is byte-for-byte the origin file. A truncated or aborted
# transfer fails `zstd -d`, and a frame that decodes to the wrong bytes fails
# the cmp. Checking only `[ -s ]` here would accept both.
END_ZERO_OUT="$PROBER_PREFIX/codec-end-zero.out"
END_ZERO_OK=0
if arm codec_end 1002 && fetch /body.bin "$END_ZERO_OUT"; then
    if grep -q '^HTTP/1.1 200' "$END_ZERO_OUT.hdrs" \
        && ! grep -qE '^(curl:|$)' "$END_ZERO_OUT.stderr" 2>/dev/null \
        && [ -s "$END_ZERO_OUT" ] \
        && zstd -d -q -f -o "$END_ZERO_OUT.plain" "$END_ZERO_OUT" 2>/dev/null \
        && cmp -s "$END_ZERO_OUT.plain" "$PROBER_PREFIX/www/body.bin"
    then
        END_ZERO_OK=1
    fi
fi
if [ "$END_ZERO_OK" -eq 1 ]; then
    echo "ok 4 - CODEC_END ZERO (fault_codec_end=1002, 2nd END call) still completed with a full response (suppression arm reached past the first-call defect, no hang/truncation)"
else
    echo "not ok 4 - CODEC_END ZERO (2nd call) did not complete cleanly"
    FAILED=$((FAILED + 1))
fi
disarm codec_end || true

# --- 5: CODEC site is called MORE THAN ONCE -- fail-closed on the 2nd call -
#
# A single ZSTD_compressStream2() call rarely drains a 200-KB body (the
# module's own output buffer is much smaller), so the non-END (CODEC) site
# is called repeatedly across one response. fault_codec=2 (ERROR outcome,
# 2nd call) proves that second call is genuinely reached: if the loop
# somehow only ever ran the site once (e.g. a regression that emits
# everything from the first call, or that reroutes subsequent iterations
# around the fault check), nth=2 would never match and the request would
# complete normally instead of failing closed. Same fail-closed assertion
# shape as oracle 2 (which already covers nth=1); this is the nth-2+
# reachability half of the same arm.
ERR2_OUT="$PROBER_PREFIX/codec-err2.out"
ARM5_OK=0
GOT200_5=0
if arm codec 2; then
    ARM5_OK=1
    if fetch /body.bin "$ERR2_OUT" && grep -q '^HTTP/1.1 200' "$ERR2_OUT.hdrs" 2>/dev/null; then
        GOT200_5=1
    fi
fi
if [ "$ARM5_OK" -eq 1 ] && [ "$GOT200_5" -eq 0 ]; then
    echo "ok 5 - CODEC ERROR on the 2nd call (fault_codec=2) failed closed, proving the streaming site is reached more than once per response"
else
    echo "not ok 5 - CODEC ERROR on the 2nd call did not fail the request (arm_ok=$ARM5_OK; site called fewer than 2 times, or the fault check does not re-run)"
    FAILED=$((FAILED + 1))
fi
disarm codec || true

# --- 6: disarm restores normal compression ----------------------------------
RESTORE_OUT="$PROBER_PREFIX/restore.out"
RESTORE_OK=0
if fetch /body.bin "$RESTORE_OUT" && grep -q '^HTTP/1.1 200' "$RESTORE_OUT.hdrs"; then
    RESTORE_OK=1
fi
if [ "$RESTORE_OK" -eq 1 ]; then
    echo "ok 6 - after disarming, a compressing request serves a clean 200 again (fault state is per-arm, not sticky)"
else
    echo "not ok 6 - request after disarm did not serve a clean 200"
    FAILED=$((FAILED + 1))
fi

# --- 7: terminal zero-output END emits a WRITER-LEGAL zero-size last_buf ----
#
# fault_codec_end=1001 is the FIRST end-of-frame call producing no output --
# the arm oracle 4 deliberately avoids. The module must still emit the
# zero-length last_buf (the suppression arm lets it through on purpose), and
# nginx's writer only tolerates a zero-size buffer that ngx_buf_special()
# accepts: `(flush||last_buf||sync) && !ngx_buf_in_memory(b) && !b->in_file`.
# out_buf comes from ngx_http_zstd_create_temp_buf(), so `temporary` stays set
# and
# ngx_buf_in_memory() stays true even when the buffer is fully drained. That
# made ngx_http_write_filter log "zero size buf in writer" and abort the
# response mid-stream.
#
# The assertion is on the ALERT and the transfer, NOT on frame validity: this
# arm suppresses the real terminal call, so the body legitimately is not a
# complete zstd frame. Asserting `zstd -d` here would be asserting that an
# injected fault did not happen. What must hold is that the fault degrades the
# BODY without provoking a writer-level abort or a worker alert.
#
# Non-vacuity: the alert grep is scoped to lines logged after this point in
# the run, and the fetch must genuinely reach the module -- an arm that never
# fired would leave a full decodable frame, which the size check below rejects.
END_ZERO1_OUT="$PROBER_PREFIX/codec-end-zero1.out"
ELOG_MARK_7="$(wc -l < "$ELOG")"
ARM7_OK=0
if arm codec_end 1001 && fetch /body.bin "$END_ZERO1_OUT"; then
    ARM7_OK=1
fi
ZEROBUF_7=0
if [ "$(tail -n +$((ELOG_MARK_7 + 1)) "$ELOG" | grep -c 'zero size buf in writer' || true)" -gt 0 ]; then
    ZEROBUF_7=1
fi
if [ "$ARM7_OK" -eq 1 ] \
    && [ "$ZEROBUF_7" -eq 0 ] \
    && grep -q '^HTTP/1.1 200' "$END_ZERO1_OUT.hdrs" 2>/dev/null
then
    echo "ok 7 - CODEC_END ZERO on the FIRST end call emitted a writer-legal zero-size last_buf (no \"zero size buf in writer\", no aborted transfer)"
else
    echo "not ok 7 - first-call CODEC_END ZERO tripped the writer or aborted the response"
    tail -n +$((ELOG_MARK_7 + 1)) "$ELOG" | grep -n 'zero size buf in writer' | sed 's/^/# /'
    FAILED=$((FAILED + 1))
fi
disarm codec_end || true

# --- 8: unfaulted dcz normal path -------------------------------------------
DCZ_BASE_OUT="$PROBER_PREFIX/dcz-base.out"
DCZ_BASE_OK=0
if [ -n "$DICT_SHA_B64" ] \
    && fetch /dcz/body.bin "$DCZ_BASE_OUT" "${DCZ_HEADERS[@]}" \
    && grep -q '^HTTP/1.1 200' "$DCZ_BASE_OUT.hdrs" \
    && grep -qi '^Content-Encoding:[[:space:]]*dcz' "$DCZ_BASE_OUT.hdrs"
then
    DCZ_BASE_OK=1
fi
if [ "$DCZ_BASE_OK" -eq 1 ]; then
    echo "ok 8 - an unfaulted request negotiated dcz before the refPrefix error arm"
else
    echo "not ok 8 - dcz normal-path control did not negotiate a clean 200"
    FAILED=$((FAILED + 1))
fi

# --- 9: parser boundary and malformed-input controls -----------------------
# Manual mutation control (2026-08-28): changing the invalid-input branch to
# clear refprefix_armed made this named oracle turn red.
PARSER9_OK=1
if ! arm refprefix 999 \
    || [ "$(read_probe_field refprefix_armed || echo invalid)" != 999 ]
then
    PARSER9_OK=0
fi
for invalid in '' '-' 0 1000 10000 1junk; do
    if ! curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_refprefix=${invalid}" -o /dev/null \
        || [ "$(read_probe_field refprefix_armed || echo invalid)" != 999 ]
    then
        PARSER9_OK=0
    fi
done
if ! curl -fsS --max-time 5 \
    "http://$HOST:$PORT/__probe?xfault_refprefix=1" -o /dev/null \
    || [ "$(read_probe_field refprefix_armed || echo invalid)" != 999 ]
then
    PARSER9_OK=0
fi
if [ "$PARSER9_OK" -eq 1 ]; then
    echo "ok 9 - fault_refprefix accepts boundary 999 and rejects empty, malformed, out-of-range, and substring keys without changing the arm"
else
    echo "not ok 9 - fault_refprefix parser changed or lost the boundary-999 arm on invalid input"
    FAILED=$((FAILED + 1))
fi

# --- 10: negative disarm clears the boundary arm ---------------------------
# Manual mutation control (2026-08-28): removing the negative-value state
# reset made this named oracle and oracle 13 turn red. Use a value longer than
# the positive arm range to pin the "any non-empty negative" parser contract.
curl -fsS --max-time 5 \
    "http://$HOST:$PORT/__probe?fault_refprefix=-10000" -o /dev/null || true
if [ "$(read_probe_field refprefix_armed || echo invalid)" = 0 ]; then
    echo "ok 10 - a negative fault_refprefix value disarmed the boundary arm"
else
    echo "not ok 10 - negative fault_refprefix did not clear the armed state"
    FAILED=$((FAILED + 1))
fi

# --- 11: dedicated site is dcz-only ----------------------------------------
# Manual mutation control (2026-08-28): moving the fault decision above the
# ctx->dcz_dict guard made this named oracle turn red on the plain request.
PLAIN_CONTROL_OUT="$PROBER_PREFIX/refprefix-plain-control.out"
ARM11_OK=0
PLAIN11_OK=0
REFPREFIX_AFTER_PLAIN=-1
if arm refprefix 1; then
    ARM11_OK=1
    if fetch /body.bin "$PLAIN_CONTROL_OUT" \
        && grep -q '^HTTP/1.1 200' "$PLAIN_CONTROL_OUT.hdrs"
    then
        PLAIN11_OK=1
    fi
    REFPREFIX_AFTER_PLAIN="$(read_probe_field refprefix_calls || echo -1)"
fi
if [ "$ARM11_OK" -eq 1 ] && [ "$PLAIN11_OK" -eq 1 ] \
    && [ "$REFPREFIX_AFTER_PLAIN" -eq 0 ]
then
    echo "ok 11 - fault_refprefix=1 left plain zstd untouched and its dedicated counter at zero"
else
    echo "not ok 11 - plain zstd consumed or was affected by the dcz-only refPrefix arm (arm_ok=$ARM11_OK; plain_ok=$PLAIN11_OK; calls=$REFPREFIX_AFTER_PLAIN)"
    FAILED=$((FAILED + 1))
fi

# --- 12: negotiated dcz consumes REFPREFIX ERROR and fails closed -----------
# Manual mutation control (2026-08-28): returning REFPREFIX_NONE at the armed
# event made this named oracle turn red (got200=1, calls=1, log=0).
# Do not re-arm here. Oracle 11 proved the plain request did not consume the
# lower-bound nth=1 arm; this request must consume that same pending event.
REF_ERR_OUT="$PROBER_PREFIX/refprefix-err.out"
ELOG_MARK_12="$(wc -l < "$ELOG")"
GOT200_12=0
# Manual mutation control (2026-08-28): inverting the empty-body check made
# this named oracle turn red. A reset or truncated response is acceptable
# here only when no representation bytes escaped before the connection failed.
if (fetch /dcz/body.bin "$REF_ERR_OUT" "${DCZ_HEADERS[@]}" \
    && grep -q '^HTTP/1.1 200' "$REF_ERR_OUT.hdrs" 2>/dev/null) \
    || [ -s "$REF_ERR_OUT" ]
then
    GOT200_12=1
fi
REFPREFIX_AFTER_DCZ="$(read_probe_field refprefix_calls || echo -1)"
REFPREFIX_LOG_12=0
if tail -n +$((ELOG_MARK_12 + 1)) "$ELOG" \
    | grep -q 'zstd: ZSTD_CCtx_refPrefix() failed:'
then
    REFPREFIX_LOG_12=1
fi
if [ "$GOT200_12" -eq 0 ] && [ "$REFPREFIX_AFTER_DCZ" -eq 1 ] \
    && [ "$REFPREFIX_LOG_12" -eq 1 ]
then
    echo "ok 12 - negotiated dcz consumed fault_refprefix=1 and the existing refPrefix error branch failed closed"
else
    echo "not ok 12 - refPrefix fault was not reached or did not fail closed (got200=$GOT200_12; calls=$REFPREFIX_AFTER_DCZ; log=$REFPREFIX_LOG_12)"
    FAILED=$((FAILED + 1))
fi

# --- 13: arm-then-disarm before consumption restores normal dcz ------------
# Re-arm first: the previous nth=1 event has already fired, so merely
# disarming it here would be vacuous. Deleting this disarm must make the first
# dcz call below fail. That mutation was run on 2026-08-28 and made this named
# oracle turn red.
ARM13_OK=0
DISARM13_OK=0
if arm refprefix 1 \
    && [ "$(read_probe_field refprefix_armed || echo invalid)" = 1 ]
then
    ARM13_OK=1
fi
if [ "$ARM13_OK" -eq 1 ] && disarm refprefix \
    && [ "$(read_probe_field refprefix_armed || echo invalid)" = 0 ]
then
    DISARM13_OK=1
fi
DCZ_RESTORE_OUT="$PROBER_PREFIX/dcz-restore.out"
if [ "$ARM13_OK" -eq 1 ] && [ "$DISARM13_OK" -eq 1 ] \
    && fetch /dcz/body.bin "$DCZ_RESTORE_OUT" "${DCZ_HEADERS[@]}" \
    && grep -q '^HTTP/1.1 200' "$DCZ_RESTORE_OUT.hdrs" \
    && grep -qi '^Content-Encoding:[[:space:]]*dcz' "$DCZ_RESTORE_OUT.hdrs"
then
    echo "ok 13 - arm-then-disarm left the first negotiated dcz request clean"
else
    echo "not ok 13 - arm/disarm setup failed or dcz failed afterwards (arm_ok=$ARM13_OK; disarm_ok=$DISARM13_OK)"
    FAILED=$((FAILED + 1))
fi

# --- 14: no signal-death across the run ------------------------------------
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 14 - a worker died by signal during fault injection"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 14 - no worker died by signal across the whole fault-injection run"
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
