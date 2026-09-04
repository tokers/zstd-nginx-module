#!/usr/bin/env bash
#
# Scenario: PER-REQUEST ALLOCATION NEUTRALITY for ngx_http_zstd_filter_module.
#
# The module serves real compressed responses and this driver proves the
# per-request work is allocation-neutral: cycle-pool counters (cycle_used,
# cycle_blocks, cycle_large), worker fd count and MASTER fd count are all
# identical across two post-drain QUIESCENT snapshots taken around one extra
# full served request. Equal means the per-request path frees everything it
# allocates.
#
# WHY THIS LIVES HERE AND NOT UPSTREAM. testkit ships an equivalent oracle at
# ci/prober/scenarios/consumer-zstd, but it load_modules a consumer .so out of
# testkit's gitignored consumers/ dir, so it SKIPs on every remote leg there --
# permanently, by its own requires-gate comment: "Nothing in CI will tell you a
# consumer regressed... a SKIP reads as a pass." In THIS repo the .so is our own
# build product, so the same oracle actually runs. That is the whole point of
# re-homing it: a skipping oracle is not coverage.
#
# DESIGN NOTE (inherited from testkit's consumer-cache-turbo, the hand-written
# reference): a per-request-leak oracle canNOT use a COLD pre-request baseline
# -- that carries the module's startup one-off -- nor a mid-work snapshot, which
# flakes on live per-request buffers. Two post-drain quiescent snapshots around
# one extra request is the shape that works.
#
# The module's config-time state (parsed dictionaries, hashed dcz strings) is
# allocated once at parse time, NOT per request, so it must not appear as a
# per-request delta; that absence is exactly the property under test.
set -euo pipefail

# shellcheck source=lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
MASTER="$PROBER_SERVER_PID"

export PROBER_ERROR_LOG="$ELOG"

FAILED=0

# The docroot the conf's `root @PREFIX@/www` points at. Compressible content,
# and large enough that the filter takes its streaming path (several
# ZSTD_compressStream2 calls and at least one out_buf) rather than a single
# trivial frame -- a one-buffer response would exercise far less of the
# per-request allocation surface this scenario is measuring.
mkdir -p "$PROBER_PREFIX/www"
{
    printf '<html><body>\n'
    i=0
    while [ "$i" -lt 400 ]; do
        printf '<p>the quick brown fox jumps over the lazy dog %d</p>\n' "$i"
        i=$((i + 1))
    done
    printf '</body></html>\n'
} >"$PROBER_PREFIX/www/index.html"

# master_fds: open descriptor count of the MASTER process. /proc/$MASTER/fd is
# not readable on every host, so a failed read is "cannot observe" -- surfaced
# as a visible SKIP on oracle 6, never as a passing zero.
master_fds() {
    [ -r "/proc/$MASTER/fd" ] || return 1
    # shellcheck disable=SC2012  # /proc fd names are decimal ints, ls|wc is exact
    ls "/proc/$MASTER/fd" 2>/dev/null | wc -l
}

snapshot() {             # read one probe snapshot into SNAP_* globals
    local body
    body="$(prober_probe_body "$HOST" "$PORT")" || return 1
    SNAP_USED="$(prober_probe_field "$body" cycle_used)" || return 1
    SNAP_BLOCKS="$(prober_probe_field "$body" cycle_blocks)" || return 1
    SNAP_LARGE="$(prober_probe_field "$body" cycle_large)" || return 1
    SNAP_FDS="$(prober_probe_field "$body" fds)" || return 1
}

# one_request OUTFILE [EXTRA_HEADER]: drive ONE full GET / to completion under
# a bounded deadline. A hung fetch must not hang the scenario, and a truncated
# capture must not be trusted as a completed request -- that would make the
# quiescent snapshot around it meaningless.
one_request() {
    local out="$1" extra="${2:-}" pid dl timed_out=0
    (
        exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
        printf 'GET / HTTP/1.1\r\nHost: prober\r\n' >&3
        [ -n "$extra" ] && printf '%s\r\n' "$extra" >&3
        printf 'Connection: close\r\n\r\n' >&3
        cat <&3 2>/dev/null || true
    ) >"$out" 2>/dev/null &
    pid=$!
    dl=$(( SECONDS + 10 ))
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$SECONDS" -ge "$dl" ]; then
            pkill -P "$pid" 2>/dev/null || true
            kill "$pid" 2>/dev/null || true
            timed_out=1
            break
        fi
        sleep 0.05
    done
    wait "$pid" 2>/dev/null || true
    # The deadline kill leaves the status line already in the capture, so the
    # grep below cannot tell a completed response from one cut off mid-body.
    # Without this the snapshot pair could straddle a request the worker still
    # holds buffers for, and oracles 3-6 would compare against a mid-flight
    # reading.
    [ "$timed_out" -eq 0 ] || return 1
    grep -q '^HTTP/1.1 200' "$out"
}

# TAP plan:
#  1 warm-up request serves 200 (readiness / non-vacuity)
#  2 the filter demonstrably COMPRESSED a response (anti-vacuity)
#  3 cycle_used equal across the two post-drain quiescent snapshots
#  4 cycle_blocks + cycle_large equal across the same two snapshots
#  5 worker fds equal across the same two snapshots
#  6 master fd count flat across the same window
#  7 no signal-death in the error log + a strict clean 200 on a final request
echo "1..7"

# --- 1: warm-up -- settles the worker so request 2 onward is steady-state ----
# Deliberately a COMPRESSING warm-up (Accept-Encoding: zstd): the compressor's
# first-use one-off allocations must land BEFORE the measured window, or
# oracle 3 would attribute that startup cost to the measured request.
WARMUP="$PROBER_PREFIX/warmup.out"
WARMUP_OK=0
if one_request "$WARMUP" "Accept-Encoding: zstd"; then
    WARMUP_OK=1
fi
if [ "$WARMUP_OK" -eq 1 ]; then
    echo "ok 1 - the warm-up request served a clean 200 (server is ready)"
else
    echo "not ok 1 - the warm-up request did not complete as a clean 200"
    head -5 "$WARMUP" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- 2: anti-vacuity ---------------------------------------------------------
# REAL ANTI-VACUITY. nginx core never emits Content-Encoding: zstd by itself --
# only this module does. Take `zstd on;` out of the conf and THIS oracle fails,
# which is what makes oracles 3-6 worth reading: they are measuring a request
# the module demonstrably participated in, not an unfiltered static file.
HITCHECK="$PROBER_PREFIX/hitcheck.out"
SIG_SEEN=0
if [ "$WARMUP_OK" -eq 1 ] && one_request "$HITCHECK" "Accept-Encoding: zstd"; then
    if grep -qiE '^Content-Encoding:[[:space:]]*zstd' "$HITCHECK"; then
        SIG_SEEN=1
    fi
fi
if [ "$SIG_SEEN" -eq 1 ]; then
    echo "ok 2 - the zstd filter COMPRESSED the response and set Content-Encoding: zstd (nginx never emits that header by itself)"
else
    echo "not ok 2 - no signature that the zstd filter ran was observed"
    head -20 "$HITCHECK" 2>/dev/null | sed 's/^/# /' || true
    FAILED=$((FAILED + 1))
fi

# --- oracle-3..6 measurement: two QUIESCENT snapshots around one more request
#
# A silent probe endpoint is a BROKEN tree, not an unmet environmental
# requirement: @PROBE@ is in this scenario's conf unconditionally and the
# requires gate has already established the .so carries the probe symbols. If
# oracles 3-6 all SKIP, the only surviving oracles are 1, 2 and 7 -- none of
# which touch an allocation metric -- so the scenario would exit 0 having
# asserted nothing about the property in its own title. That is a vacuous
# green, so it reds instead.
BASE_OK=1
if ! snapshot; then
    BASE_OK=0
    echo "# the probe endpoint did not answer for the first post-drain snapshot"
fi
if [ "$BASE_OK" -eq 1 ]; then
    BASE_USED="$SNAP_USED"; BASE_BLOCKS="$SNAP_BLOCKS"; BASE_LARGE="$SNAP_LARGE"; BASE_FDS="$SNAP_FDS"
fi
BASE_MFDS="$(master_fds || true)"

STIM="$PROBER_PREFIX/stimulus.out"
STIM_OK=0
if [ "$BASE_OK" -eq 1 ] && one_request "$STIM" "Accept-Encoding: zstd"; then
    STIM_OK=1
fi

FINAL_OK=0
if [ "$STIM_OK" -eq 1 ] && snapshot; then
    FINAL_OK=1
    FINAL_USED="$SNAP_USED"; FINAL_BLOCKS="$SNAP_BLOCKS"; FINAL_LARGE="$SNAP_LARGE"; FINAL_FDS="$SNAP_FDS"
fi
FINAL_MFDS="$(master_fds || true)"

if [ "$STIM_OK" -ne 1 ]; then
    echo "# the extra measured request did not complete -- oracles 3-6 will SKIP rather than compare against a vacuous reading"
fi

if [ "$BASE_OK" -eq 0 ] || [ "$STIM_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "# oracles 3-6 cannot be evaluated (base=$BASE_OK stim=$STIM_OK final=$FINAL_OK); failing rather than banking a green"
    FAILED=$((FAILED + 1))
fi

# --- 3: cycle_used flat -------------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 3 - cycle_used allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_USED" = "$FINAL_USED" ]; then
    echo "ok 3 - cycle_used was flat across the extra compressed request ($BASE_USED)"
else
    echo "not ok 3 - cycle_used grew across the extra compressed request (before=$BASE_USED after=$FINAL_USED)"
    FAILED=$((FAILED + 1))
fi

# --- 4: cycle_blocks + cycle_large flat --------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 4 - cycle_blocks/cycle_large allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_BLOCKS" = "$FINAL_BLOCKS" ] && [ "$BASE_LARGE" = "$FINAL_LARGE" ]; then
    echo "ok 4 - cycle_blocks ($BASE_BLOCKS) and cycle_large ($BASE_LARGE) were flat across the extra compressed request"
else
    echo "not ok 4 - cycle_blocks/cycle_large grew across the extra compressed request (before blocks=$BASE_BLOCKS large=$BASE_LARGE, after blocks=$FINAL_BLOCKS large=$FINAL_LARGE)"
    FAILED=$((FAILED + 1))
fi

# --- 5: worker fds flat -------------------------------------------------------
if [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 5 - worker fds allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_FDS" = "$FINAL_FDS" ]; then
    echo "ok 5 - worker fd count was flat across the extra compressed request ($BASE_FDS)"
else
    echo "not ok 5 - worker fd count grew across the extra compressed request (before=$BASE_FDS after=$FINAL_FDS)"
    FAILED=$((FAILED + 1))
fi

# --- 6: master fd count flat --------------------------------------------------
if [ -z "$BASE_MFDS" ] || [ -z "$FINAL_MFDS" ]; then
    echo "ok 6 - master descriptor count # SKIP /proc/$MASTER/fd not readable on this host"
elif [ "$BASE_OK" -eq 0 ] || [ "$FINAL_OK" -eq 0 ]; then
    echo "ok 6 - master descriptor count allocation-neutrality # SKIP a post-drain snapshot did not answer"
elif [ "$BASE_MFDS" = "$FINAL_MFDS" ]; then
    echo "ok 6 - master fd count was flat across the extra compressed request ($BASE_MFDS)"
else
    echo "not ok 6 - master fd count grew across the extra compressed request (before=$BASE_MFDS after=$FINAL_MFDS)"
    FAILED=$((FAILED + 1))
fi

# --- 7: no signal-death + a final strict clean 200 ---------------------------
SIGDEATH=0
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    SIGDEATH=1
fi

FINAL_REQ="$PROBER_PREFIX/final.out"
FINAL_CLEAN=0
if one_request "$FINAL_REQ" "Accept-Encoding: zstd"; then
    FINAL_CLEAN=1
fi

if [ "$SIGDEATH" -eq 0 ] && [ "$FINAL_CLEAN" -eq 1 ]; then
    echo "ok 7 - no worker died by signal, and a final request still served a clean 200"
else
    echo "not ok 7 - server health check failed (signal-death=$SIGDEATH, final-clean=$FINAL_CLEAN)"
    if [ "$SIGDEATH" -eq 1 ]; then
        grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    fi
    FAILED=$((FAILED + 1))
fi

exit "$(( FAILED > 0 ? 1 : 0 ))"
