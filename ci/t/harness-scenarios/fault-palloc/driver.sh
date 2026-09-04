#!/usr/bin/env bash
#
# Scenario: POOL-ALLOCATION FAULT INJECTION for ngx_http_zstd_filter_module.so.
#
# Reachable only through the harness's TEST_HARNESS build (see the requires
# gate): the per-request allocation sites in the filter go through the
# ngx_http_zstd_{palloc,pnalloc,pcalloc,alloc_chain_link,list_push,
# pool_cleanup_add} wrappers, which consult the PALLOC fault site
# before delegating to the real allocator. Armed via
# GET /__probe?fault_palloc=<n>: the n-th WRAPPED allocation since the arm
# returns NULL. Negative disarms.
#
# WHY THIS SCENARIO EXISTS. Pool allocation failure is unprovokable in a
# normal test -- nginx's pool only fails when the OS refuses memory, and an
# ulimit big enough to force that kills the worker and every other oracle
# with it. So the NULL-check branch on each of those sites had no test at
# all: an unchecked NULL, or a half-mutated header list, would stay green
# forever. That is issues.md row m8.
#
# THE ORDINAL -> SITE MAP. Which wrapped allocation a given nth reaches is
# a property of this request (200 KB, zstd on, default buffer sizing), not a
# constant of the module. Measured on nginx 1.31.4 by logging __LINE__ at
# each wrapper call, the 6 wrapped allocations of one such request are:
#
#   nth   site                                           bytes on the wire?
#    1    ctx pcalloc, header filter                     no
#    2    Content-Encoding ngx_list_push, header filter  no
#    3    CCtx cleanup ngx_pool_cleanup_add              no
#    4    out_buf combined allocation                    no
#    5    emit chain link                                no
#    6    emit chain link                                YES
#
# WHERE "COMMITTED" ACTUALLY IS. Note that the boundary is NOT the header
# filter / body filter split, which is where one would expect it. nginx
# buffers the response, so ngx_http_send_header() returning does not put
# bytes on the wire; the status line only reaches the client once enough
# output has accumulated to flush. Measured on this request that happens
# between the 5th and 6th wrapped allocation -- so allocations 3..5 are in
# the body filter yet still fail with nothing delivered, and only 6 fails
# with a response already committed.
#
# That is why the two oracles below are split at 5/6 rather than at 2/3:
# the split has to follow the OBSERVABLE (has the client been promised a
# zstd stream yet?), because that is what decides which behaviour is
# correct. Splitting it where the code structure suggests would have made
# oracle 4 assert "200 was on the wire" for allocations where it never
# is, and the oracle would have been red for a reason that is not a defect.
#
# The oracles aim at 1..5 (uncommitted; every distinct site) and 6 (committed
# emit link). Incoming links are intentionally absent: the synchronously
# drained path now walks caller-owned links and allocates no wrappers. If the
# ordering ever changes, the counter assertions
# still hold but an oracle could silently start testing a different site --
# so each oracle names the site it believes it is hitting, and the mutation
# testing recorded in the PR is what ties an oracle to its guard.
#
# NON-VACUITY DISCIPLINE. Every oracle below asserts the fault ACTUALLY
# FIRED, not merely that the request misbehaved. A request can fail for
# reasons unrelated to the arm, and an arm the module silently DECLINEs
# (which is exactly what this site did before this change) leaves the
# request succeeding normally. Both would be indistinguishable from a real
# pass if the oracle only looked at the response. So each oracle checks the
# probe's palloc_calls counter advanced to the armed ordinal -- the
# observable that exists only when the wrapper ran and the site was armed.
set -euo pipefail

# shellcheck source=../../harness/ci/prober/lib.sh
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"

FAILED=0

mkdir -p "$PROBER_PREFIX/www"
# 200 KB: large enough to need several output buffers and several chain
# links, which is what puts allocation sites AFTER the header commit on the
# call sequence at all. A small body commits headers and finishes in one
# body-filter pass, and oracle 3 would have nothing to aim at.
head -c 204800 /dev/zero | tr '\0' 'a' >"$PROBER_PREFIX/www/body.bin"

# arm NTH / disarm: GET /__probe?fault_palloc=<nth>. Arming and reading are
# the same request (see ngx_http_zstd_probe_handler's arm-then-render
# comment), and arming RESETS the counter, so the counter read must come
# from a LATER, key-less /__probe request -- never from the arming one.
arm() {
    curl -fsS --max-time 5 \
        "http://$HOST:$PORT/__probe?fault_palloc=${1}" -o /dev/null
}

disarm() { arm -1; }

# palloc_calls: the module's wrapped-allocation counter, since the arm.
# A key-less /__probe neither arms nor resets.
palloc_calls() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe" \
        | sed 's/.*"palloc_calls":\([0-9]*\).*/\1/'
}

chain_links_allocated() {
    curl -fsS --max-time 5 "http://$HOST:$PORT/__probe" \
        | sed 's/.*"chain_links_allocated":\([0-9]*\).*/\1/'
}

# fetch: bounded GET of the compressible body. Headers to $2.hdrs, body to
# $2, curl's own diagnostic to $2.stderr. Returns curl's exit status --
# which matters here: the two failure classes this scenario separates are
# distinguished precisely by whether any response line was written before
# the connection went away.
fetch() {
    curl -sS --max-time 10 -D "$2.hdrs" -o "$2" \
        -H 'Accept-Encoding: zstd' \
        "http://$HOST:$PORT$1" 2>"$2.stderr"
}

# --- oracle plan --------------------------------------------------------
# 1  warm-up: a plain compressing request serves 200 (readiness), and
#    establishes how many wrapped allocations one such request makes
# 2  the PALLOC site is ARMABLE at all -- the counter advances. Before this
#    change fault_set_global returned NGX_DECLINED for PALLOC, so this
#    oracle is the one that fails outright on the old module
# 3  BEFORE anything is committed to the wire (nth=1 ctx pcalloc, 2
#    Content-Encoding list_push, 3 cleanup_add, 4 out_buf, 5 emit chain link
#    -- every distinct site on the uncommitted side): the
#    request fails closed with NO response line at all
# 4  AFTER the response is committed (nth=6 emit chain link): the 200 and
#    Content-Encoding: zstd ARE on the wire, and then the
#    connection is torn down mid-body rather than completing a truncated or
#    corrupt zstd stream. Completing the response is the defect this oracle
#    exists to catch
# 5  the fault is one-shot and per-arm: after disarming, a compressing
#    request serves a clean 200 again
# 6  an out-of-range nth is REFUSED rather than stored as an arm that can
#    never fire (the codec ZERO_BASE encoding does not apply to this site).
#    Observed via the counter, not the HTTP status -- see the oracle
# 7  no worker died by signal across the whole run
echo "1..7"

# --- 1: warm-up + establish the wrapped-allocation count ------------------
disarm || true
WARM="$PROBER_PREFIX/warm.out"
BASE_CALLS=0
if fetch /body.bin "$WARM" && grep -q '^HTTP/1.1 200' "$WARM.hdrs"; then
    BASE_CALLS=$(palloc_calls)
    BASE_INPUT_LINKS=$(chain_links_allocated)
    if [ "${BASE_CALLS:-0}" -gt 0 ] && [ "${BASE_INPUT_LINKS:-1}" -eq 0 ]; then
        echo "ok 1 - warm-up served a clean 200, made $BASE_CALLS wrapped pool allocations, and copied zero fully-drained input links"
    elif [ "${BASE_CALLS:-0}" -le 0 ]; then
        echo "not ok 1 - warm-up served 200 but the module reported ZERO wrapped allocations (palloc_calls=$BASE_CALLS) -- the wrappers are not on the request path, so every oracle below would assert nothing"
        FAILED=$((FAILED + 1))
    else
        echo "not ok 1 - warm-up copied $BASE_INPUT_LINKS input chain links even though it drained synchronously; expected zero lazy tail copies"
        FAILED=$((FAILED + 1))
    fi
else
    echo "not ok 1 - warm-up request did not serve a clean 200"
    FAILED=$((FAILED + 1))
fi

# --- 2: the PALLOC site is armable ----------------------------------------
#
# THE load-bearing non-vacuity oracle. fault_set_global used to answer
# NGX_DECLINED for NGX_TEST_PROBE_FAULT_PALLOC, which the testkit reports as
# "no hook at all": the arm silently did nothing and every request stayed
# normal. Asserting the counter advances to exactly the armed ordinal proves
# the arm was accepted AND that the wrapper consulted the site.
if arm 3; then
    fetch /body.bin "$PROBER_PREFIX/arm.out" || true
    SEEN=$(palloc_calls)
    if [ "${SEEN:-0}" -ge 3 ]; then
        echo "ok 2 - PALLOC site accepted the arm and the wrapped-allocation counter advanced (palloc_calls=$SEEN)"
    else
        echo "not ok 2 - PALLOC arm did not take effect (palloc_calls=$SEEN after arming nth=3) -- the site is refusing the arm, so no fault below can fire"
        FAILED=$((FAILED + 1))
    fi
else
    echo "not ok 2 - /__probe refused the fault_palloc arm outright"
    FAILED=$((FAILED + 1))
fi
disarm || true

# --- 3: allocation failure BEFORE anything is committed -------------------
#
# Every distinct site on the uncommitted side of the flush boundary: nth=1
# ctx pcalloc and nth=2 Content-Encoding ngx_list_push (header filter),
# nth=3 CCtx cleanup_add, nth=4 out_buf temp buffer, and nth=5 emit chain
# link (body filter, but still before the response
# flushes -- see the map above). In all of these the client has been
# promised nothing yet, so the correct outcome is fail-closed with nothing
# on the wire: NGX_ERROR finalizes the request and no status line is ever
# produced.
#
# nth=2 matters on its own. A half-mutated header list -- the push
# succeeding but its fields left unset, or the failure ignored -- is one of
# the concrete regressions this row was filed about, and it is invisible
# unless the allocation can actually be failed there.
#
# The counter check is what makes this non-vacuous: "no response line" is
# also what a dead worker or a wedged port produces, and neither has
# anything to do with the arm.
PRE_FAILED=0
PRE_DETAIL=""
for n in 1 2 3 4 5; do
    OUT="$PROBER_PREFIX/precommit.$n"
    rm -f "$OUT" "$OUT.hdrs"
    armed=0
    st=1
    if arm "$n"; then
        armed=1
        fetch /body.bin "$OUT" && st=0 || st=$?
    fi
    calls=$(palloc_calls)
    line=$(head -1 "$OUT.hdrs" 2>/dev/null | tr -d '\r' || true)
    if [ "$armed" -eq 1 ] && [ "${calls:-0}" -ge "$n" ] \
       && [ "$st" -ne 0 ] && [ -z "$line" ]
    then
        PRE_DETAIL="$PRE_DETAIL nth=$n(rc=$st,calls=$calls,ok)"
    else
        PRE_DETAIL="$PRE_DETAIL nth=$n(armed=$armed,calls=$calls,rc=$st,line='$line',BAD)"
        PRE_FAILED=1
    fi
    disarm || true
done
if [ "$PRE_FAILED" -eq 0 ]; then
    echo "ok 3 - allocation failure before the response is committed failed closed with no response line at all:$PRE_DETAIL"
else
    echo "not ok 3 - an uncommitted-side allocation failure did not fail closed as expected:$PRE_DETAIL"
    FAILED=$((FAILED + 1))
fi

# --- 4: allocation failure AFTER the response is committed ----------------
#
# The emit-link site reached past the flush boundary at nth=6. By this point
# "200 OK" and "Content-Encoding: zstd" really are on the wire, so it CANNOT be
# retracted
# -- the client has been promised a zstd stream. The only correct behaviour
# left is to abort the connection, so the client sees a truncated transfer
# (a hard, detectable error) instead of a complete-looking body that is not
# a valid zstd frame.
#
# So this oracle asserts BOTH halves: the 200 really was committed, AND the
# transfer did not complete. Asserting only the second half would also pass
# for a request that failed before ever sending headers -- that is oracle
# 3's case, a different branch, and conflating the two would let a
# regression in either one hide behind the other.
POST_FAILED=0
POST_DETAIL=""
n=6
OUT="$PROBER_PREFIX/postcommit.$n"
rm -f "$OUT" "$OUT.hdrs"
armed=0
st=1
if arm "$n"; then
    armed=1
    fetch /body.bin "$OUT" && st=0 || st=$?
fi
calls=$(palloc_calls)
got200=0
gotce=0
grep -q '^HTTP/1.1 200' "$OUT.hdrs" 2>/dev/null && got200=1
grep -qi '^Content-Encoding: *zstd' "$OUT.hdrs" 2>/dev/null && gotce=1
if [ "$armed" -eq 1 ] && [ "${calls:-0}" -ge "$n" ] \
   && [ "$got200" -eq 1 ] && [ "$gotce" -eq 1 ] && [ "$st" -ne 0 ]
then
    POST_DETAIL="$POST_DETAIL nth=$n(rc=$st,calls=$calls,ok)"
else
    POST_DETAIL="$POST_DETAIL nth=$n(armed=$armed,calls=$calls,200=$got200,ce=$gotce,rc=$st,BAD)"
    POST_FAILED=1
fi
disarm || true
if [ "$POST_FAILED" -eq 0 ]; then
    echo "ok 4 - allocation failure after the response is committed aborted the connection mid-body instead of completing a corrupt zstd stream:$POST_DETAIL"
else
    echo "not ok 4 - a post-commit allocation failure did not abort as expected (a completed transfer here means a truncated body was served as if valid):$POST_DETAIL"
    FAILED=$((FAILED + 1))
fi

# --- 5: disarming restores normal service ---------------------------------
CLEAN="$PROBER_PREFIX/clean.out"
if fetch /body.bin "$CLEAN" && grep -q '^HTTP/1.1 200' "$CLEAN.hdrs"; then
    echo "ok 5 - after disarming, a compressing request serves a clean 200 again (fault state is per-arm, not sticky)"
else
    echo "not ok 5 - a disarmed request did not serve a clean 200 -- fault state leaked past the arm"
    FAILED=$((FAILED + 1))
fi

# --- 6: an out-of-range nth is refused, not stored -------------------------
#
# 1000+ is the codec site's ZERO-outcome encoding and means nothing here.
# Storing it would arm allocation call 1000+, which no request ever reaches:
# the arm would look accepted and never fire, which is exactly the
# false-green class this surface exists to prevent.
#
# HOW REFUSAL IS OBSERVED. Not by HTTP status -- ngx_http_zstd_probe_handler
# discards ngx_test_probe_arm()'s return value on purpose (it renders the
# post-arm state either way), so a declined arm still answers 200 and
# `curl -f` cannot see it. The observable that DOES differ is the counter:
# accepting an arm resets palloc_calls to 0, refusing it leaves the counter
# untouched. So drive the counter to a known non-zero value first, then
# offer the bad arm and require the counter to have survived.
disarm || true
fetch /body.bin "$PROBER_PREFIX/pre-range.out" || true
BEFORE_BAD=$(palloc_calls)
arm 1001 || true
AFTER_BAD=$(palloc_calls)
if [ "${BEFORE_BAD:-0}" -gt 0 ] && [ "${AFTER_BAD:-0}" -eq "${BEFORE_BAD:-0}" ]; then
    echo "ok 6 - fault_palloc=1001 (out of this site's range) was refused, not stored: the counter was left untouched at $AFTER_BAD"
elif [ "${BEFORE_BAD:-0}" -le 0 ]; then
    echo "not ok 6 - could not establish a non-zero counter before offering the out-of-range arm (palloc_calls=$BEFORE_BAD), so refusal is unobservable and this oracle would assert nothing"
    FAILED=$((FAILED + 1))
else
    echo "not ok 6 - fault_palloc=1001 was ACCEPTED (counter reset $BEFORE_BAD -> $AFTER_BAD); the codec ZERO_BASE encoding does not apply to this site and storing it arms a call no request ever reaches"
    FAILED=$((FAILED + 1))
fi
disarm || true

# --- 7: no worker died by signal -------------------------------------------
#
# Every oracle above deliberately makes an allocation fail. If any of those
# branches dereferenced the NULL instead of handling it, the worker would
# have taken a SIGSEGV -- and oracles 3 and 4 would still have "passed",
# because a crashed worker also produces a torn-down connection. This is the
# oracle that separates "handled the failure" from "crashed on it".
if grep -qE 'worker process .* exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG"; then
    echo "not ok 7 - a worker died by signal -- an allocation-failure branch dereferenced NULL rather than handling it"
    grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$ELOG" | sed 's/^/# /'
    FAILED=$((FAILED + 1))
else
    echo "ok 7 - no worker died by signal across the whole allocation-fault run"
fi

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
