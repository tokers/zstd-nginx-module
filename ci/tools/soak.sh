#!/usr/bin/env bash
#
# Sustained mixed-load soak for the zstd filter. Drives a real nginx
# (ideally an ASAN/UBSAN build, optionally under valgrind) with
# concurrent, varied requests for a fixed duration, then asserts the
# worker survived cleanly: no sanitizer report, no crash, no leak, no
# error-log [alert]/[emerg]. This is the "survives production-shaped
# load" check that synthetic single-shot tests do not give.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 120 8
#
# Exit non-zero on ANY of: sanitizer error, valgrind error, nginx
# crash/non-clean exit, error-log alert/emerg, or a corrupted response.

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"
SOAK_SEED="${SOAK_SEED:-$(( $(date +%s) & 0x7fffffff ))}"

if ! [[ "$SOAK_SEED" =~ ^[0-9]+$ ]]; then
    echo "FAIL: SOAK_SEED must be an integer from 0 through 2147483647" >&2
    exit 2
fi
SOAK_SEED="$(printf '%s' "$SOAK_SEED" | sed 's/^0*//')"
SOAK_SEED="${SOAK_SEED:-0}"
if [ "${#SOAK_SEED}" -gt 10 ] \
    || { [ "${#SOAK_SEED}" -eq 10 ] && [ "$SOAK_SEED" -gt 2147483647 ]; }
then
    echo "FAIL: SOAK_SEED must be an integer from 0 through 2147483647" >&2
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# Mixed payload sizes: tiny (sub-min_length), medium, large (multi-buffer),
# and a chunked/no-Content-Length upstream path.
head -c 50 /dev/urandom | base64 >"$WORK/html/tiny"
head -c 200000 /dev/urandom | base64 >"$WORK/html/medium"
head -c 4000000 /dev/urandom | base64 >"$WORK/html/large"
printf 'AAAAAAAAAA%.0s' $(seq 1 20000) >"$WORK/html/compressible"

# RFC 9842 dcz dictionary. The soak previously sent only zstd/gzip, so the
# whole dcz path -- negotiation, ZSTD_CCtx_refPrefix, the 40-byte frame
# header, dictionary lifetime across requests -- ran under NEITHER sanitizer
# lane despite being the newest and largest block of code in the module.
# The dictionary content overlaps the response bodies below so refPrefix has
# real matches to find rather than compressing a miss.
printf 'shared-boilerplate compute render %.0s' $(seq 1 200) \
    >"$WORK/html/dcz-dict"
DICT_B64="$(openssl dgst -sha256 -binary "$WORK/html/dcz-dict" | base64)"
printf 'shared-boilerplate compute render %.0s' $(seq 1 400) \
    >"$WORK/html/dczbody"

cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;
    zstd_window_log 21;
    server {
        listen 127.0.0.1:18222;
        root $WORK/html;
        default_type text/plain;
        location / {
            zstd on;
            zstd_min_length 100;
            zstd_max_length 8m;
            zstd_types text/plain;
        }
        location /dcz {
            zstd on;
            zstd_min_length 100;
            zstd_types text/plain;
            # RFC 9842 section 8 restricts dcz to secure contexts, and
            # this soak listener is plain HTTP -- the sanitizer and
            # valgrind nginx builds it runs against have no
            # ngx_http_ssl_module, so it cannot be anything else. The
            # acknowledgement models the supported TLS-terminating-proxy
            # deployment and keeps the dcz path (negotiation,
            # ZSTD_CCtx_refPrefix, the 40-byte frame header) under the
            # sanitizers, which is the whole point of exercising it here.
            zstd_dcz_assume_secure_transport on;
            zstd_dcz_dict_file $WORK/html/dcz-dict;
            alias $WORK/html/dczbody;
        }
        location /bypass {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            zstd_bypass \$arg_nozstd;
            alias $WORK/html/medium;
        }
    }
}
EOF

export DICT_B64

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:verbosity=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    SUPP="$(cd "$(dirname "$0")/../.." && pwd)/ci/suppressions/valgrind.suppress"
    RUN=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --suppressions="$SUPP" --gen-suppressions=all --log-file="$WORK/logs/valgrind.%p"
        "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Data-race / lock-order checking under helgrind (thread pool + any
    # shared state). Reuses the same suppression file.
    SUPP="$(cd "$(dirname "$0")/../.." && pwd)/ci/suppressions/valgrind.suppress"
    RUN=(valgrind --tool=helgrind --error-exitcode=99
        --suppressions="$SUPP" --gen-suppressions=all --log-file="$WORK/logs/helgrind.%p"
        "${RUN[@]}")
fi

"${RUN[@]}" &
NGINX_PID=$!

ready=0
for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://127.0.0.1:18222/tiny" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "FAIL: nginx never became ready (no successful /tiny request in 10s)" >&2
    kill "$NGINX_PID" 2>/dev/null || true
    tail -40 "$WORK/logs/error.log" || true
    exit 1
fi

echo "soak: ${DURATION}s, concurrency ${CONC}$(
    [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'
    [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)'
)"
echo "soak: seed $SOAK_SEED (replay with SOAK_SEED=$SOAK_SEED)"
END=$(($(date +%s) + DURATION))
fail=0

worker() {
    local wid="$1"
    local paths=(/tiny /medium /large /compressible
        "/bypass" "/bypass?nozstd=1" /dcz)
    local prefix_paths=(/tiny /tiny /medium /medium /large /large
        /compressible /bypass "/bypass?nozstd=1" /dcz /dcz)
    local prefix_aes=(gzip zstd gzip zstd gzip zstd zstd zstd zstd zstd dcz)
    local prefix_count=${#prefix_paths[@]}
    local i=0 ok=0 bad=0 dcz_seen=0 rng=$(((10#$SOAK_SEED + wid) & 0x7fffffff))
    local -a counts
    for ((cell = 0; cell < prefix_count; cell++)); do counts[cell]=0; done
    while [ "$i" -lt "$prefix_count" ] || [ "$(date +%s)" -lt "$END" ]; do
        if [ "$i" -lt "$prefix_count" ]; then
            p=${prefix_paths[$i]}
            ae=${prefix_aes[$i]}
            cell=$i
        else
            rng=$(((1103515245 * rng + 12345) & 0x7fffffff))
            p=${paths[$((rng % ${#paths[@]}))]}
            rng=$(((1103515245 * rng + 12345) & 0x7fffffff))
            ae=$([ $((rng % 4)) -eq 0 ] && echo "gzip" || echo "zstd")
            cell=-1
        fi
        i=$((i + 1))
        body="$WORK/r.${wid}.${i}"
        # The prefix has separate /dcz plain-zstd and negotiated-dcz cells,
        # so both the fallback and refPrefix paths always run. dcz_seen below
        # additionally proves that negotiation produced a real dcz frame.
        dcz_want=0
        bad_before=$bad
        hdrs=(-H "Accept-Encoding: $ae")
        if [ "$ae" = "dcz" ]; then
            p=/dcz
            dcz_want=1
            ae=zstd
            hdrs=(-H "Accept-Encoding: zstd, dcz"
                  -H "Available-Dictionary: :${DICT_B64}:"
                  -H "Sec-Fetch-Site: same-origin")
        fi
        identity_want=0
        if [ "$ae" != "zstd" ] || [ "$p" = "/tiny" ] \
            || [ "$p" = "/bypass?nozstd=1" ]
        then
            identity_want=1
        fi
        if curl -fsS "${hdrs[@]}" \
            "http://127.0.0.1:18222$p" -o "$body" 2>/dev/null; then
            # Every served response variant must be enumerated explicitly.
            # Unrecognized magics are a hard failure, not a silent pass.
            #
            # Legitimate response variants:
            # 1. Plain zstd: magic 28b52ffd (all paths except /bypass?nozstd=1)
            # 2. DCZ skippable frame: magic 5e2a4d18 (from /dcz with negotiation)
            # 3. Identity/uncompressed: no magic (only /bypass?nozstd=1, which
            #    has zstd_bypass active, so the response is not compressed)
            #
            # A dcz response starts with 5e2a4d18, NOT 28b52ffd, so testing
            # only for the zstd magic would let every dcz response fall through
            # and count as ok without ever being decoded. Decode dcz against
            # the same dictionary the request advertised: that verifies the
            # frame header, the refPrefix output and the dictionary content.
            magic="$(head -c4 "$body" | od -An -tx1 | tr -d ' ')"
            if [ "$identity_want" -eq 1 ]; then
                if [ "$magic" = "28b52ffd" ] || [ "$magic" = "5e2a4d18" ]; then
                    echo "BAD compressed identity-only cell $p (Accept-Encoding: $ae, magic: $magic)"
                    bad=$((bad + 1))
                else
                    ok=$((ok + 1))
                fi
            elif [ "$magic" = "28b52ffd" ]; then
                if zstd -dq -c "$body" >/dev/null 2>&1; then
                    ok=$((ok + 1))
                else
                    echo "BAD zstd $p"
                    bad=$((bad + 1))
                fi
            elif [ "$magic" = "5e2a4d18" ]; then
                if zstd -dq -D "$WORK/html/dcz-dict" -c "$body" \
                    >/dev/null 2>&1; then
                    ok=$((ok + 1))
                    dcz_seen=$((dcz_seen + 1))
                else
                    echo "BAD dcz $p"
                    bad=$((bad + 1))
                fi
            elif [ "$dcz_want" -eq 1 ]; then
                # Asked for dcz with a matching dictionary and a
                # same-origin fetch, and got something that is neither a
                # dcz frame nor a zstd frame.
                echo "BAD dcz $p: negotiated request returned magic $magic"
                bad=$((bad + 1))
            else
                # Every other combination (ae advertised zstd, and the path
                # is not sub-min_length or bypassed) must have compressed.
                # Identity here is a real "we stopped compressing"
                # regression, not a benign variant.
                echo "BAD unknown magic $magic $p (Accept-Encoding: $ae)"
                bad=$((bad + 1))
            fi

            # A negotiated request that came back as a plain zstd frame is
            # a dcz regression, not a pass: the gate silently declined and
            # the 28b52ffd branch above would otherwise have accepted it.
            if [ "$dcz_want" -eq 1 ] && [ "$magic" = "28b52ffd" ]; then
                echo "BAD dcz $p: negotiated request fell back to plain zstd"
                bad=$((bad + 1))
            fi
            if [ "$cell" -ge 0 ] && [ "$bad" -eq "$bad_before" ]; then
                counts[cell]=$((counts[cell] + 1))
            fi
        else
            echo "FAIL request $p (curl exit $?)"
            bad=$((bad + 1))
        fi
        rm -f "$body"
    done
    echo "worker $wid: $ok ok, $bad bad/failed, $dcz_seen dcz"
    for ((cell = 0; cell < prefix_count; cell++)); do
        echo "worker $wid cell ${prefix_paths[$cell]}+${prefix_aes[$cell]}: ${counts[$cell]}"
        if [ "${counts[$cell]}" -eq 0 ]; then
            echo "FAIL worker $wid: deterministic cell ${prefix_paths[$cell]}+${prefix_aes[$cell]} had no verified response"
            bad=$((bad + 1))
        fi
    done
    if [ "$dcz_seen" -eq 0 ]; then
        echo "FAIL worker $wid: no dcz response was ever verified"
        return 1
    fi
    if [ "$bad" -ne 0 ] || [ "$ok" -eq 0 ]; then
        return 1
    fi
    return 0
}

pids=()
for w in $(seq 1 "$CONC"); do
    worker "$w" &
    pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool cleanups (incl. CCtx/CDict) run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null
rc=$?

# shellcheck source=ci/tools/lsan_log_verdict.sh
. "$(cd "$(dirname "$0")" && pwd)/lsan_log_verdict.sh"

problems=0
indeterminate=0
if compgen -G "$WORK/logs/asan*" >/dev/null; then
    echo "ASAN/UBSAN log:"
    cat "$WORK"/logs/asan*
    set +e
    lsan_check_log_glob "$WORK/logs/asan*"
    asan_rc=$?
    set -e
    case "$asan_rc" in
        0) : ;;
        2)
            echo "::warning::LeakSanitizer could not run its exit-time check" \
                 "(ptrace blocked on this runner — LXC seccomp / yama). Soak" \
                 "leak check INDETERMINATE, not clean; fix the runner profile" \
                 "to restore coverage."
            indeterminate=1
            ;;
        *)
            echo "FAIL: ASAN/UBSAN report (see log above)"
            problems=1
            ;;
    esac
else
    echo '::warning::LeakSanitizer produced no verbose exit-hook log; soak leak check INDETERMINATE'
    indeterminate=1
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
        "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        # Dump every log holding errors in full: the WORK dir is wiped on
        # exit, so this is the only place the stacks (and the exact
        # suppression blocks from --gen-suppressions=all) survive, e.g.
        # in a CI job log.
        for _vglog in "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.*; do
            [ -f "$_vglog" ] || continue
            grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' "$_vglog" || continue
            echo "---- $_vglog ----"
            cat "$_vglog"
        done
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"
    problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a corrupted response"
    problems=1
fi
# QUIT is a clean exit; valgrind uses 99, ASAN 42 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"
    tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
if [ "$indeterminate" -ne 0 ]; then
    echo "⚠ soak passed: ${DURATION}s @ ${CONC} concurrent, no crash/sanitizer" \
         "finding, but the leak lane is INDETERMINATE this run (ptrace" \
         "blocked -- see warning above)"
else
    echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no sanitizer/leak/crash"
fi
