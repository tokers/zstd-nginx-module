#!/usr/bin/env bash
#
# Reload-under-ASAN leak regression for the zstd_dict_file ZSTD_CDict
# lifecycle. Targets the bug class fixed in 0fb40d9 ("Free ZSTD_CDict on
# configuration cleanup to prevent memory leak") and f735a5d ("pass size=0
# to ngx_pool_cleanup_add for dict cleanup handler"): the CDict leak only
# manifests when the configuration is reloaded (SIGHUP), which the normal
# smoke tests never do.
#
# Strategy: start nginx (built with -fsanitize=address) using a dictionary,
# SIGHUP it several times so the old cycle's dict cleanup runs repeatedly,
# then stop nginx cleanly. ASAN's leak detector reports on exit; a leak
# report in the log fails this script.
#
# LeakSanitizer uses ptrace for its exit-time stop-the-world phase. LLVM first
# runs a heuristic preflight which may print "ptrace appears to be blocked"
# even though it then continues and the real check succeeds. Verbose logs plus
# ci/tools/lsan_log_verdict.sh distinguish that false warning from an actual
# attach failure, require an exit-hook marker for every process, and run a
# deliberate-leak control. The shutdown watchdog still bounds a real hang.
#
# Usage: tools/test_reload_leak.sh <nginx-binary> [reloads]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NGINX="${1:?usage: test_reload_leak.sh <nginx-binary> [reloads]}"
RELOADS="${2:-5}"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# A non-trivial dictionary so ZSTD_createCDict() actually allocates.
head -c 8192 /dev/urandom | base64 >"$WORK/html/zstd.dict"

cat >"$WORK/conf/nginx.conf" <<EOF
daemon off;
master_process on;
worker_processes 1;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 64; }
http {
    access_log off;
    zstd_dict_file_unsafe on;
    zstd_dict_file $WORK/html/zstd.dict;
    server {
        listen 127.0.0.1:18099;
        location / {
            zstd on;
            zstd_min_length 1;
            zstd_types text/plain;
            default_type text/plain;
            return 200 "dictionary compressed body long enough to compress\n";
        }
    }
}
EOF

# ASAN must report leaks on exit and treat them as failures.
export ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:exitcode=23:verbosity=1:log_path=$WORK/logs/asan"

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
NGINX_PID=$!

# Wait for the listener — quietly (the old loop let the first refused
# curl print to stderr, a red herring that muddied flake diagnosis) and
# with an explicit verdict when startup never completes: ASAN startup
# on a loaded shared runner is exactly when this fires.
ready=0
for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "http://127.0.0.1:18099/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    echo "❌ nginx under ASAN did not accept connections within 10s"
    kill -9 "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

for i in $(seq 1 "$RELOADS"); do
    curl -fsS -o /dev/null -H 'Accept-Encoding: zstd' "http://127.0.0.1:18099/"
    kill -HUP "$NGINX_PID"
    sleep 0.5
    echo "  reload $i/$RELOADS done"
done

# One final request against the latest cycle, then a clean shutdown so
# every cycle's pool cleanup (including the dict cleanup handler) runs.
# The watchdog bounds the wait: a ptrace-blocked LSan can hang at exit,
# which would otherwise eat the job timeout instead of yielding a
# verdict. And wait must not run under set -e: a leak makes nginx exit
# 23 (exitcode above), which used to abort the script right here,
# skipping the report that says WHY.
curl -fsS -o /dev/null -H 'Accept-Encoding: zstd' "http://127.0.0.1:18099/"
kill -QUIT "$NGINX_PID"
( sleep 90; kill -9 "$NGINX_PID" 2>/dev/null ) &
WATCHDOG=$!
set +e
wait "$NGINX_PID"
rc=$?
set -e
kill "$WATCHDOG" 2>/dev/null || true

if [ "$rc" -eq 137 ]; then
    echo "::warning::nginx under ASAN had to be killed by the shutdown" \
         "watchdog (LeakSanitizer hang?). Leak check INDETERMINATE and" \
         "therefore failed."
    exit 1
fi

if [ "$rc" -ne 0 ]; then
    echo "❌ nginx exited non-zero ($rc) under ASAN after reloads"
    tail -50 "$WORK/logs/error.log" || true
    exit 1
fi

"$SCRIPT_DIR/lsan_log_verdict.sh" "$WORK/logs/asan*"
echo "✓ No CDict leak across $RELOADS config reloads under ASAN"
