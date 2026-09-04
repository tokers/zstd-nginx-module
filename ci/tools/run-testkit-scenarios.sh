#!/usr/bin/env bash
# Run and verify this module's nginx-module-testkit consumer scenarios.
#
# Usage:
#   ci/tools/run-testkit-scenarios.sh --build DIR --version VERSION [options]
#       [scenario ...]
#
# Required:
#   --build DIR       nginx/Angie build tree containing objs/<server> and the
#                     harness-enabled zstd module.
#   --version VERSION concrete server version used by the testkit build lookup.
#
# Options:
#   --root DIR        module root (default: repository root).
#   --flavor NAME     nginx or angie (default: nginx).
#   --log-dir DIR     TAP output directory (default: repository root).
#   --runner CMD      testkit runner prefix, for example valgrind options.
#   --timeout-scale N scale testkit timeouts for slow tooling.
#   -h, --help        show this help.
#
# With no scenario arguments, all committed consumer scenarios run. The script
# preserves every scenario's narrow expected-log allowance, re-derives the TAP
# verdict, rejects all-skip/empty runs, and checks property-specific witness
# lines. It keeps running after a failure so one deep run reports every broken
# scenario, then exits non-zero. Logs are the only side effect. Add a scenario
# to SCENARIOS and its witness checks below; callers intentionally share this
# list so PR, coverage, and Memcheck surfaces cannot drift.

set -euo pipefail

usage() {
    sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'
}

ROOT=""
BUILD=""
FLAVOR="nginx"
VERSION=""
LOG_DIR=""
RUNNER=""
TIMEOUT_SCALE=""
SCENARIOS=(
    fault-arms
    alloc-neutral
    fault-palloc
    codec-call-count
    setparam-call-count
    setparam-call-count-nodict
)

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build) BUILD="${2:?--build requires a directory}"; shift 2 ;;
        --root) ROOT="${2:?--root requires a directory}"; shift 2 ;;
        --flavor) FLAVOR="${2:?--flavor requires a name}"; shift 2 ;;
        --version) VERSION="${2:?--version requires a value}"; shift 2 ;;
        --log-dir) LOG_DIR="${2:?--log-dir requires a directory}"; shift 2 ;;
        --runner) RUNNER="${2:?--runner requires a command}"; shift 2 ;;
        --timeout-scale) TIMEOUT_SCALE="${2:?--timeout-scale requires a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; SCENARIOS=("$@"); break ;;
        -*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) SCENARIOS=("$@"); break ;;
    esac
done

[ -n "$ROOT" ] || ROOT="$(git rev-parse --show-toplevel)"
[ -n "$LOG_DIR" ] || LOG_DIR="$ROOT"
[ -n "$BUILD" ] || { echo "ERROR: --build is required" >&2; exit 2; }
[ -n "$VERSION" ] || { echo "ERROR: --version is required" >&2; exit 2; }
[ "${#SCENARIOS[@]}" -gt 0 ] || { echo "ERROR: no scenarios selected" >&2; exit 2; }
[ -d "$ROOT" ] || { echo "ERROR: --root is not a directory: $ROOT" >&2; exit 2; }
[ -d "$BUILD" ] || { echo "ERROR: --build is not a directory: $BUILD" >&2; exit 2; }
ROOT="$(realpath "$ROOT")"
BUILD="$(realpath "$BUILD")"
mkdir -p "$LOG_DIR"
LOG_DIR="$(realpath "$LOG_DIR")"

PROBER_DIR="$ROOT/ci/t/harness/ci/prober"
RUN_SCENARIO="${PROBER_RUN_SCENARIO:-$PROBER_DIR/run-scenario.sh}"
[ -x "$RUN_SCENARIO" ] || {
    echo "ERROR: testkit runner is not executable: $RUN_SCENARIO" >&2
    exit 2
}

export PROBER_ROOT="$ROOT"
export PROBER_BUILD="$BUILD"
export PROBER_MODULE="${PROBER_MODULE:-ngx_http_zstd_filter_module.so}"
export PROBER_DIRECTIVE="${PROBER_DIRECTIVE:-zstd_probe}"
export PROBER_PROBE="${PROBER_PROBE:-zstd_probe;}"
[ -z "$RUNNER" ] || export PROBER_VALGRIND="$RUNNER"
[ -z "$TIMEOUT_SCALE" ] || export PROBER_TIMEOUT_SCALE="$TIMEOUT_SCALE"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    status=1
}

require_line() {
    local log="$1" pattern="$2" message="$3"
    grep -qE "$pattern" "$log" || fail "$message"
}

verify_tap() {
    local scenario="$1" log="$2" total skipped n plan plans_text
    local -a plans

    if grep -q '^Bail out!' "$log"; then
        fail "$scenario reported a TAP bailout"
    fi
    if grep -q '^not ok' "$log"; then
        fail "$scenario reported at least one 'not ok' line"
    fi
    if ! plans_text="$(sed -nE 's/^1\.\.([0-9]+)([[:space:]]*#.*)?$/\1/p' "$log")"; then
        fail "$scenario could not parse its TAP plan"
        plans=()
    elif [ -n "$plans_text" ]; then
        mapfile -t plans <<<"$plans_text"
    else
        plans=()
    fi
    if [ "${#plans[@]}" -ne 1 ]; then
        fail "$scenario reported ${#plans[@]} TAP plans; expected exactly one"
        plan=-1
    else
        plan="${plans[0]}"
    fi
    total="$(grep -c '^ok ' "$log" || true)"
    skipped="$(grep -c '^ok .*# SKIP' "$log" || true)"
    if [ "$total" -eq 0 ]; then
        fail "$scenario reported no passing TAP oracle"
    elif [ "$total" -eq "$skipped" ]; then
        fail "$scenario skipped every oracle"
    fi
    if [ "$plan" -ge 0 ] && ! awk -v plan="$plan" '
        /^(ok|not ok) [0-9]+/ {
            n = ($1 == "not" ? $3 : $2) + 0
            if (n < 1 || n > plan || seen[n]++) exit 1
            count++
        }
        END { if (count != plan) exit 1 }
    ' "$log"; then
        fail "$scenario TAP results do not exactly satisfy plan 1..$plan"
    fi

    case "$scenario" in
        alloc-neutral)
            skipped="$(grep -cE '^ok [345] .*# SKIP' "$log" || true)"
            [ "$skipped" -ne 3 ] || fail \
                "alloc-neutral skipped all cycle/worker allocation oracles 3-5"
            ;;
        fault-palloc)
            require_line "$log" '^ok 2 - PALLOC site accepted the arm[^#]*$' \
                "fault-palloc did not prove the PALLOC site was armed"
            ;;
        codec-call-count)
            for n in 2 4 6 8 10; do
                require_line "$log" "^ok $n - [^#]*total codec calls is [^#]*$" \
                    "codec-call-count oracle $n did not assert the call count"
            done
            ;;
        setparam-call-count)
            for n in 3 7; do
                require_line "$log" "^ok $n - [^#]*setParameter call count is [^#]*$" \
                    "setparam-call-count oracle $n did not assert the call count"
            done
            require_line "$log" '^ok 4 - [^#]*frame window size is [^#]*$' \
                "setparam-call-count did not assert the CDict frame window"
            ;;
        setparam-call-count-nodict)
            require_line "$log" '^ok 3 - [^#]*setParameter call count is [^#]*$' \
                "setparam-call-count-nodict did not assert the reference count"
            require_line "$log" '^ok 4 - [^#]*frame window size is [^#]*$' \
                "setparam-call-count-nodict did not assert the reference window"
            ;;
    esac
}

status=0
for scenario in "${SCENARIOS[@]}"; do
    scenario_dir="$ROOT/ci/t/harness-scenarios/$scenario"
    log="$LOG_DIR/$scenario-tap.log"
    [ -d "$scenario_dir" ] || {
        fail "scenario directory does not exist: $scenario_dir"
        continue
    }

    allow_log=""
    case "$scenario" in
        fault-arms)
            allow_log='zstd: ZSTD_(compressStream2|CCtx_refPrefix)\(\) failed'
            ;;
        fault-palloc)
            allow_log='zstd: |ngx_(palloc|pcalloc|pnalloc)'
            ;;
    esac

    printf '%s\n' "== testkit scenario: $scenario =="
    set +e
    if [ -n "$allow_log" ]; then
        (
            cd "$PROBER_DIR"
            PROBER_ALLOW_LOG="$allow_log" \
                "$RUN_SCENARIO" "$scenario_dir" "$FLAVOR" "$VERSION"
        ) | tee "$log"
    else
        (
            cd "$PROBER_DIR"
            unset PROBER_ALLOW_LOG
            "$RUN_SCENARIO" "$scenario_dir" "$FLAVOR" "$VERSION"
        ) | tee "$log"
    fi
    run_status="${PIPESTATUS[0]}"
    set -e

    [ "$run_status" -eq 0 ] || fail "$scenario runner exited $run_status"
    verify_tap "$scenario" "$log"
done

exit "$status"
