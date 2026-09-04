#!/usr/bin/env bash
# Offline positive and negative controls for run-testkit-scenarios.sh.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
TOOL="$ROOT/ci/tools/run-testkit-scenarios.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/testkit-runner-unit.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/root/ci/t/harness/ci/prober" "$WORK/root/ci/t/harness-scenarios" \
    "$WORK/logs" "$WORK/build"

for scenario in fault-arms alloc-neutral fault-palloc codec-call-count \
    setparam-call-count setparam-call-count-nodict; do
    mkdir -p "$WORK/root/ci/t/harness-scenarios/$scenario"
done

FAKE="$WORK/fake-run-scenario"
cat >"$FAKE" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
scenario="$(basename "$1")"
printf '%s\t%s\n' "$scenario" "${PROBER_ALLOW_LOG-unset}" >> "$CALLS"
case "$scenario" in
    fault-arms)
        printf '1..1\nok 1 - fault reached\n'
        ;;
    alloc-neutral)
        printf '1..5\nok 1 - boot\nok 2 - probe\nok 3 - cycle used\nok 4 - cycle blocks\nok 5 - worker fds\n'
        ;;
    fault-palloc)
        printf '1..2\nok 1 - boot\nok 2 - PALLOC site accepted the arm\n'
        ;;
    codec-call-count)
        printf '1..10\n'
        for n in 1 3 5 7 9; do printf 'ok %s - decoded\n' "$n"; done
        for n in 2 4 6 8 10; do printf 'ok %s - total codec calls is 1\n' "$n"; done
        ;;
    setparam-call-count)
        printf '1..7\nok 1 - boot\nok 2 - decoded\nok 3 - setParameter call count is 1\nok 4 - frame window size is 1024\nok 5 - decoded\nok 6 - ready\nok 7 - setParameter call count is 2\n'
        ;;
    setparam-call-count-nodict)
        printf '1..4\nok 1 - boot\nok 2 - decoded\nok 3 - setParameter call count is 3\nok 4 - frame window size is 2048\n'
        ;;
esac
SH
chmod +x "$FAKE"

run() {
    CALLS="$WORK/calls" PROBER_RUN_SCENARIO="$FAKE" "$TOOL" \
        --root "$WORK/root" --build "$WORK/build" --version 1.31.4 \
        --log-dir "$WORK/logs"
}

run
[ "$(wc -l < "$WORK/calls")" -eq 6 ]
grep -q $'^fault-arms\tzstd: ZSTD_' "$WORK/calls"
grep -q $'^fault-palloc\tzstd: ' "$WORK/calls"
grep -q $'^alloc-neutral\tunset$' "$WORK/calls"

# A skipped property witness must fail even when the fake runner exits zero.
cat >"$WORK/skip-runner" <<'SH'
#!/usr/bin/env bash
printf '1..1\nok 1 - nothing # SKIP unavailable\n'
SH
chmod +x "$WORK/skip-runner"
if CALLS="$WORK/calls" PROBER_RUN_SCENARIO="$WORK/skip-runner" "$TOOL" \
    --root "$WORK/root" --build "$WORK/build" --version 1.31.4 \
    fault-arms >/dev/null 2>&1; then
    echo "FAIL: all-skip scenario was accepted" >&2
    exit 1
fi

# The specific call-count witness is stronger than generic green TAP.
cat >"$WORK/weak-runner" <<'SH'
#!/usr/bin/env bash
printf '1..10\n'
for n in $(seq 1 10); do printf 'ok %s - decoded\n' "$n"; done
SH
chmod +x "$WORK/weak-runner"
if CALLS="$WORK/calls" PROBER_RUN_SCENARIO="$WORK/weak-runner" "$TOOL" \
    --root "$WORK/root" --build "$WORK/build" --version 1.31.4 \
    codec-call-count >/dev/null 2>&1; then
    echo "FAIL: codec scenario without count witnesses was accepted" >&2
    exit 1
fi

# A green prefix is not a complete TAP result: every planned number is owed.
cat >"$WORK/incomplete-runner" <<'SH'
#!/usr/bin/env bash
printf '1..2\nok 1 - only half the plan ran\n'
SH
chmod +x "$WORK/incomplete-runner"
if PROBER_RUN_SCENARIO="$WORK/incomplete-runner" "$TOOL" \
    --root "$WORK/root" --build "$WORK/build" --version 1.31.4 \
    fault-arms >/dev/null 2>&1; then
    echo "FAIL: incomplete TAP plan was accepted" >&2
    exit 1
fi

# --help and an explicit --root must not require the caller to be in a Git tree.
(cd "$WORK" && "$TOOL" --help >/dev/null)

# The requires gates run with pipefail. A grep -q probe exits on its first
# match and can SIGPIPE a still-writing nm, turning a real symbol into a false
# "packaged build" skip. Make nm deterministically outlive that first match;
# the shipped counted/full-consumption check must still accept the module.
mkdir -p "$WORK/build/objs" "$WORK/bin"
: >"$WORK/build/objs/ngx_http_zstd_filter_module.so"
cat >"$WORK/bin/nm" <<'SH'
#!/usr/bin/env bash
printf '00000000 T ngx_test_probe_arm\n'
for n in $(seq 1 20000); do
    printf '%08d T unrelated_symbol_%d\n' "$n" "$n"
done
SH
chmod +x "$WORK/bin/nm"
PATH="$WORK/bin:$PATH" PROBER_BUILD="$WORK/build" \
    bash "$ROOT/ci/t/harness-scenarios/alloc-neutral/requires" \
        ignored nginx 1.31.4

echo "OK: testkit scenario runner positive/negative controls passed"
