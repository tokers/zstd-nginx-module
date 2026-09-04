#!/bin/bash
# ci/tools/coverage.sh -- publish a coverage REPORT for src/, never a gate.
#
# Coverage is the cheapest number to inflate: a test that touches a line and
# asserts nothing still moves it, so a floor buys the metric and sells the
# thing it was standing in for. This script has no --fail-under default and
# no exit-nonzero-on-threshold path; COVERAGE_FAIL_UNDER exists only for a
# downstream adopter that has decided otherwise (step 26 note in PROMPT.md).
#
# Usage: ci/tools/coverage.sh [flavor] [version]
#   Runs ci-build.sh in "coverage" mode (separate .build tree, --coverage
#   compiled in), runs ci/t/, the assertion-bearing runtime drivers, and all
#   testkit scenarios against the instrumented binary so .gcda files land next
#   to the .gcno objects, then reports with gcovr FILTERED TO src/
#   -- unfiltered gcovr walks the whole configured nginx tree (order 200k
#   lines of upstream C) and buries the module's own number in noise.
#
# Env:
#   COVERAGE_FAIL_UNDER  optional; if set, gcovr --fail-under-line is used.
#                        Unset by default -- see the header note above.
#   COVERAGE_HARNESS     optional, default 1. When 1, the coverage tree is
#                        built with the TEST_HARNESS probe compiled in and the
#                        ci/t/harness-scenarios/* scenarios are run against it
#                        after the Test::Nginx suites, so the libzstd FAULT
#                        paths (which no ci/t/ test can reach -- there is no
#                        way to make libzstd fail from the outside) are counted
#                        instead of being reported as dead lines. Set to 0 to
#                        reproduce the pre-harness number.
#
# gcovr flag note: --object-directory is used, NOT --gcov-object-directory,
# which fails argparse on gcovr below 7.0. --object-directory is accepted by
# every gcovr version this script has been run against (verified on 7.2).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
# shellcheck source=ci/linter/lib.sh
. "$MODULE_DIR/ci/linter/lib.sh"
cd "$MODULE_DIR"

collect_module_gcda() {
    mapfile_checked MODULE_GCDA find "$1" -name 'ngx_http_zstd_*.gcda'
}

if [ "${1:-}" = "--selftest-work-list" ]; then
    collect_module_gcda "${2:?usage: coverage.sh --selftest-work-list DIR}"
    exit 0
fi

FLAVOR="${1:-nginx}"
VERSION="${2:-}"

command -v gcovr >/dev/null || {
    echo "ERROR: gcovr not found (pip install gcovr / apt-get install gcovr)" >&2
    exit 2
}

COVERAGE_HARNESS="${COVERAGE_HARNESS:-1}"

echo "== coverage: building $FLAVOR ${VERSION:-<mainline>} in coverage mode =="
# Measure the portable SHA-256 implementation instead of compiling it beside
# the OpenSSL EVP path and then leaving nearly all of it untouched. Production
# builds and the PR suite still exercise EVP; this report covers code owned by
# the module that would otherwise be represented by a misleading 7% file rate.
if [ "$COVERAGE_HARNESS" = "1" ]; then
    # BOTH switches, always together. TEST_HARNESS=1 alone compiles the probe
    # sources and still yields a probe-free .so -- measured in this repo
    # (packaged=0 probe symbols, TEST_HARNESS=1 alone=0, both=18). With a
    # probe-free .so every scenario below would SKIP or fail to arm, and the
    # coverage number would silently be the pre-harness one while claiming
    # otherwise. Verified compatible with --coverage: the coverage tree builds
    # clean with the probe in and emits .gcno for every unit.
    echo "   (with TEST_HARNESS -- fault paths will be exercised)"
    NGX_ZSTD_NO_LIBCRYPTO=1 TEST_HARNESS=1 \
        CFLAGS="${CFLAGS:-} -DNGX_TEST_HARNESS" \
        bash "$SCRIPT_DIR/ci-build.sh" "$FLAVOR" "$VERSION" coverage
else
    NGX_ZSTD_NO_LIBCRYPTO=1 \
        bash "$SCRIPT_DIR/ci-build.sh" "$FLAVOR" "$VERSION" coverage
fi

# ci-build.sh resolves an empty VERSION to the current mainline; recover the
# resolved value from the build tree it actually created rather than
# re-resolving (a second nginx.org scrape could race a release and disagree).
BUILD_ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
if [ -n "$VERSION" ]; then
    # An explicit version names exactly one tree. Globbing here instead would
    # silently report on whatever version sorts highest -- ask for 1.30.4 with a
    # 1.31.2 tree present and you get a coverage figure for the wrong binary,
    # which reads as a real measurement.
    SRCDIR="$BUILD_ROOT/${FLAVOR}-${VERSION}-coverage"
else
    SRCDIR="$(find "$BUILD_ROOT" -maxdepth 1 -type d -name "${FLAVOR}-*-coverage" | sort -V | tail -1)"
fi
if [ -z "$SRCDIR" ] || [ ! -d "$SRCDIR" ]; then
    echo "ERROR: no coverage build tree found under $BUILD_ROOT" >&2
    [ -n "$VERSION" ] && echo "       expected: $SRCDIR" >&2
    exit 1
fi
echo "Coverage build tree: $SRCDIR"

BIN="$SRCDIR/objs/$FLAVOR"
[ -x "$BIN" ] || { echo "ERROR: $BIN not found or not executable" >&2; exit 1; }
REPORT_DIR="$MODULE_DIR/.build/coverage-report"
mkdir -p "$REPORT_DIR"
# ci-build.sh reuses an existing build directory. A changed compiler/configure
# checksum makes libgcov reject old counters instead of replacing them, so every
# invocation starts profile collection from a known empty state.
find "$SRCDIR/objs/addon" -name '*.gcda' -delete

echo "== coverage: exercising the binary via ci/t/ =="
export TEST_NGINX_BINARY="$BIN"
export TEST_NGINX_TIMEOUT="${TEST_NGINX_TIMEOUT:-20}"
STRICT_SERVROOT="$HOME/.nginx-servroot-coverage-filter-${GITHUB_RUN_ID:-local-$$}-${GITHUB_RUN_ATTEMPT:-1}"
export TEST_NGINX_SERVROOT="$STRICT_SERVROOT"
trap 'rm -rf -- "$STRICT_SERVROOT"' EXIT
rm -rf -- "$TEST_NGINX_SERVROOT"
mkdir -p "$TEST_NGINX_SERVROOT"
# Both dcz and static tests assert validators derived from these fixtures.
# Normalize before either suite so checkout/build time cannot change the ETag.
touch -d @1541504307 ci/t/suite/test ci/t/suite/test.zst
prove -v ci/t/00-filter.t ci/t/02-conf-warn.t ci/t/03-dcz.t

export TEST_NGINX_SERVROOT="$MODULE_DIR/ci/t/servroot-static"
mkdir -p "$TEST_NGINX_SERVROOT"
prove -v ci/t/01-static.t

echo "== coverage: exercising runtime regression drivers =="
# Keep every endpoint inside the coverage workflow's declared 64-port band.
# These are assertion-bearing end-to-end drivers already used by the PR suite;
# running them against the instrumented binary turns their reachability into
# line/branch evidence without inventing coverage-only tests.
COVERAGE_RUNTIME_PORT_BASE="${COVERAGE_RUNTIME_PORT_BASE:-${TEST_BASE_PORT:-19330}}"
p="$COVERAGE_RUNTIME_PORT_BASE"
python3 ci/tools/test_encoding.py --nginx-binary "$BIN" --port "$((p + 0))"
python3 ci/tools/test_compression_matrix.py \
    --nginx-binary "$BIN" --port "$((p + 1))" --backend-port "$((p + 2))"
python3 ci/tools/test_concurrent_cctx_isolation.py \
    --nginx-binary "$BIN" --port "$((p + 3))" --backend-port "$((p + 4))"
python3 ci/tools/test_cctx_reuse.py --nginx-binary "$BIN" --port "$((p + 5))"
python3 ci/tools/test_proxy_unbuffered_truncation.py \
    --nginx-binary "$BIN" --port "$((p + 6))" --backend-port "$((p + 7))"
python3 ci/tools/test_slow_drain.py \
    --nginx-binary "$BIN" --port "$((p + 8))" --backend-port "$((p + 9))"
python3 ci/tools/test_sub_filter_cctx_reset.py \
    --nginx-binary "$BIN" --port "$((p + 10))" --backend-port "$((p + 11))"
python3 ci/tools/test_terminal_frame.py --nginx-binary "$BIN" --port "$((p + 12))"
python3 ci/tools/test_reload_under_load.py \
    --nginx-binary "$BIN" --port "$((p + 13))" --backend-port "$((p + 14))"
python3 ci/tools/test_window_cap.py \
    --nginx-binary "$BIN" --port "$((p + 15))" --backend-port "$((p + 16))"
python3 ci/tools/test_ldm_budget_config.py --nginx-binary "$BIN" --port "$((p + 17))"
python3 ci/tools/test_cctx_advisory_policy.py --nginx-binary "$BIN" --port "$((p + 18))"
python3 ci/tools/test_bufs_bound_policy.py --nginx-binary "$BIN" --port "$((p + 19))"
python3 ci/tools/test_bypass_vary_config_policy.py \
    --nginx-binary "$BIN" --port "$((p + 20))"
python3 ci/tools/test_zstd_long_ldm.py \
    --nginx-binary "$BIN" --port "$((p + 21))" --backend-port "$((p + 22))"
python3 ci/tools/test_dcz.py --nginx-binary "$BIN" \
    --port "$((p + 23))" --tls-port "$((p + 24))" --insecure-port "$((p + 25))"
python3 ci/tools/test_dcz_cache_partition.py \
    --nginx-binary "$BIN" --port "$((p + 26))" --origin-port "$((p + 27))"
python3 ci/tools/test_dcz_budget_ring.py \
    --nginx-binary "$BIN" --port "$((p + 28))" --backend-port "$((p + 30))"
python3 ci/tools/test_dcz_prefix_alloc.py --nginx-binary "$BIN" --port "$((p + 31))"
python3 ci/tools/test_var_dynamic_cacheable.py \
    --nginx-binary "$BIN" --port "$((p + 32))"

# The testkit is the only layer that reaches worker-internal fault/counter
# paths. Use the same canonical six-scenario runner as the PR and Memcheck
# jobs; a failure stays visible AND fails this script at the end (after the
# report is still published) -- a bailed-out scenario, whose TAP plan/oracle
# evidence run-testkit-scenarios.sh already verifies per scenario, must never
# pass silently just because the coverage PERCENTAGE has no floor.
HARNESS_SCENARIOS_FAILED=0
if [ "$COVERAGE_HARNESS" = "1" ]; then
    echo "== coverage: exercising all module testkit scenarios =="
    if [ ! -x "$MODULE_DIR/ci/t/harness/ci/prober/run-scenario.sh" ]; then
        echo "WARNING: harness submodule not checked out --" \
             "fault/counter paths will report as uncovered" >&2
    else
        # Always (re)build: the prober binary can exist but be staler than its
        # sources, which silently bails every fault/counter scenario while
        # this script still reports coverage success (audit A30-F7).
        if ! bash "$MODULE_DIR/ci/t/harness/ci/prober/build.sh"; then
            echo "ERROR: prober build failed --" \
                 "fault/counter paths will report as uncovered" >&2
            HARNESS_SCENARIOS_FAILED=1
        fi

        scen_version="${SRCDIR##*/}"
        scen_version="${scen_version%-coverage}"
        scen_version="${scen_version#"$FLAVOR-"}"
        if ! "$SCRIPT_DIR/run-testkit-scenarios.sh" \
            --root "$MODULE_DIR" \
            --build "$SRCDIR" \
            --flavor "$FLAVOR" \
            --version "$scen_version" \
            --log-dir "$REPORT_DIR"; then
            echo "ERROR: one or more testkit scenarios failed their TAP" \
                 "plan/oracle; their missing lines remain visible in the" \
                 "report, but this run will exit non-zero" >&2
            HARNESS_SCENARIOS_FAILED=1
        fi
    fi
fi

echo "== coverage: gcovr over src/ only =="

# gcovr's --filter/--gcov-filter narrow the REPORT and which gcda match a
# pattern, but gcovr still WALKS every .gcda under the search path first --
# the module's own .o/.gcno/.gcda land flat in objs/ (as
# ngx_http_zstd_<name>_module_modules.*), alongside gcda for the WHOLE
# upstream core (order 200k lines) this addon-module build also compiles
# from scratch, and upstream's gcda resolve to a source layout gcovr can't
# find from here -- a hard error, not a filtered-out line, even under
# --gcov-filter. Pass the module's own .gcda as explicit search_paths so
# gcovr never opens an upstream one at all.
# The addon module's .gcda land at objs/addon/src/, mirroring the
# --add-dynamic-module path nginx's configure stages the module source into
# -- NOT flat in objs/ (that directory holds .gcno for a *_modules.c shim
# that is a compile-time registration stub, never itself executed, so it
# never gets a matching .gcda).
collect_module_gcda "$SRCDIR/objs/addon"
if [ "${#MODULE_GCDA[@]}" -eq 0 ]; then
    echo "ERROR: no .gcda for the zstd module under $SRCDIR/objs -- ci/t/ did not" \
        "exercise the coverage-instrumented binary" >&2
    exit 1
fi

# Even given only the module's OWN .gcda, gcov still resolves an inlined
# call target's compilation unit and reports on gcda for upstream objects
# (ngx_event.c, ngx_open_file_cache.c, ...) that are not under $MODULE_DIR --
# a real gcov behaviour, not a gcovr bug. Those errors are non-fatal to the
# run (gcovr logs and continues) and --filter drops them from the report
# regardless; --gcov-ignore-errors=no_working_dir_found silences the noise
# without hiding a real parse failure in the module's own files.
GCOVR_ARGS=(
    --root "$MODULE_DIR"
    --filter "$MODULE_DIR/src/"
    # gcov records nginx inline-header paths relative to the source root. Using
    # objs/ here makes it discard the entire filter gcda when it cannot resolve
    # src/core/ngx_string.h, yielding a plausible report with the main module
    # silently absent.
    --object-directory "$SRCDIR"
    --gcov-ignore-errors=no_working_dir_found
    --print-summary
    --xml "$REPORT_DIR/coverage.xml"
    --html-details "$REPORT_DIR/coverage.html"
    "${MODULE_GCDA[@]}"
)
if [ -n "${COVERAGE_FAIL_UNDER:-}" ]; then
    GCOVR_ARGS+=(--fail-under-line "$COVERAGE_FAIL_UNDER")
fi

gcovr "${GCOVR_ARGS[@]}"

echo "== coverage: report written to $REPORT_DIR =="

if [ "$HARNESS_SCENARIOS_FAILED" -ne 0 ]; then
    echo "ERROR: coverage report published above, but one or more testkit" \
         "scenarios did not verify -- see the ERROR lines above for which" \
         "scenario/TAP plan bailed" >&2
    exit 1
fi
