#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERDICT="$ROOT/ci/tools/sanitizer_suite_verdict.py"
WORK="$(mktemp -d "$ROOT/.sanitizer-verdict-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/suite.tap" <<'EOF'
ok 1 - first
ok 2 - second
1..2
EOF
cat >"$WORK/core.log" <<'EOF'
nginx.c:10:3: runtime error: core-only undefined behavior
    #0 0x123 in ngx_worker_process_cycle nginx/src/os/unix/ngx_process_cycle.c:1
EOF

python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:0" \
	--sanitizer-log "$WORK/core.log" >/dev/null

cat >"$WORK/core-with-later-module-log.log" <<'EOF'
nginx.c:10:3: runtime error: core-only undefined behavior
    #0 0x123 in ngx_worker_process_cycle nginx/src/os/unix/ngx_process_cycle.c:1
2026/08/31 12:00:00 [notice] 12#12: harmless ngx_http_zstd_body_filter diagnostic
EOF
python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:0" \
	--sanitizer-log "$WORK/core-with-later-module-log.log" >/dev/null

cat >"$WORK/module.log" <<'EOF'
==12==ERROR: AddressSanitizer: heap-use-after-free on address 0x123
    #0 0x123 in memcpy sanitizer_common_interceptors.inc:1
    #1 0x456 in ngx_http_zstd_body_filter src/ngx_http_zstd_filter_module.c:512
SUMMARY: AddressSanitizer: heap-use-after-free sanitizer_common_interceptors.inc:1
EOF
if python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:0" \
	--sanitizer-log "$WORK/module.log" >/dev/null 2>&1; then
	echo "FAIL: split-line-module-frame mutant was not rejected" >&2
	exit 1
fi

cat >"$WORK/lsan-module.log" <<'EOF'
==12==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0x123 in malloc sanitizer_common_interceptors.inc:1
    #1 0x456 in ngx_http_zstd_body_filter src/ngx_http_zstd_filter_module.c:512
SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).
EOF
if python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:0" \
	--sanitizer-log "$WORK/lsan-module.log" >/dev/null 2>&1; then
	echo "FAIL: split-line LSan module frame was not rejected" >&2
	exit 1
fi

cat "$WORK/core.log" "$WORK/module.log" >"$WORK/multiple.log"
if python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:0" \
	--sanitizer-log "$WORK/multiple.log" >/dev/null 2>&1; then
	echo "FAIL: later module-attributable report was not rejected" >&2
	exit 1
fi

if python3 "$VERDICT" --suite "fixture:$WORK/suite.tap:23" \
	--sanitizer-log "$WORK/core.log" >/dev/null 2>&1; then
	echo "FAIL: ignored-suite-exit mutant was not rejected" >&2
	exit 1
fi

sed 's/^1\.\.2$/1..3/' "$WORK/suite.tap" >"$WORK/truncated.tap"
if python3 "$VERDICT" --suite "fixture:$WORK/truncated.tap:0" \
	--sanitizer-log "$WORK/core.log" >/dev/null 2>&1; then
	echo "FAIL: truncated TAP plan was not rejected" >&2
	exit 1
fi

echo "sanitizer suite verdict tests passed"
