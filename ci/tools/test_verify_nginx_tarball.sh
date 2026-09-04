#!/usr/bin/env bash
# Offline positive and negative controls for verify-nginx-tarball.sh.
# Usage: ci/tools/test_verify_nginx_tarball.sh
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verifier="$script_dir/verify-nginx-tarball.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

cat >"$work/bin/wget" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
for arg in "$@"; do
    case "$arg" in
        --output-document=*) output="${arg#*=}" ;;
        http://*|https://*) url="$arg" ;;
    esac
done
printf '%s\n' "$url" >"${FAKE_WGET_LOG:?}"
printf 'detached signature\n' >"$output"
EOF

cat >"$work/bin/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\n' "${GNUPGHOME:?}" "$*" >>"${FAKE_GPG_LOG:?}"
if [[ " $* " == *" --verify "* ]] && [ "${FAKE_GPG_VERIFY:-ok}" = "fail" ]; then
    exit 1
fi
EOF
chmod +x "$work/bin/wget" "$work/bin/gpg"

run_verifier() {
	PATH="$work/bin:$PATH" \
		FAKE_WGET_LOG="$work/wget.log" \
		FAKE_GPG_LOG="$work/gpg.log" \
		"$verifier" "$@"
}

tarball="$work/nginx-1.2.3.tar.gz"
printf 'tarball\n' >"$tarball"
run_verifier "$tarball"
grep -qx 'https://nginx.org/download/nginx-1.2.3.tar.gz.asc' "$work/wget.log"
grep -q -- '--verify' "$work/gpg.log"
test "$(grep -c -- '--import' "$work/gpg.log")" -eq \
	"$(find "$script_dir/keys" -maxdepth 1 -name '*.key' -type f | wc -l)"
gnupghome="$(head -1 "$work/gpg.log" | cut -f1)"
test ! -e "$gnupghome"

if FAKE_GPG_VERIFY=fail run_verifier "$tarball" \
	'https://example.invalid/nginx.sig' >/dev/null 2>&1; then
	echo 'verifier accepted a rejected signature' >&2
	exit 1
fi
grep -qx 'https://example.invalid/nginx.sig' "$work/wget.log"
gnupghome="$(tail -1 "$work/gpg.log" | cut -f1)"
test ! -e "$gnupghome"

if run_verifier "$work/missing.tar.gz" >/dev/null 2>&1; then
	echo 'verifier accepted a missing tarball' >&2
	exit 1
fi
"$verifier" --help | grep -q '^Usage:'

workflow="${WORKFLOW_FILE:-$script_dir/../../.github/workflows/build-test.yml}"
python3 - "$workflow" <<'PY'
import re
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as stream:
    workflow = yaml.safe_load(stream)

verify_steps = []
inline = []
for job_name, job in workflow.get("jobs", {}).items():
    for step in job.get("steps", []):
        if not isinstance(step, dict):
            continue
        run = step.get("run", "")
        name = step.get("name", "")
        if name == "Verify nginx tarball PGP signature":
            verify_steps.append((job_name, run))
        if "nginx" in run and re.search(r"gpg\b[\s\S]*--\S*verify", run):
            inline.append(job_name)

if not verify_steps:
    raise SystemExit("no nginx tarball verification steps found")
wrong = [job for job, run in verify_steps if "verify-nginx-tarball.sh" not in run]
if wrong:
    raise SystemExit(f"nginx verification bypasses shared helper in: {', '.join(wrong)}")
if inline:
    raise SystemExit(f"inline nginx PGP verification reintroduced in: {', '.join(inline)}")
PY

echo 'verify-nginx-tarball controls passed'
