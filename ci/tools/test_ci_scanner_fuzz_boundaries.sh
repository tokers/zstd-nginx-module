#!/usr/bin/env bash
# Gate CI C scanner selectors and the production-sized fuzz domain.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

assert_contract() {
  local base=${1:-.}
  grep -Fq "'^(src|ci)/.*\.[ch]$'" "$base/ci/linter/lint-c.sh" || return 1
  [ "$(grep -Fc "files: '^(src|ci)/.*\.[ch]$'" "$base/.pre-commit-config.yaml")" -ge 3 ] \
    || return 1
  # Check each owning step independently: both must use checked discovery and
  # pass the explicit C-file array rather than a directory to the scanner.
  python3 - "$base/.github/workflows/security-scanners.yml" <<'PY' || return 1
import pathlib, re, sys, yaml

doc = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
steps = doc["jobs"]["scanners"]["steps"]
for name, command in (("flawfinder", "flawfinder"), ("semgrep", "semgrep scan")):
    run = next(step["run"] for step in steps if step.get("name") == name)
    required = (
        'mapfile_checked files find',
        '"$GITHUB_WORKSPACE/src" "$GITHUB_WORKSPACE/ci"',
        "-name '*.c'", "-name '*.h'",
        '[ "${#files[@]}" -gt 0 ]',
    )
    if not all(token in run for token in required):
        raise SystemExit(f"{name} does not discover checked src+ci C/H targets")
    invocation = rf'^\s*{re.escape(command)}\b.*?"\$\{{files\[@\]\}}".*?\|\s*tee'
    if re.search(invocation, run, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"{name} command does not consume the C target array")
    if name == "flawfinder" and "--error-level=4" not in run:
        raise SystemExit("flawfinder findings are not blocking at level 4")
    if name == "semgrep" and re.search(r'(?<![-\w])--error(?![-\w])', run) is None:
        raise SystemExit("Semgrep findings are not blocking")
PY
  [ "$(grep -Fc -- '-max_len=65536' "$base/.github/workflows/fuzzing.yml")" -ge 2 ] \
    || return 1
  grep -Fq -- '-max_len=65536' "$base/.github/workflows/ci-deep.yml" \
    || return 1
  grep -Fq 'for size in 4095 4096 4097 65535 65536' \
    "$base/.github/workflows/fuzzing.yml" || return 1
}

assert_contract

work=$(mktemp -d "${TMPDIR:-/tmp}/scanner-fuzz-contract.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/ci/linter"
cp ci/linter/lint-c.sh "$work/ci/linter/"
cp .pre-commit-config.yaml "$work/"
cp -a .github "$work/"
sed -i 's/(src|ci)/src/g; s/65536/4096/g' \
  "$work/ci/linter/lint-c.sh" "$work/.pre-commit-config.yaml" \
  "$work/.github/workflows/security-scanners.yml" "$work/.github/workflows/fuzzing.yml" \
  "$work/.github/workflows/ci-deep.yml"
if assert_contract "$work" >/dev/null 2>&1; then
  echo 'FAIL: scanner/max_len mutant did not make the contract gate red' >&2
  exit 1
fi
assert_contract

# The exact CI Semgrep profiles must still block a real C finding. Keep the
# source under a non-C suffix so the repository's normal widened scan stays
# clean; copy it to the temporary C target only for this negative control.
if command -v semgrep >/dev/null 2>&1; then
	cp ci/linter/fixtures/semgrep-blocking.c.fixture "$work/blocking.c"
	set +e
	semgrep scan --config p/c --config p/security-audit \
		--severity=WARNING --severity=ERROR --error --jobs=1 --metrics=off \
		"$work/blocking.c" >"$work/semgrep-negative.log" 2>&1
	semgrep_rc=$?
	set -e
	if [ "$semgrep_rc" -ne 1 ]; then
		echo "FAIL: Semgrep negative control returned $semgrep_rc, want finding status 1" >&2
		cat "$work/semgrep-negative.log" >&2
		exit 1
	fi
  echo 'OK: Semgrep C finding remains blocking'
fi
echo 'OK: CI C scanner selectors and >4096 fuzz boundaries are enforced'
