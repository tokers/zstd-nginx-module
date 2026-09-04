#!/usr/bin/env bash
# ci/tools/test_ci_dependency_bootstrap.sh -- ensure fork fallbacks install
# their non-runner dependencies before CI uses them.
#
# Usage: ci/tools/test_ci_dependency_bootstrap.sh
# Inputs: repository .github/workflows/*.yml files.
# Side effects: none.  Exit non-zero on a missing bootstrap or package.

set -euo pipefail

root=${CI_DEPENDENCY_ROOT:-$(git rev-parse --show-toplevel)}
cd "$root"

require_apt_package() {
  local file=$1 package=$2
  local base=${CI_DEPENDENCY_ROOT:-$root}
  python3 - "$base/$file" "$package" <<'PY'
import pathlib, shlex, sys, yaml

path, wanted = pathlib.Path(sys.argv[1]), sys.argv[2]
doc = yaml.safe_load(path.read_text(encoding="utf-8"))
for job in (doc.get("jobs") or {}).values():
    for step in job.get("steps", []) if isinstance(job, dict) else []:
        run = step.get("run") if isinstance(step, dict) else None
        if not isinstance(run, str):
            continue
        logical = run.replace("\\\n", " ")
        for line in logical.splitlines():
            try:
                lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
                lexer.whitespace_split = True
                lexer.commenters = "#"
                words = list(lexer)
            except ValueError:
                continue
            start = 0
            for end in [
                *[i for i, word in enumerate(words) if word in {";", "&&", "||", "|"}],
                len(words),
            ]:
                command = words[start:end]
                start = end + 1
                apt = 1 if command[:1] == ["sudo"] else 0
                if len(command) > apt and command[apt] == "apt-get" \
                        and "install" in command[apt + 1:]:
                    install = command.index("install", apt + 1)
                    packages = {
                        w for w in command[install + 1:] if not w.startswith("-")
                    }
                    if wanted in packages:
                        raise SystemExit(0)
print(f"FAIL: {path} must install apt package {wanted}", file=sys.stderr)
raise SystemExit(1)
PY
}

require() {
  local file=$1 needle=$2
  if ! grep -Fq -- "$needle" "$file"; then
    echo "FAIL: $file must declare $needle for its fork fallback" >&2
    exit 1
  fi
}

require_before() {
  local file=$1 first=$2 second=$3 first_line second_line
  first_line=$(grep -n -m1 -F -- "$first" "$file" | cut -d: -f1 || true)
  second_line=$(grep -n -m1 -F -- "$second" "$file" | cut -d: -f1 || true)
  if [ -z "$first_line" ] || [ -z "$second_line" ] || [ "$first_line" -ge "$second_line" ]; then
    echo "FAIL: $file must install curl before resolving nginx" >&2
    exit 1
  fi
}

require_regex() {
  local file=$1 pattern=$2
  if ! grep -Eq -- "$pattern" "$file"; then
    echo "FAIL: $file must declare a matching fork fallback dependency" >&2
    exit 1
  fi
}

# These workflows resolve nginx with curl before their normal package profile.
# A fork has no vars.POOL, so ubuntu-latest must receive curl explicitly first.
for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/valgrind.yml; do
  require "$file" 'name: Install bootstrap dependencies'
done

for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/valgrind.yml; do
  require_before "$file" 'name: Install bootstrap dependencies' \
    'curl -fsSL https://nginx.org/en/download.html'
done

# Detached nginx signatures are verified by these fallback workflows.  Do not
# let their green runs depend on gpg having happened to be in a runner image.
for file in \
  .github/workflows/asan.yml \
  .github/workflows/build-test.yml \
  .github/workflows/bump.yml \
  .github/workflows/ci-deep.yml \
  .github/workflows/codeql.yml \
  .github/workflows/harness-fault-arms.yml \
  .github/workflows/security-scanners.yml \
  .github/workflows/valgrind.yml; do
  require_apt_package "$file" gnupg
done

# Test::Nginx is deliberately installed from its pinned CPAN distribution;
# semgrep is deliberately installed through pipx/pip.  Keep both paths
# visible in the workflow rather than assuming a persistent builder carries
# either tool already.
require_apt_package .github/workflows/build-test.yml cpanminus
# The validation job runs this script through git, while cvary-interop clones
# the real comparison module.  Check both declarations rather than allowing a
# package in one job to mask a missing package in the other.
require_regex .github/workflows/build-test.yml '^[[:space:]]+git[[:space:]]+\\$'
require .github/workflows/build-test.yml \
  'sudo apt-get install -y build-essential git gnupg libzstd-dev'
require_apt_package .github/workflows/ci-deep.yml cpanminus
require .github/workflows/security-scanners.yml 'semgrep==1.173.0'

# The soak workers construct their dictionary digest with the openssl CLI;
# likewise, the deep fuzz failure notification serializes JSON with Python.
require_apt_package .github/workflows/asan.yml openssl
require_apt_package .github/workflows/valgrind.yml openssl
require_apt_package .github/workflows/ci-deep.yml openssl
require_apt_package .github/workflows/ci-deep.yml clang
require_apt_package .github/workflows/ci-deep.yml curl
require_apt_package .github/workflows/ci-deep.yml python3

# CodeQL inspects its database through Python and unpacks src.zip when the
# action stores extracted sources as an archive.
require_apt_package .github/workflows/codeql.yml python3
require_apt_package .github/workflows/codeql.yml unzip
# The dependency parser itself uses yaml.safe_load; keep that import available
# in the validation job that executes this script.
require_apt_package .github/workflows/build-test.yml python3-yaml

# Negative control: comments are not package installations.
mutant=$(mktemp -d "${TMPDIR:-/tmp}/dependency-bootstrap.XXXXXX")
trap 'rm -rf "$mutant"' EXIT
mkdir -p "$mutant/.github/workflows"
cp .github/workflows/asan.yml "$mutant/.github/workflows/asan.yml"
sed -i 's/gnupg/libgcrypt20-dev/g' "$mutant/.github/workflows/asan.yml"
printf '\n# gnupg was removed from the apt install above\n' \
  >>"$mutant/.github/workflows/asan.yml"
sed -i '/set -euo pipefail/a\          echo install gnupg' \
  "$mutant/.github/workflows/asan.yml"
sed -i '/set -euo pipefail/a\          echo "apt-get install gnupg"' \
  "$mutant/.github/workflows/asan.yml"
if CI_DEPENDENCY_ROOT="$mutant" require_apt_package \
    .github/workflows/asan.yml gnupg >/dev/null 2>&1; then
  echo 'FAIL: dependency comment mutant was accepted as an installation' >&2
  exit 1
fi
echo 'OK: dependency comment mutant rejected'

echo 'OK: fork fallback dependencies are explicitly bootstrapped'
