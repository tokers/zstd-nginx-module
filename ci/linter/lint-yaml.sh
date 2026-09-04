#!/usr/bin/env bash
# ci/linter/lint-yaml.sh -- yamllint over every *.yml/*.yaml, plus actionlint
# over .github/workflows/*.
#
# Workflows are code that fails silently: a bad `if:` expression, an unknown
# context or a shell error inside a `run:` block does not stop the run, it
# makes the job pass while checking nothing. actionlint is the only checker
# here that reads them as GitHub Actions rather than as YAML.
#
#   -ignore 'label ".+" is unknown'
#       actionlint 1.7.7 carries a FIXED list of runner images and flags newer
#       ones (ubuntu-26.04, ubuntu-26.04-arm) as unknown. Every such report is
#       about the linter's age, not the workflow. Drop the ignore once
#       actionlint is new enough to know the labels this repo targets.
#   SHELLCHECK_OPTS=-Swarning
#       actionlint's embedded shellcheck otherwise reports at info while
#       lint-sh.sh gates at warning -- same finding, two verdicts.
#
# No --strict on yamllint, on purpose: warnings (long inline `run:` lines) stay
# visible without failing the gate, errors still block. The rule set lives in
# .yamllint at the repo root so editors and this script agree.
#
# actionlint and zizmor are not alternatives: actionlint reads a workflow as
# SYNTAX (bad if:, unknown context, shell error in run:), zizmor reads it as an
# ATTACK SURFACE (template injection, dangerous triggers, leaked credentials,
# unpinned actions, over-broad permissions). This repo targets self-hosted
# runners, where a workflow-level mistake is arbitrary code execution on the
# build host -- so the security pass is not optional here.
#
# --persona=pedantic, not the default: the default already passes on this tree,
# so gating on it would never go red. Pedantic is what caught the matrix
# interpolations in ci-deep.yml and the undocumented CodeQL permissions. Findings
# that are genuinely inapplicable get a `# zizmor: ignore[rule]` at the line,
# with the reason -- never a blanket rule disable in zizmor.yml.
#
# --offline: no API calls from a commit hook. The online audits need a token and
# only add repo-settings context, which belongs in a periodic review, not here.
#
# Usage: ci/linter/lint-yaml.sh [files...]   Env: LINT_MODE=staged|all
# Extend: yamllint rules live in .yamllint at the repo root.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '\.ya?ml$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-yaml: no YAML files to check"; exit 0; }

echo "lint-yaml: ${#FILES[@]} file(s)"
rc=0

need yamllint "apt-get install yamllint"
say "yamllint"
yamllint "${FILES[@]}" || rc=1

WF=()
for f in "${FILES[@]}"; do
    [[ "$f" =~ ^\.github/workflows/ ]] && WF+=("$f")
done
if [ "${#WF[@]}" -gt 0 ]; then
    need actionlint "go install github.com/rhysd/actionlint/cmd/actionlint@latest  (see install-linters.sh)"
    say "actionlint (${#WF[@]} workflow(s))"
    SHELLCHECK_OPTS=-Swarning \
        actionlint -ignore 'label ".+" is unknown' "${WF[@]}" || rc=1

    need zizmor "pipx install zizmor"
    say "zizmor (workflow security, pedantic)"
    zizmor --offline --persona=pedantic --no-progress "${WF[@]}" || rc=1
fi

exit "$rc"
