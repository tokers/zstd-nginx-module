#!/usr/bin/env bash
# ci/linter/selftest.sh -- negative controls for the lint gate itself.
#
# The gate is the thing that decides whether everything else is allowed to
# land, so "the gate ran and said clean" has to be distinguishable from "the
# gate ran nothing and said clean". That distinction is not observable from a
# green lint job: a selector typo used to make run-all.sh print
# "== all linters clean ==" and exit 0 having executed zero checkers.
#
# Every case here asserts the FAILING direction -- a check that only ever
# asserts the passing direction cannot detect its own disarming.
#
# Usage:  ci/linter/selftest.sh
# Exit:   0 all controls held, 1 one or more did not.
#
# Runs in about a second: no case invokes a real checker (LINT_ONLY values are
# either bogus or rejected before dispatch), so no linter needs to be installed.
#
# Extend: add a case() line. Keep each case asserting a specific exit status,
# and prefer a case where the OLD, broken behaviour would have passed.

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 2

rc=0

# case <expected-exit> <description> -- command...
case_() {
    local want="$1" desc="$2"; shift 2
    local out got
    out="$("$@" 2>&1)"; got=$?
    if [ "$got" -eq "$want" ]; then
        echo "ok   $desc (exit $got)"
    else
        echo "FAIL $desc: expected exit $want, got $got" >&2
        printf '       | %s\n' "${out//$'\n'/$'\n       | '}" >&2
        rc=1
    fi
}

# The regression itself: an unmatched selector must be "could not run" (2),
# not "clean" (0).
case_ 2 "unknown LINT_ONLY exits 2" \
    env LINT_ONLY=nosuchchecker ci/linter/run-all.sh

# ...including when only SOME of the listed names are bogus in a way that
# leaves nothing selected.
case_ 2 "LINT_ONLY of only-bogus names exits 2" \
    env LINT_ONLY="c-lang shellscript" ci/linter/run-all.sh

# The error names the offending value and the known checkers, or nobody can
# act on it.
# Captured first, not piped into grep: `set -o pipefail` would otherwise hand
# the pipeline run-all.sh's exit 2 and the assertion would read as failed no
# matter what the message said.
msg="$(env LINT_ONLY=nosuchchecker ci/linter/run-all.sh 2>&1)"
if printf '%s\n' "$msg" | grep -q 'matched no checker; known: .*sh'; then
    echo "ok   unmatched-selector message names value and known checkers"
else
    echo "FAIL unmatched-selector message is not actionable" >&2
    rc=1
fi

# Positive control: the selector still selects. --list is used rather than a
# real run so this stays independent of which linters are installed.
case_ 0 "--list works" ci/linter/run-all.sh --list
case_ 0 "CI topology negative controls hold" \
    python3 ci/linter/ci_topology.py --selftest

# The CodeQL SARIF filter decides which findings reach the Security tab. Its
# dangerous direction is dropping a result it should have kept -- silently,
# since a dropped finding leaves no trace. Its own controls assert the KEEP
# side (module results, and results with no resolvable location).
case_ 0 "CodeQL SARIF filter scoping controls hold" \
    python3 ci/tools/filter-codeql-sarif.py --selftest

# Work-list consumers used process substitution, whose exit status is not
# visible to mapfile. Exercise each real consumer with a producer that emits a
# plausible prefix and then fails; all three must propagate its exact status.
case_ 23 "lint work list rejects partial output followed by failure" \
    env MAPFILE_CHECKED_FAULT=partial-error ci/linter/lint-sh.sh ci/linter/lib.sh
case_ 23 "dictionary work list rejects partial output followed by failure" \
    env MAPFILE_CHECKED_FAULT=partial-error ci/fuzz/gen_dict.sh --check

# shellcheck disable=SC2317  # Invoked indirectly through case_ below.
dict_crlf_rejected_() (
    local backup out got mode
    backup="$(mktemp "${TMPDIR:-/tmp}/fuzz-dict.XXXXXX")" || exit 2
    cp ci/fuzz/fuzz.dict "$backup" || exit 2
    trap 'cp "$backup" ci/fuzz/fuzz.dict; rm -f "$backup"' EXIT INT TERM
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s\r\n' "$line"
    done <"$backup" >ci/fuzz/fuzz.dict

    for mode in check regenerate; do
        if [ "$mode" = check ]; then
            out="$(ci/fuzz/gen_dict.sh --check 2>&1)"; got=$?
        else
            out="$(ci/fuzz/gen_dict.sh 2>&1)"; got=$?
        fi
        if [ "$got" -ne 1 ] ||
            ! printf '%s\n' "$out" | grep -qF 'contains CRLF line endings'; then
            printf '%s: expected exit 1 with CRLF diagnosis, got %d\n%s\n' \
                "$mode" "$got" "$out" >&2
            exit 1
        fi
    done
)
case_ 0 "dictionary CRLF rejection covers check and regeneration" \
    dict_crlf_rejected_
case_ 23 "coverage work list rejects partial output followed by failure" \
    env MAPFILE_CHECKED_FAULT=partial-error ci/tools/coverage.sh \
        --selftest-work-list "$ROOT"
case_ 23 "docs directive list rejects partial output followed by failure" \
    env MAPFILE_CHECKED_FAULT=partial-error ci/tools/test_docs_ci_drift.sh \
        --selftest-directive-list
case_ 23 "docs workflow list rejects partial output followed by failure" \
    env MAPFILE_CHECKED_FAULT=partial-error ci/tools/test_docs_ci_drift.sh \
        --selftest-workflow-list

# ----------------------------------------------------------------------------
# workflow_policy.py -- the red path of each policy check.
#
# Every fixture below encodes a bypass that VALID YAML used to walk straight
# through while the checks parsed workflows by regex. Each was verified in both
# directions when it was written: red on the current parser, green on the
# regex one. They are committed rather than planted in .github/workflows/ at
# runtime so no cleanup failure can leave a probe workflow in the live tree.
#
# Extend: add a fixture directory with its own .github/workflows/ and a README
# stating which bypass it encodes, then a policy_ line here.

policy_() {  # policy_ <expected-exit> <fixture> <subcommand>
    local want="$1" fixture="$2" cmd="$3"
    case_ "$want" "policy $cmd: $fixture" \
        env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd"
}

# policy_msg_ <fixture> <subcommand> <grep-ere> -- red, and red for the STATED
# reason.
#
# Exit status alone cannot tell a finding from a crash: an uncaught
# AttributeError also exits 1, so a fixture asserting only `1` stays green when
# the branch it covers is replaced by a traceback. That is not hypothetical --
# deleting the `isinstance(spec, dict)` guard in check_secrets() made
# secrets-untyped die on `None.get()` and every exit-1 control still passed.
# Use this wherever the guard under test is what stops a crash.
#
# Captured first, not piped: pipefail would hand the pipeline the checker's
# exit 1 and the assertion would read as failed whatever the message said.
policy_msg_() {
    local fixture="$1" cmd="$2" want_re="$3" out got
    out="$(env "WORKFLOW_POLICY_ROOT=ci/linter/fixtures/policy/$fixture" \
        python3 ci/linter/workflow_policy.py "$cmd" 2>&1)"; got=$?
    if [ "$got" -eq 1 ] && printf '%s\n' "$out" | grep -qE "$want_re"; then
        echo "ok   policy $cmd: $fixture (finding, not a crash)"
    else
        echo "FAIL policy $cmd: $fixture: expected exit 1 matching /$want_re/, got $got" >&2
        printf '%s\n' "$out" | sed 's/^/       | /' >&2
        rc=1
    fi
}

# THE control that makes the rest mean anything: a fixture tree that is simply
# a valid workflow must be GREEN on all three. Without it, a red on any bypass
# fixture could be the fixture shape rather than the bypass.
policy_ 0 clean runners
policy_ 0 clean ports
policy_ 0 clean docs
policy_ 0 clean provenance
# Deliberately NO `policy_ 0 clean cadence`: the clean fixture has no
# workflow_call member, so that line would assert green over an empty set --
# vacuous, and indistinguishable from the check being broken. The green control
# for cadence is member-with-push-ok below, which has a member to clear.

# A `.yaml` workflow was invisible to every check: unchecked runner, unchecked
# ports, undocumented gate.
policy_ 1 bypass-yaml-extension runners
policy_ 1 bypass-yaml-extension docs

# `on: [pull_request]` / `on: pull_request` are the same trigger as the mapping
# form; both used to skip the runner-trust check, as did an inline
# pull_request_target.
policy_ 1 bypass-inline-events runners

# `runtime:  # comment` used to yield zero jobs, so a runtime-bearing job with
# no port band reported "no runtime-bearing jobs" and exit 0.
policy_ 1 bypass-commented-job-key ports

# A band verifier placed BELOW the first binder. Declaration, pass-through and
# uniqueness all hold, so the presence checks stay green -- this repo's own
# build-test.yml sat in exactly this shape until 2026-08-02.
policy_ 1 verify-after-bind ports

# A job whose only binder is `prove` (not ci/tools/test_runtime.py) used to be
# exempt from the "declare TEST_BASE_PORT" requirement, even though `prove` is
# already a BINDERS member and the ordering check already treats it as one.
# Found downstream as a failed negative control: deleting a prove-only job's
# band left this check green.
policy_ 1 prove-only-binder-exempt ports

# The other half of the same defect: a prove job may declare a unique band,
# satisfy every check above, and still bind 1984, because Test::Nginx reads
# TEST_NGINX_PORT and has never heard of TEST_BASE_PORT. The driver's
# pass-through guard is keyed on starts_runtime, so it never covered `prove`.
policy_ 1 prove-band-not-passed-through ports

# A workflow_call member carrying its own `push:` runs twice per change and BOTH
# runs are green, so nothing else in the toolchain notices. Every member here is
# correct today, but only a per-file comment says so, and a comment does not
# survive the next workflow copied in. These run as a PAIR: the -ok fixture is
# the same file with `schedule:` (the intended shape), and without it the red
# above is equally consistent with "any second trigger is flagged".
policy_ 1 member-with-push cadence
policy_ 0 member-with-push-ok cadence

# The three ways a secret goes missing between a caller and a member, none of
# which fails anything at the time it is introduced. `inherit` is green and
# merely over-broad; an untyped declaration starts the call with an empty
# string; an undeclared secret is dropped at the boundary while both halves
# read as correct in isolation. These run as a GROUP with secrets-typed-ok:
# this repo declares no secrets, so without a green fixture that DOES, the
# three reds would be equally consistent with "any mention of a secret is
# flagged" -- and the live check would be asserting green over an empty set.
policy_ 1 secrets-inherit secrets
# The same defect one repository over. The caller loop filtered to local
# members BEFORE judging `inherit`, so a call to
# `owner/repo/.github/workflows/x.yml@ref` was skipped -- the case where
# `inherit` is WORST, since the secret set crosses a repository boundary to a
# moving ref. Distinct from secrets-inherit: reordering that filter back below
# the inherit branch leaves the local fixture red and only this one green.
policy_ 1 secrets-inherit-external secrets
# The third case that filter used to swallow: an external call whose `secrets:`
# is neither a mapping nor `inherit`. `inherit` was hoisted above the filter,
# but the SHAPE check stayed below it, so `secrets: false` on an external member
# reported clean over a caller GitHub refuses to start. Exit 2, not 1 -- an
# uninterpretable `secrets:` means the check did not run over that call, so
# policy_msg_ (which hardcodes exit 1) cannot assert this one. Moving the shape
# check back below `if not local` turns this fixture green while every other
# secrets fixture stays exactly as it is.
policy_ 2 secrets-malformed-external secrets
# Message-asserted: a null spec is exactly the input that crashes `.get()` if
# the isinstance guard is removed, and a traceback also exits 1.
policy_msg_ secrets-untyped secrets 'declares secret .* untyped'
# secrets-optional is NOT redundant with secrets-untyped. Disarming the
# `required is not True` test left secrets-untyped red anyway -- it trips the
# missing-key branch -- so the value test had no control of its own. A mutant
# that survives is a branch nothing is gating.
policy_ 1 secrets-optional secrets
# ...and secrets-no-required-key is not redundant with EITHER. `NAME:` with
# nothing under it parses to null, and null `is not True`, so the value branch
# covers secrets-untyped even when the missing-key branch is deleted. Only a
# spec that is a real mapping without the key separates the two.
policy_ 1 secrets-no-required-key secrets
policy_ 1 secrets-undeclared secrets
# The mirror of secrets-undeclared, and the direction the check missed when
# first written: member requires it, caller wires nothing.
policy_ 1 secrets-required-not-wired secrets
policy_ 0 secrets-typed-ok secrets

# A step downloads a tarball; a later step in the same job extracts it and
# runs the unpacked configure with no gpg/sha256 trust-anchor assertion
# anywhere in between -- the class this repo hit in build-test.yml/ci-deep.yml
# after the ci-build.sh fix (a direct download/extract/execute path added
# outside that already-verified helper). These run as a PAIR: the -ok fixture
# is the same job with a sha256 comparison step inserted, so the red above is
# not equally consistent with "any download in a job is flagged".
policy_ 1 provenance-unverified-extract provenance
policy_ 0 provenance-verified-ok provenance
# A reviewed verification helper named later in the SAME run block cannot
# retroactively protect extraction that occurred earlier in that block.
policy_ 1 provenance-verify-helper-after-extract provenance
# The trap this check exists to close: the download step is gated
# `cache-hit != 'true'`, so a cache HIT skips it entirely and a checker that
# only looks for a download step present would read the job as having
# nothing to verify. This must still go red -- a cached tarball is exactly as
# untrusted as a fresh one until re-checked.
policy_ 1 provenance-cache-hit-skips-verify provenance
# The scoping regex must know every spelling that writes a file from the
# network, not just `-O`/`-o`. A bare `wget "<url>"` is the idiom four of this
# repo's own jobs use; while the regex required -O those jobs matched no
# download token and were skipped wholesale rather than checked -- a gate
# failing open. Same class for `curl -O` and `Invoke-WebRequest -OutFile`.
policy_ 1 provenance-bare-wget-unverified provenance
# One probe per spelling the DOWNLOAD_RE comment claims to cover. Without
# these two, a regression in the curl -O or Invoke-WebRequest branch passes
# the selftest while the comment still advertises them as handled.
policy_ 1 provenance-curl-O-unverified provenance
policy_ 1 provenance-iwr-outfile-unverified provenance
# The ANCHOR half failing open, not the scoping half: a bare `sha256sum f`
# prints a digest and compares nothing, yet used to satisfy TRUST_ANCHOR_RE.
# provenance-verified-ok is the green control for a real comparison.
policy_ 1 provenance-noncomparing-sha256 provenance
# No archive at all: download a standalone binary, chmod +x, run it. The
# tar/unzip patterns miss this entirely, yet it is the same privilege
# boundary one step shorter.
policy_ 1 provenance-exec-downloaded-binary provenance
# ZIP files need not retain a .zip extension. The detector must still reject
# an unverified archive passed to unzip under an extensionless local name.
policy_ 1 provenance-unverified-unzip provenance
policy_ 1 provenance-chained-unzip provenance
policy_ 1 provenance-mixed-codeql-unzip provenance
policy_ 1 provenance-pipe-unzip provenance
policy_ 1 provenance-subshell-unzip provenance
policy_ 1 provenance-apt-chained-unzip provenance

# A mistyped pool label in a schedule-only workflow. The trust half of the
# runners check does not apply to a workflow no fork can reach, and skipping it
# used to skip the LABEL membership test with it -- while actionlint, the only
# other thing that reads runner labels, stays silent on the `fromJSON(...)`
# selectors this repo uses everywhere. Six selectors in bump.yml and ci-deep.yml
# had no label checking at all. These two run as a PAIR: the -ok fixture is the
# same file spelled correctly, and without it the red below is equally
# consistent with "every non-PR-reachable workflow is now flagged".
policy_ 1 schedule-only-runner-labels runners

# The -ok fixture is checked through a TEMPORARY COPY whose selector is
# regenerated from workflow_policy.py, rather than against the tracked file's
# hardcoded selector. A hosted-only adopter, which step 13 tells to turn
# SELF_HOSTED_ALLOWED off, otherwise sees this
# POSITIVE control fail against a selector the fixture still spells the
# skeleton's way: correct behaviour, confusing symptom, and it cost the
# nginx-cache-turbo-module adoption a debugging detour on 2026-08-10.
#
# A COPY, not the tracked file: a selftest that rewrites a tracked fixture
# leaves the tree dirty on every run, and a test which mutates the repo it is
# testing is a worse problem than the stale fixture it fixes.
ok_src="ci/linter/fixtures/policy/schedule-only-runner-labels-ok"
if approved="$(python3 ci/linter/fixture-selector.py 2>/dev/null)" \
   && [ -n "$approved" ] && [ -d "$ok_src" ]; then
    ok_tmp="$(mktemp -d "${TMPDIR:-/tmp}/lint-okfix.XXXXXX")"
    cp -r "$ok_src/." "$ok_tmp/"
    python3 ci/linter/fixture-selector.py --write \
        "$ok_tmp/.github/workflows/nightly.yml"
    case_ 0 "policy runners: schedule-only-runner-labels-ok (selector from workflow_policy)" \
        env "WORKFLOW_POLICY_ROOT=$ok_tmp" \
        python3 ci/linter/workflow_policy.py runners
    rm -rf "$ok_tmp"
else
    # Hosted-only repo: SELF_HOSTED_ALLOWED is off, so there is no approved
    # self-hosted selector for a positive control to assert. Say so rather
    # than silently skipping -- a control that vanishes is the failure mode
    # this whole file exists to catch.
    echo "skip policy runners: schedule-only-runner-labels-ok (SELF_HOSTED_ALLOWED off: hosted-only)"
fi

# WIRING CONTROLS. These assert that a checker is reachable at all, which is a
# weaker claim than "it goes red on a defect" -- the red-direction probes need
# real tools and live in each checker's header instead, so this file keeps its
# no-linter-required property. They exist because both failures below were
# silent: a checker nobody dispatches and a hook nobody runs look exactly like a
# clean tree.
#
# core.hooksPath REPLACES .git/hooks/, so `pre-commit install` writes a file git
# never reads. Measured 2026-08-02: trailing whitespace and a missing final
# newline committed clean past the hooks whose only job is those two things.
# .githooks/pre-commit therefore has to invoke pre-commit itself.
case_ 0 "the commit hook invokes the pre-commit-config hooks" \
    grep -q '^ *pre-commit run' .githooks/pre-commit

# run-all.sh dispatches by glob, so a checker that is not executable, or is
# named outside the lint-*.sh pattern, is silently not run.
# Every glob-discovered checker is named in lint.yml's LINT_ONLY.
#
# run-all.sh picks checkers up by glob, but CI narrows the run to an explicit
# allowlist, and nothing connected the two: a checker added to ci/linter/ ran
# locally and in the pre-commit hook while being silently absent from every PR.
# That is not a hypothetical -- ci-cadence shipped in 2026-08-06 and had never
# run remotely when this control was written. A gate that runs everywhere except
# the merge path is the one place it is load-bearing.
missing=""
only="$(sed -n 's/^ *LINT_ONLY: *//p' .github/workflows/lint.yml)"
for s in ci/linter/lint-*.sh; do
    n="${s#ci/linter/lint-}"; n="${n%.sh}"
    # "c" is deliberately excluded in CI (see lint.yml's header): the src/
    # scanners run in security-scanners.yml instead.
    [ "$n" = "c" ] && continue
    printf '%s\n' "$only" | tr ' ' '\n' | grep -qx "$n" || missing="$missing $n"
done
if [ -z "$missing" ]; then
    echo "ok   every checker is named in lint.yml LINT_ONLY"
else
    echo "FAIL checkers absent from lint.yml LINT_ONLY:$missing" >&2
    echo "       | they run locally and in the hook, but never on a PR" >&2
    rc=1
fi

case_ 0 "lint-spelling is dispatched by run-all.sh" \
    bash -c 'ci/linter/run-all.sh --list | grep -q lint-spelling.sh'

# The control above closes the loop for checkers that ARE a ci/linter/lint-*.sh
# script. Two gates in lint.yml are not: ast-grep and gitleaks live in
# .pre-commit-config.yaml and are invoked as their own `run:` steps, because
# run-all.sh discovers checkers by the lint-*.sh glob and can never reach them.
# That left them structurally unguarded -- delete either step from lint.yml and
# every control here still passed, which is how they came to be hook-only (and
# so absent from every PR) until 2026-08-22.
#
# Keying on the step NAME rather than the tool binary is deliberate: the name is
# what the job summary shows, and a step renamed out of this list is a step
# whose disappearance from the UI nobody would notice either.
for step in \
    'ast-grep (structural sinks, gate on promoted rules)' \
    'gitleaks (whole tracked tree)'
do
    if grep -qF -- "- name: $step" .github/workflows/lint.yml; then
        echo "ok   lint.yml still runs the non-script gate: $step"
    else
        echo "FAIL lint.yml no longer runs: $step" >&2
        echo "       | it is not a ci/linter/lint-*.sh script, so run-all.sh" >&2
        echo "       | cannot dispatch it and no other control covers it" >&2
        rc=1
    fi
done

# The prompt-steps temp root went with the checker (see below), leaving only
# $badroot. Its trap is registered here because `trap ... EXIT` REPLACES any
# earlier EXIT trap rather than adding to it.
#
# lint-prompt-steps.* and lint-sync-stamp.sh are reference-only: they check
# ci/PROMPT.md step citations and the skeleton-shared .github/ content stamps,
# neither of which this module has. Dropped with their selftest cases rather
# than left asserting against a checker that is not here.
badroot=""
trap 'rm -rf ${badroot:+"$badroot"}' EXIT INT TERM

# Unparsable YAML is "could not run" (2), never "clean" -- GitHub may still
# read a file this parser rejects, so a verdict over the rest of the tree would
# be unsupported. Fixture is generated: a committed broken-YAML file would trip
# yamllint on the real tree.
# Assigned into the variable the EXIT trap above already covers; a second
# `trap ... EXIT` here would replace that one and leak this temp root.
badroot="$(mktemp -d)"
mkdir -p "$badroot/.github/workflows"
printf 'on: [pull_request\njobs: {\n' > "$badroot/.github/workflows/broken.yml"
case_ 2 "policy runners: unparsable YAML is exit 2, not clean" \
    env "WORKFLOW_POLICY_ROOT=$badroot" python3 ci/linter/workflow_policy.py runners

if [ "$rc" -eq 0 ]; then
    echo "== lint gate selftest: all controls held =="
else
    echo "== lint gate selftest: FAILED ==" >&2
fi
exit "$rc"
