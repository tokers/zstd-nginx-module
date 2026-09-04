#!/usr/bin/env bash
# ci/linter/lint-c.sh -- C static analysis for src/ and ci/ *.[ch].
#
# Mirrors .github/workflows/security-scanners.yml exactly:
#   flawfinder  gate at >=4   (below 4 is risky-API grep noise; gating on it
#                              trains everyone to --no-verify)
#   semgrep     gate at >=WARNING with p/c + p/security-audit
# plus cppcheck, which CI does not run and which is cheap enough locally.
#
# If a threshold moves in that workflow, move it here in the SAME commit --
# otherwise local-green stops predicting remote-green, which is the only
# reason this script exists.
#
# NOT here, deliberately:
#   clang-tidy -- needs ngx_auto_config.h, i.e. a configured nginx tree. A
#                 local hook cannot assume one, and a check that skips itself
#                 when the tree is missing is a vacuous gate. CI-only.
#
# Usage: ci/linter/lint-c.sh [files...]     (no args => LINT_MODE, default all)
# Env:   LINT_MODE=staged|all
#        LINT_SKIP_SEMGREP=1   explicit, loud opt-out for slow machines
#
# Extend: add a scanner as one more block below; keep the CI mirror comment
# accurate or the header above becomes a lie.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '^(src|ci)/.*\.[ch]$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-c: no C files to check"; exit 0; }

echo "lint-c: ${#FILES[@]} file(s)"
rc=0

# fuzz.dict's coding-name tokens are generated from the real
# ngx_http_zstd_coding_weight(..., "TOKEN", ...) call sites in src/*.[ch]
# (ci/fuzz/gen_dict.sh). A merely incomplete dictionary still produces a
# green crash-only fuzz run, so this is the only thing that would ever
# catch a new coding name added without updating the dictionary.
say "fuzz.dict coding-token drift (ci/fuzz/gen_dict.sh --check)"
bash "$(git rev-parse --show-toplevel)/ci/fuzz/gen_dict.sh" --check || rc=1

need flawfinder "apt-get install flawfinder"
say "flawfinder (gate >=4)"
flawfinder --minlevel=4 --error-level=4 --quiet "${FILES[@]}" || rc=1

need cppcheck "apt-get install cppcheck"
say "cppcheck (error,warning)"
# --error-exitcode=1 makes any reported id fail. missingInclude/unusedFunction
# are suppressed: this is a module compiled INTO nginx, so its headers and its
# ngx_http_* callbacks are never resolvable or called from this tree alone.
cppcheck --quiet --error-exitcode=1 \
    --enable=warning,performance,portability \
    --inline-suppr \
    --suppress=missingInclude --suppress=missingIncludeSystem \
    --suppress=unusedFunction --suppress=unknownMacro \
    --suppress=normalCheckLevelMaxBranches \
    "${FILES[@]}" || rc=1

if [ -n "${LINT_SKIP_SEMGREP:-}" ]; then
    warn "semgrep SKIPPED via LINT_SKIP_SEMGREP -- CI still gates on it"
else
    need semgrep "pipx install semgrep==1.173.0"
    say "semgrep (gate >=WARNING)"
    # --quiet is deliberately absent: it hides semgrep-core's own crash text
    # (io_uring/RLIMIT_MEMLOCK) and turns a diagnosable failure into a bare
    # exit 2 that reads like a real finding.
    #
    # --jobs=1 is a correctness flag, not a speed flag. semgrep-core defaults to
    # one OCaml domain per core (32 here), each of which opens its own io_uring
    # ring against the 8 MB RLIMIT_MEMLOCK this host shares with the self-hosted
    # CI runners. Under runner load it exhausts and semgrep-core dies with
    # `Unix_error: Cannot allocate memory io_uring_queue_init` -> exit 2, which
    # this script reports as a finding. Observed 3/3 crashed on a 3-file scan
    # while runners were busy, 0/3 on an idle box: a load-dependent false RED.
    # src/ is three files, so the parallelism was buying nothing to begin with.
    #
    # --metrics=off: no scan-summary POST to semgrep.dev. Measured 2.76s -> 1.27s
    # on this tree, i.e. more than half the wall clock was that upload.
    semgrep scan --config p/c --config p/security-audit \
        --severity=WARNING --severity=ERROR --error \
        --jobs=1 --metrics=off "${FILES[@]}" || rc=1
fi

exit "$rc"
