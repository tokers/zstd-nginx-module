#!/usr/bin/env bash
# Regression test for audit A30-F7: coverage.sh must unconditionally
# (re)build the harness prober before running testkit scenarios. The
# prober binary can exist but be STALER than its sources -- a guard that
# only rebuilds when the binary is ABSENT does not catch that case, and a
# stale binary silently bails every fault/counter scenario while
# coverage.sh still reports coverage success.
#
# A second-pass audit could not exercise this guard's negative control
# directly: the ci/t/harness submodule is not checked out in every
# environment, and a full coverage.sh run is a forbidden long-runner here.
# This test instead asserts the STRUCTURAL shape of the fix -- the
# prober/build.sh invocation is not nested inside a condition that tests
# for the binary's absence -- and proves the assertion can actually fail
# by mutating a copy of coverage.sh back into the old buggy (guarded
# rebuild) shape and confirming the assertion goes red on that copy.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
src="$root/ci/tools/coverage.sh"

# Passes iff `bash ".../prober/build.sh"` is invoked unconditionally
# (module-level "always rebuild"), not gated behind an absence check such
# as `if [ ! -x .../run-scenario.sh ]; then ... build.sh; fi` or
# `if [ ! -f .../prober ]; then ... build.sh; fi`.
assert_unconditional_rebuild() {
    local file=$1

    grep -Fq 'prober/build.sh' "$file" || return 1

    # Extract the block from the harness-submodule presence check to its
    # closing `fi` at the same indent, i.e. the whole
    # `if [ ! -x .../run-scenario.sh ]; then ... else ... fi` construct
    # that guards scenario execution.
    local block
    block=$(sed -n '/harness submodule not checked out/,/^    fi$/p' "$file")
    [ -n "$block" ] || return 1

    # The build.sh call must appear directly under the `else` branch (the
    # submodule-present path), not inside a NESTED absence-only guard
    # such as `if [ ! -x ... ] || [ ! -f .../prober ]; then build.sh; fi`
    # sitting inside that else. Isolate everything between `else` and the
    # matching `fi` and confirm build.sh is not itself wrapped in another
    # `if [ ! ... ]; then ... fi` around it.
    local else_branch
    else_branch=$(printf '%s\n' "$block" | sed -n '/^    else$/,/^    fi$/p')
    [ -n "$else_branch" ] || return 1

    # The rebuild invocation must actually be present INSIDE the else
    # branch (not merely somewhere else in the file, e.g. a comment or a
    # different guarded copy) -- otherwise this whole check is satisfied
    # by a file that mentions build.sh anywhere and never calls it here.
    # shellcheck disable=SC2016  # literal pattern: $MODULE_DIR must not expand
    printf '%s\n' "$else_branch" \
        | grep -Fq 'bash "$MODULE_DIR/ci/t/harness/ci/prober/build.sh"' \
        || return 1

    # Old buggy shape: a second, nested absence guard directly wrapping
    # the build.sh call, e.g.
    #   if [ ! -x ".../prober" ]; then
    #       bash ".../prober/build.sh"
    #   fi
    # Detect that shape: an `if [ ! ` line followed (within a few lines,
    # before any `fi`) by the build.sh invocation.
    if printf '%s\n' "$else_branch" \
        | awk '
            /if[[:space:]]*\[[[:space:]]*!/ { guard=1; next }
            /^[[:space:]]*fi[[:space:]]*$/  { guard=0; next }
            guard && /prober\/build\.sh/    { found=1 }
            END { exit !found }
        '; then
        return 1
    fi

    return 0
}

assert_unconditional_rebuild "$src"

work=$(mktemp -d "${TMPDIR:-/tmp}/coverage-prober-rebuild.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp "$src" "$work/coverage.sh"

# Mutate the fix back into the pre-A30-F7 buggy shape: gate the rebuild
# behind an absence-only check on the prober binary itself, so a STALE
# (present but outdated) binary would again silently skip the rebuild.
python3 - "$work/coverage.sh" <<'PY'
import sys

path = sys.argv[1]
with open(path) as f:
    text = f.read()

old = (
    '        # Always (re)build: the prober binary can exist but be staler than its\n'
    '        # sources, which silently bails every fault/counter scenario while\n'
    '        # this script still reports coverage success (audit A30-F7).\n'
    '        if ! bash "$MODULE_DIR/ci/t/harness/ci/prober/build.sh"; then\n'
)
new = (
    '        # (mutated) only rebuild when the prober binary is absent --\n'
    '        # this is the pre-A30-F7 buggy shape the negative control targets.\n'
    '        if [ ! -x "$MODULE_DIR/ci/t/harness/ci/prober/prober" ] && \\\n'
    '            ! bash "$MODULE_DIR/ci/t/harness/ci/prober/build.sh"; then\n'
)

if old not in text:
    sys.exit(
        "FAIL: mutation anchor text not found in coverage.sh -- "
        "the A30-F7 fix comment/guard moved; update this test together "
        "with coverage.sh"
    )

with open(path, "w") as f:
    f.write(text.replace(old, new, 1))
PY

if assert_unconditional_rebuild "$work/coverage.sh" >/dev/null 2>&1; then
    echo 'FAIL: mutated (absence-guarded) coverage.sh copy still passed the' \
        'unconditional-rebuild assertion -- the assertion cannot detect' \
        'a regression to the pre-A30-F7 stale-prober bug' >&2
    exit 1
fi
echo 'OK: negative control -- absence-guarded mutant correctly fails the' \
    'unconditional-rebuild assertion'

# Second negative control: drop the build.sh invocation from the else
# branch entirely (e.g. accidentally deleted, or moved somewhere the
# assertion does not look) and confirm the assertion still catches it --
# a file that merely MENTIONS build.sh elsewhere (a comment, a different
# guarded copy) must not satisfy this check.
cp "$src" "$work/coverage-removed.sh"
# shellcheck disable=SC2016  # literal pattern: $MODULE_DIR must not expand
sed -i '/bash "\$MODULE_DIR\/ci\/t\/harness\/ci\/prober\/build\.sh"/d' \
    "$work/coverage-removed.sh"
if assert_unconditional_rebuild "$work/coverage-removed.sh" >/dev/null 2>&1; then
    echo 'FAIL: coverage.sh copy with the build.sh call removed from the' \
        'else branch still passed the unconditional-rebuild assertion --' \
        'the assertion does not actually require the call inside that' \
        'branch' >&2
    exit 1
fi
echo 'OK: negative control -- else-branch-missing-build.sh mutant' \
    'correctly fails the unconditional-rebuild assertion'

echo 'OK: coverage.sh unconditionally rebuilds the prober (A30-F7) and' \
    'negative controls'
