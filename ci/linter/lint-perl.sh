#!/usr/bin/env bash
# ci/linter/lint-perl.sh -- syntax + critic pass over the Test::Nginx suite
# (ci/t/*.t) and any *.pl / *.pm.
#
# Two passes, because they catch different failures:
#   perl -c      a typo in a .t file otherwise surfaces as a confusing prove
#                failure minutes into a CI run. Needs Test::Nginx::Socket
#                installed -- see install-linters.sh (cpan, not apt).
#   perlcritic   severity 4 (harsh and above). Severity 3 and below is style
#                argument on DSL-shaped test files (__DATA__ blocks, no
#                `use strict` in a .t that Test::Nginx already sets up) and
#                would land this red on arrival.
#
# Usage: ci/linter/lint-perl.sh [files...]   Env: LINT_MODE=staged|all
# Extend: repo-wide policy exceptions belong in a .perlcriticrc at the repo
# root so editors agree with this script.

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

mapfile_checked FILES lint_files '\.(t|pl|pm)$' "$@"
[ "${#FILES[@]}" -gt 0 ] || { echo "lint-perl: no Perl files to check"; exit 0; }

echo "lint-perl: ${#FILES[@]} file(s)"
rc=0

need perl "apt-get install perl"
say "perl -c"
for f in "${FILES[@]}"; do
    perl -c "$f" >/dev/null || rc=1
done

need perlcritic "apt-get install libperl-critic-perl  (or: cpan Perl::Critic)"
say "perlcritic (severity >=4)"
perlcritic --severity 4 --quiet "${FILES[@]}" || rc=1

exit "$rc"
