# fixture: schedule-only-runner-labels-ok

The positive control for `schedule-only-runner-labels`, and the reason that one
means anything.

Same shape — schedule-only, not reachable from any pull request — but the
selector is the approved one: the pool read from `vars.POOL`, with a
GitHub-hosted fallback. Expected: `runners` exit 0.

`ci/linter/selftest.sh` regenerates this `runs-on:` line through a temporary
copy before checking it, so a hosted-only adopter that turns
`SELF_HOSTED_ALLOWED` off does not see this control fail against a selector it
deliberately rejects.

Without this, a red on the drift fixture is equally consistent with "the label
check caught the typo" and "non-PR-reachable workflows are now flagged
unconditionally". Those are different checks and only one of them is wanted; the
pair separates them.

It is a separate fixture rather than a second workflow inside the red one
because `policy_` asserts an exit STATUS, not a finding count. A clean workflow
sitting beside a dirty one in the same tree changes nothing about the exit code
and would prove nothing.
