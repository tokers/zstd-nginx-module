# fixture: member-with-push-ok

The green half of the `member-with-push` pair: a `workflow_call` member whose
second trigger is `schedule:`, which is the INTENDED shape -- codeql.yml and
ci-deep.yml are reached both from ci.yml and on their own cadence, and that is
not a duplicate run of the same tree.

This exists so the red next door means "a member carries a PR-duplicating
trigger" and not merely "a member carries two triggers".

Workflow: `.github/workflows/build-test.yml`.
