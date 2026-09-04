# fixture: member-with-push

A `workflow_call` member that also carries its own `push: branches: [main]`.
`workflow_call` does not suppress a member's own triggers, so this runs twice
per change -- once on the PR, once on the merge commit, against a tree
identical to the head that already passed. The two runs get different
concurrency keys, so `cancel-in-progress` cannot collapse them.

The reason this needs a fixture at all: BOTH runs are green. Nothing fails,
nothing is slower, and the duplicate is visible only in the runner bill and in
a README that has quietly stopped describing what runs when. Downstream this
shape reached six of seven members before review caught it.

`cadence` must go red here. Its pair, `member-with-push-ok`, is the same file
with `schedule:` instead -- without that twin, this red would be equally
consistent with "any member carrying a second trigger is flagged", which is not
the rule.

Workflow: `.github/workflows/build-test.yml`.
