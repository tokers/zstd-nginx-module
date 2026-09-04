# fixture: schedule-only-runner-labels

Encodes the bypass: **a drifted runner selector in a workflow that no pull
request can reach was checked by nothing at all.**

`check_runners` used to `continue` past any workflow whose triggers did not
include `pull_request` or `workflow_call`, because the fork-trust question only
applies to a job a fork can cause to run. That skipped the exact-string
membership test with it, and that membership test is the only thing in this
toolchain that reads the pool labels.

actionlint does not cover the gap. It validates runner labels for a LITERAL
`runs-on` only; every selector in this repo is a `fromJSON(...)` expression,
which it walks past without a word. A quiet linter and a clean linter print the
same thing.

Measured in the real tree, 2026-08-02: `builder02` -> `buidler02` in
`build-test.yml` (`workflow_call`, PR-reachable) was reported; the same edit in
`bump.yml` and `ci-deep.yml` (`schedule` + `workflow_dispatch`) was silent, on
both this check and actionlint. Six selectors had no label checking anywhere.

The failure mode is why it is worth a gate: a selector naming a pool this repo
does not own is not a lint error and not a dispatch error. It is a queued job
that never picks up a runner, on a weekly schedule nobody is watching.

`nightly.yml` here is that shape — schedule-only, with the pool inlined into
`runs-on` instead of read from `vars.POOL`. Expected: `runners` exit 1.

Why an inlined pool rather than the mistyped `buidler02` this fixture used to
carry: since 2026-08-13 the pool label lives in the `POOL` repo variable and
appears nowhere in the tree, so a label typo is no longer expressible *here*.
It is still expressible in the GitHub UI, and it fails the same way it always
did: `["self-hosted","buidler02","lxc"]` is valid JSON and non-empty, so it
parses, skips the fallback, and queues against a label nobody answers. No
linter in this repo can see the variable's value.
What remains spellable, and what this now encodes, is a selector that has
drifted from the approved form: an inlined label set, a resurrected fork
ternary, a hand-edited fallback. That drift fails the same way the typo did.

The GREEN half of this control is the sibling fixture
`schedule-only-runner-labels-ok` — the same file using the approved selector,
which must stay silent. Without it, a red here could be "non-PR-reachable
workflows are now always flagged" rather than "the drift is caught".
