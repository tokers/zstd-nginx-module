# fixture: secrets-malformed-external

`secrets:` holding neither a mapping nor `inherit` -- here `false` -- on a call
to a reusable workflow in ANOTHER REPOSITORY.

The reason this needs its own fixture, next to `secrets-inherit-external`: the
caller loop rejected `inherit` above the local-member filter but still validated
the SHAPE of `secrets:` below it. An external call carrying `secrets: false` was
dropped by that filter before the shape was ever judged, and `secrets` reported
CLEAN over a caller GitHub will refuse to start. `secrets: []` took the same
path.

The filter exists to gate `declared` lookups, which mean nothing for a member
this tree cannot read. It was never meant to gate whether the call is valid at
all, and that is the distinction this fixture pins.

No member workflow is checked in here, deliberately -- as in
`secrets-inherit-external`, the member is external and unreadable, so the shape
of the call site is the only thing there is to judge.

`secrets` must exit **2** here, not 1. A `secrets:` value this checker cannot
interpret means the check did not RUN over that call, which is a different claim
from "ran and found a problem" -- see `PolicyError` in `workflow_policy.py`.
That is also why `policy_msg_` cannot assert this fixture: it hardcodes exit 1.

Its local twin is `secrets-undeclared` (a mapping, judged against a declaration);
its `inherit` twin is `secrets-inherit-external`.

Workflows: `.github/workflows/ci.yml`.
