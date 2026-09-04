# fixture: secrets-inherit-external

`secrets: inherit` on a call to a reusable workflow in ANOTHER REPOSITORY --
`owner/repo/.github/workflows/x.yml@ref` rather than `./.github/workflows/x.yml`.

The reason this needs its own fixture, next to `secrets-inherit`: the caller
loop used to filter to local members BEFORE it judged `inherit`, so this call
was skipped entirely. That inverted the severity. A local `inherit` overshares
within one repository; this one hands the caller's entire secret set to code
maintained somewhere else, at a ref that can move under you.

No member workflow is checked in here, and that is the point -- the member is
external and unreadable from this tree, so the check cannot pair the call
against a declaration. `inherit` is rejected on the call site alone.

`secrets` must go red here. Its local twin is `secrets-inherit`; its green twin
is `secrets-typed-ok`, which names the secret at the call site.

Workflows: `.github/workflows/ci.yml`.
