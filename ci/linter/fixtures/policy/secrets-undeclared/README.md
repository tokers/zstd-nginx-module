# fixture: secrets-undeclared

A caller passing `GH_SUBMODULE_TOKEN` to a member whose `workflow_call: {}`
declares no secrets at all. This is the shape every member in the reference
repo has today, which is correct only while no caller passes anything.

The reason this needs a fixture: the secret is dropped at the call boundary in
silence. The caller looks right -- the secret is named, wired from
`${{ secrets.* }}`, visible in review -- and the member simply never receives
it. Both halves read as correct in isolation; only the pairing is wrong.

`secrets` must go red here. Its green twin is `secrets-typed-ok`, the same call
against a member that declares what it is being passed.

Workflows: `.github/workflows/{ci,build-test}.yml`.
