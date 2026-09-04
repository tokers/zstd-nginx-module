# fixture: secrets-untyped

A `workflow_call` member declaring `GH_SUBMODULE_TOKEN:` with no `required:`
key. The secret IS declared, so the caller-side check has nothing to say and
the name shows up where a reader expects it.

The reason this needs a fixture: an untyped (or `required: false`) secret
restores exactly the failure the declaration was supposed to remove. GitHub
will start the call with the secret absent, the member sees an empty string,
and it dies downstream of the cause -- a checkout that 404s, a curl that 401s.
`required: true` is what makes it refuse to start instead.

`secrets` must go red here. Its green twin is `secrets-typed-ok`, the same
declaration with `required: true`.

Workflow: `.github/workflows/build-test.yml`.
