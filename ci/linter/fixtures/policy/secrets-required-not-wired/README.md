# fixture: secrets-required-not-wired

The mirror image of `secrets-undeclared`: here the MEMBER declares
`GH_SUBMODULE_TOKEN` with `required: true` and the CALLER passes nothing.

The reason this needs a fixture: it is the direction the check missed on first
writing. Both halves look right in isolation again -- the member's declaration is
exactly the endorsed shape, and the caller is a plain `uses:` with no secrets
block, which is correct for every OTHER member in a repo like this one.

GitHub does refuse to start the call, so this fails loudly rather than silently.
That is the whole point of `required: true`. But it fails on the first run after
merge, and the caller/member pairing is checkable at review time instead.

`secrets` must go red here. Its green twin is `secrets-typed-ok`, the same member
with the caller actually wiring the secret.

Workflows: `.github/workflows/{ci,build-test}.yml`.
