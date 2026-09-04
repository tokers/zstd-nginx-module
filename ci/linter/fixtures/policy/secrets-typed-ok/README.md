# fixture: secrets-typed-ok

The endorsed shape, and the green half of three pairs: a member declaring
`GH_SUBMODULE_TOKEN` with `required: true`, and a caller wiring that one secret
by name.

Without this fixture, the reds in `secrets-inherit`, `secrets-untyped` and
`secrets-undeclared` would be equally consistent with "any workflow mentioning
a secret is flagged" -- which is the opposite of the rule. The rule is that
secrets must be declared at the member and wired explicitly, so the correctly
declared and wired case has to be provably green.

Workflows: `.github/workflows/{ci,build-test}.yml`.
