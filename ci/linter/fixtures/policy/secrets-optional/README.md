# fixture: secrets-optional

A member declaring `GH_SUBMODULE_TOKEN` with `required: false`. Distinct from
`secrets-untyped`: the `required:` key IS present, so a check that only asks
"was it typed at all" passes this.

The reason this needs its OWN fixture: it is the mutant that survived.
Disarming the `required is not True` branch left `secrets-untyped` red anyway,
because that fixture trips the missing-key branch instead -- so the value test
had no control of its own and could have been deleted silently.

`required: false` is not a weaker version of the rule, it is the absence of it:
GitHub starts the call with the secret unset, the member reads an empty string,
and the failure surfaces downstream of the cause.

`secrets` must go red here. Its green twin is `secrets-typed-ok`.

Workflow: `.github/workflows/build-test.yml`.
