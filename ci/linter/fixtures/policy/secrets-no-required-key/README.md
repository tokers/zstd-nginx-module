# fixture: secrets-no-required-key

A member declaring `GH_SUBMODULE_TOKEN` as a real mapping -- with a
`description:` -- but no `required:` key. This is the shape a careful author
produces when documenting a secret without typing it.

The reason this needs its OWN fixture, distinct from both `secrets-untyped` and
`secrets-optional`: it is the second mutant that survived. `secrets-untyped`
spells the declaration `GH_SUBMODULE_TOKEN:` with nothing under it, which YAML
parses to null -- and null `is not True`, so the VALUE branch catches it even
with the missing-key branch deleted. Only a spec that is a genuine mapping
lacking the key can distinguish the two.

`secrets` must go red here. Its green twin is `secrets-typed-ok`.

Workflow: `.github/workflows/build-test.yml`.
