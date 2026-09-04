# fixture: secrets-inherit

A caller reaching a member with `secrets: inherit` instead of naming what the
member needs. The member here is correctly typed, so the only defect is at the
call site -- `inherit` hands that member the caller's ENTIRE secret set,
including every secret it has no business reading.

The reason this needs a fixture: `inherit` works. The pipeline is green, the
member gets its token, and the only symptom is a blast radius that silently
grows every time an unrelated secret is added to the repo. Nothing in
actionlint or zizmor objects to it.

`secrets` must go red here. Its green twin is `secrets-typed-ok`, the same
topology with the secret named explicitly at the call site.

Workflows: `.github/workflows/{ci,build-test}.yml`.
