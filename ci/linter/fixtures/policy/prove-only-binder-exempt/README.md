# fixture: prove-only-binder-exempt

`check_ports()`'s declaration-required branch — the one its own comment calls
"THE CHECK THAT MATTERS MOST" — keyed on `starts_runtime`
(`RUNTIME_DRIVER in body`, i.e. `ci/tools/test_runtime.py`) rather than on
`BINDERS`/`BINDER_RE`. A job whose only binder is `prove` was therefore exempt
from the "declare `TEST_BASE_PORT`" requirement, even though `prove` is already
a `BINDERS` member and `_order_finding()` already treats it as one thing that
binds the band.

The exemption is invisible from every other angle. Such a job declares no band,
so the uniqueness check has nothing to collide; it silently takes Test::Nginx's
hardcoded default and collides with any other runtime job pinned to the same
runner. Found downstream in `nginx-api-abuse-module` as a failed negative
control: deleting a prove-only job's band left `ports` GREEN, reporting "all
with distinct port bands".

`ports` must go red here.

Workflow: `.github/workflows/runtime.yml` — a job that runs `prove -v ci/t/`
and declares no `TEST_BASE_PORT`.
