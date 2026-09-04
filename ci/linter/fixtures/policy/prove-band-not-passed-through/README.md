# fixture: prove-band-not-passed-through

A `prove` job that declares a unique `TEST_BASE_PORT` and never passes it on.

Every check above this one is satisfied: the band is declared, it is distinct
from every sibling, its width does not overrun a neighbour. The job still binds
1984, because Test::Nginx reads `TEST_NGINX_PORT` and has never heard of
`TEST_BASE_PORT`. A declaration nothing consumes is decoration.

`check_ports()` had the equivalent guard for the runtime driver
(`--port "$TEST_BASE_PORT"`) but keyed it on `starts_runtime`, so the `prove`
path had no pass-through check at all: the change that made `prove` a
first-class binder for the declaration-required branch extended what must
declare a band without extending what must pass it through.

Ported from `labs/nginx-error-abuse-module` (raised by CodeRabbit on that
repo's PR #48) as the REF49 carry-back recorded in that module's TODO.md. The
skeleton had the declaration half already and this half not at all.

`ports` must go red here.

Workflow: `.github/workflows/runtime.yml`.
