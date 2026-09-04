# fixture: verify-after-bind

Encodes the defect this repo shipped until 2026-08-02: `build-test.yml` ran
`ci/tools/max-port.sh` *between* `prove` and the runtime suite. Every existing
check reads that job as correct — it declares a distinct band, it passes the
band to the driver, and the verifier is present — so nothing went red while the
first binder ran unguarded and the one failure the verifier exists to name
arrived inside `prove` as an unattributed bind error or timeout.

The verifier is a property of a POSITION, not of a job. `ports` must go red
here.

Workflow: `.github/workflows/ci.yml`.
