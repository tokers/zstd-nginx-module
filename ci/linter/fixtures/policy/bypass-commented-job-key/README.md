# fixture: a trailing comment on a job key

`_jobs()` split on `^  (\w[\w-]*):\s*$`, so `runtime:  # note` matched nothing
and the whole file yielded ZERO jobs. `ports` then reported "no runtime-bearing
jobs" -- clean, exit 0 -- for a workflow that starts the runtime driver with no
port band. That is the vacuous-gate shape these linters exist to prevent,
occurring inside a linter.

Workflow: `.github/workflows/runtime.yml`.
