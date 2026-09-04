# ci/linter/fixtures/ — trees the linters must go RED on

**Nothing here is a workflow this repo runs. Do not "fix" these files.**

Every file under `policy/` is deliberately wrong in one specific way. They are
the negative controls for `ci/linter/workflow_policy.py`, driven by
`ci/linter/selftest.sh`, which points a check at one of these trees with
`WORKFLOW_POLICY_ROOT=<dir>` and asserts the exit status.

`policy/clean/` is the positive control and must stay clean. Every sibling
encodes a bypass that valid YAML used to walk straight through:

| Fixture | Encodes |
|---|---|
| `clean/` | a plain, correct workflow — all three checks green |
| `bypass-yaml-extension/` | `.yaml`, invisible while `workflows()` globbed `*.yml` |
| `bypass-inline-events/` | `on: [pull_request]`, `on: pull_request`, inline `pull_request_target` |
| `bypass-commented-job-key/` | `runtime:  # comment`, which emptied the job list |

## Why a scanner will flag these, and why that is correct

These workflows select self-hosted runners for fork pull requests, use
`pull_request_target`, and declare no `permissions:`. That is the point — a
fixture that passed a security scanner would not be testing anything.

The repo's own gate does not see them: `ci/linter/lint-yaml.sh` scopes
actionlint and zizmor to paths matching `^\.github/workflows/`, which these are
not (they live under `ci/linter/fixtures/.../.github/workflows/`). yamllint does
read them, and they are valid YAML, so it passes.

If a future scanner is added that walks the whole tree, **exclude this
directory rather than editing the fixtures.** Making these files pass a security
scanner disarms every control they provide, and the resulting green is exactly
the vacuous gate the whole `selftest.sh` layer exists to detect.

## Adding one

Create `policy/<bypass-name>/` with its own `.github/workflows/` and a `README.md`
saying which bypass it encodes and which subcommand must go red. Add a `policy_`
line to `ci/linter/selftest.sh`. Then verify it in BOTH directions: red on the
current parser, and green once you revert the fix it guards — a control that has
never been observed failing is a control you have not tested.
