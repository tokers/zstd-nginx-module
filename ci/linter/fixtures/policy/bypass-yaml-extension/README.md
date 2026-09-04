# fixture: a workflow with the .yaml extension

GitHub reads `*.yml` and `*.yaml` alike; `workflows()` used to glob `*.yml`
only, so this self-hosted, PR-triggered, undocumented workflow was invisible to
every policy check. `runners` and `docs` must both go red here.

The documented workflow list deliberately mentions no file: `docs` must report
the undocumented gate.
