# fixture: provenance-verify-helper-after-extract

The same-step ordering bypass: the job downloads and extracts an nginx archive,
then invokes the shared verification helper after extraction. Merely naming the
reviewed helper must not anchor commands that already consumed untrusted bytes.

Workflow: `.github/workflows/ci.yml`.
