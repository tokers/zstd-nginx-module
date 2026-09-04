# fixture: provenance-mixed-codeql-unzip

The local CodeQL database exception applies only to its own extraction. It
must not exempt an unverified ZIP extraction earlier in the same step.

Workflow: `.github/workflows/ci.yml`.
