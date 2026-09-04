# fixture: clean

Positive control for ci/linter/selftest.sh. Every policy check must report
clean against this tree, so that a RED result on a sibling fixture is
attributable to the bypass that fixture encodes and not to the fixture shape.

Workflow: `.github/workflows/ci.yml`.
