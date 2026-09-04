# fixture: inline event syntax

`on: [pull_request]` and `on: pull_request` mean exactly what the indented
mapping form means. The reachability test used to be a regex for an INDENTED
MAPPING KEY, so both inline spellings walked past the runner-trust check with a
bare self-hosted `runs-on:`.

`.github/workflows/seq.yml`, `.github/workflows/scalar.yml` and
`.github/workflows/target.yml`: `runners` must report all three.
