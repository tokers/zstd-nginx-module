# fixture: provenance-exec-downloaded-binary

No archive is involved: a STANDALONE executable is downloaded, marked
executable, and run directly. The tar/unzip patterns miss this completely,
so the job passed while running unverified attacker-controllable code on the
runner -- the same privilege boundary the archive cases exist to guard, one
step shorter.

`provenance` must go red here.

Workflow: `.github/workflows/ci.yml`.
