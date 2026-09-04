# ci/linter — local lint gate

Mirrors the cheap half of remote CI so a push does not burn a round-trip on a
finding shellcheck could have named in two seconds. Every script is standalone;
`run-all.sh` runs them all and `.githooks/pre-commit` runs `run-all.sh --staged`.

## Layout

| Script | Covers | Gate |
|---|---|---|
| `lint-c.sh` | `src/*.[ch]` | flawfinder ≥4, cppcheck (warning/performance/portability), semgrep ≥WARNING (`p/c`, `p/security-audit`) |
| `lint-nginx.sh` | `src/*.[ch]` | nginx conventions: libc alloc/str/num/io instead of `ngx_*`, hard tabs, >80 columns, trailing whitespace, `ngx_config.h` include order |
| `lint-sh.sh` | `*.sh`, `*.bash`, `.githooks/*` | shellcheck `-S warning` |
| `lint-python.sh` | `*.py` | `ruff check` + `ruff format --check` |
| `lint-perl.sh` | `ci/t/*.t`, `*.pl`, `*.pm` | `perl -c` + perlcritic severity ≥4 |
| `lint-yaml.sh` | `*.yml`, `*.yaml` | yamllint (errors block, warnings visible), actionlint + zizmor (`--persona=pedantic`) on `.github/workflows/` |
| `lint-ci-runners.sh` | `.github/workflows/` | fork PRs never select the self-hosted pool; `pull_request_target` forbidden; every `runs-on` names labels that exist, including on workflows no pull request can reach |
| `lint-ci-ports.sh` | `.github/workflows/` | every port-binding job declares a distinct `TEST_BASE_PORT` band, binds it, and verifies it above the FIRST binding step |
| `lint-ci-cadence.sh` | `.github/workflows/` | a `workflow_call` member carries no `push:`/`pull_request:` of its own, so it runs once per change rather than twice on two uncancellable concurrency keys (`schedule:` allowed) |
| `lint-ci-secrets.sh` | `.github/workflows/` | a `workflow_call` member declares the secrets it needs with `required: true`; callers wire them by name and never use `secrets: inherit` |
| `lint-docs-drift.sh` | `.github/workflows/`, `README.md` | every workflow documented, every documented workflow exists |
| `lint-spelling.sh` | all tracked files | codespell over prose, comments and log strings; vendored trees excluded via `lib.sh` |
| `run-all.sh` | all of the above | runs every check, reports once |
| `install-linters.sh` | — | apt-get → pipx → cpan → upstream binary |
| `lib.sh` | — | sourced helpers (file selection, missing-tool failure) |
| `workflow_policy.py` | — | the repo-policy checks the `ci-*`/`docs-drift` wrappers call (`runners`, `ports`, `docs`, `cadence`, `secrets`) |
| `selftest.sh` | — | negative controls for the gate itself; run before the linters in `lint.yml`. Includes the set-equality control: every checker is named in `lint.yml`'s `LINT_ONLY` |
| `fixtures/policy/` | — | trees the policy checks must go RED on — the known bypasses, the runner-label and step-ordering cases, and the four ways a `secrets:` declaration goes wrong; `clean/` and the `-ok` trees must stay GREEN |

Rule config lives at the repo root so editors and these scripts agree:
`.yamllint` (workflow-shaped YAML), `.perlcriticrc` (Test::Nginx-shaped Perl).
Both carry the reason for every relaxation; read them before adding another.

Thresholds deliberately match `.github/workflows/security-scanners.yml`. Move
one there and move it here **in the same commit**, or local-green stops
predicting remote-green — the only reason this directory exists.

The `ci-*`, `docs-drift` and `sync-stamp` rows are **repo-policy** checks, not
general linters, and that is why they are here rather than left to actionlint or
zizmor. Those two read a workflow against general knowledge: syntax, and a
catalogue of known attack shapes. These encode facts only this repo knows: which
self-hosted labels exist, that the runners are persistent and shared with the
Debian package builds, which port band each job owns, that `ci.yml` is the single
orchestrator, that a member's secret surface is declared at the member, which
files an adopter copies, and which file documents the pipeline. Each one goes red when a
NEW workflow is added without a property every existing workflow happens to have
— the case where copying an existing file is the only thing between the repo and
a regression, and nothing enforces the copy.

`clang-tidy` is **CI-only**: it needs `ngx_auto_config.h`, which exists only in
a configured nginx tree. A hook cannot assume one, and a check that skips
itself when the tree is missing is a vacuous gate.

## 1. Install the linters

```sh
ci/linter/install-linters.sh          # install what is missing
ci/linter/install-linters.sh --check  # report only
```

Preference order, and why each tool lands where it does:

### apt-get (preferred — distro-managed, no PEP 668 fight)

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    shellcheck cppcheck flawfinder yamllint clang-tidy \
    libperl-critic-perl perl pipx cpanminus
```

### pip / pipx (Python tools Debian does not carry at the needed version)

Use `pipx`, not `pip3`: Debian 12+ marks the system interpreter
externally-managed, so a bare `pip3 install` fails and
`--break-system-packages` is a worse answer than a venv per tool.

```sh
pipx install 'ruff==0.16.1'         # pinned to the CI version on purpose
pipx install 'semgrep==1.173.0'     # pinned to the CI version on purpose
```

`ruff` and `semgrep` are pinned because an unpinned upgrade changes findings
under you and local stops matching CI. Bump each here and in its CI consumer
together -- `ruff` in `install-linters.sh`, `semgrep` in
`security-scanners.yml` too.

### cpan (Perl modules apt does not carry on every target release)

```sh
sudo cpanm --notest Test::Nginx::Socket   # also what makes `perl -c` work on ci/t/*.t
sudo cpanm --notest Perl::Critic          # only if libperl-critic-perl was unavailable
```

`--notest`: Test::Nginx's own suite wants a live nginx and a free port, which
an install step has no business demanding.

```sh
pipx install zizmor                 # GitHub Actions security audit
```

`zizmor` is deliberately **not** pinned, unlike ruff and semgrep: its rule set
is the whole point, and a frozen security scanner stops finding what it was
added for. A new rule going red is a finding to triage, not drift to suppress.

### upstream binary (no apt/pip/cpan source)

```sh
ver=1.7.7
sha=023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757
curl -fsSL -o actionlint.tgz \
  "https://github.com/rhysd/actionlint/releases/download/v${ver}/actionlint_${ver}_linux_amd64.tar.gz"
echo "$sha  actionlint.tgz" | sha256sum -c -   # must pass before the next line
tar -xzf actionlint.tgz actionlint && sudo install -m0755 actionlint /usr/local/bin/
```

Do not pipe the tarball straight into `tar`: that installs whatever the network
returned. The digest is from the release's `actionlint_${ver}_checksums.txt` and
is pinned beside the version in `install-linters.sh` too — bump both together.

Make sure `~/.local/bin` is on `PATH` for the pipx-installed tools.

## 2. Enable the pre-commit hook

The hook is tracked at `.githooks/pre-commit` so a change to the gate arrives
as a reviewable diff. Git does not use it until you point `core.hooksPath` at
the directory — once per clone:

```sh
git config core.hooksPath .githooks
```

Verify it is live:

```sh
git config --get core.hooksPath     # -> .githooks
```

Bypass in an emergency with `git commit --no-verify`.

**This replaces the `pre-commit` framework hook.** `core.hooksPath` makes git
ignore `.git/hooks/` entirely, including the hook `pre-commit install` writes
there. The repo's `.pre-commit-config.yaml` still exists and covers overlapping
ground (whitespace fixers, private-key detection, gitleaks, flawfinder,
semgrep, cppcheck, ruff, shellcheck, actionlint). Pick one:

- `git config core.hooksPath .githooks` — this directory: also covers Perl,
  yamllint and the nginx conventions, no Python framework needed.
- `pipx install pre-commit && pre-commit install` — the framework: also runs
  the whitespace/EOF fixers, `detect-private-key` and `gitleaks` over the
  staged patch, but not `lint-nginx.sh`, `lint-perl.sh` or `lint-yaml.sh`'s
  yamllint/zizmor passes. Then leave `core.hooksPath` unset.

Running both means running flawfinder, semgrep, cppcheck and ruff twice per
commit.

## 3. Use it

```sh
ci/linter/run-all.sh                 # every tracked file
ci/linter/run-all.sh --staged        # what the hook runs
ci/linter/run-all.sh src/foo.c       # named files
LINT_ONLY="c nginx" ci/linter/run-all.sh
LINT_SKIP_SEMGREP=1 ci/linter/run-all.sh   # loud opt-out of the slowest pass
LINT_JOBS=1 ci/linter/run-all.sh           # serial, for bisecting a hang
ci/linter/run-all.sh --list
```

Exit codes: `0` clean, `1` findings, `2` a linter is missing.

### Speed, and why it is shaped this way

Measured 2026-07-31 on the self-hosted build host (i9-14900HX, 32 threads)
with **no CI job
running** — see the caveat below before comparing against your own numbers:

| | before | after |
|---|---|---|
| full tree | 3.8s | **1.45s** |
| one C file | 2.9s | **1.31s** |
| full tree, `LINT_JOBS=1` | 3.2s | 2.57s |

Re-measure on an idle box or not at all. This host also runs six self-hosted CI
runner slots, and at load average ~50 the same full-tree run took 2.2s to 12.4s
across six back-to-back attempts — the run-to-run spread is wider than the
entire improvement, so a busy-box A/B measures the neighbours, not the change.
Check `/proc/loadavg` first.

Two changes, only one of which is really about speed:

- **`semgrep --metrics=off`.** The end-of-scan POST to semgrep.dev was 2.76s of
  a 2.76s scan; without it the same scan is 1.27s. More than half the hook's
  wall clock was telemetry.
- **`semgrep --jobs=1`.** A *correctness* fix. semgrep-core defaults to one
  OCaml domain per core and each domain opens its own io_uring ring against
  this host's 8 MB `RLIMIT_MEMLOCK`, which is shared with the self-hosted CI
  runners. When the runners are busy it exhausts and semgrep-core aborts with
  `Unix_error: Cannot allocate memory io_uring_queue_init`, exit 2 — a red
  commit gate caused by neighbouring load, not by the diff. Reproduced 3/3 on a
  busy box, 0/3 on an idle one. `src/` is three files, so nothing was gained by
  the parallelism in the first place. `security-scanners.yml` carries the same
  two flags; they run on the same host and must stay in sync.
- **`run-all.sh` fans the checkers out** (`LINT_JOBS`, default one slot per
  checker). Each checker's output is buffered and replayed whole in glob order,
  never streamed: findings carry a `file:line` but not a checker name, so
  interleaved output is unattributable. Fixed order also keeps two runs of the
  same dirty tree byte-comparable.

The floor is now semgrep's own startup. If this creeps back over ~2s, scope
semgrep — do not drop a checker.

Suppress one justified `lint-nginx.sh` finding with a trailing
`/* NOLINT-nginx */` on that line. Whole-rule suppression is deliberately not
supported: the exception belongs next to the code that needs it, where review
can see the reason.

## Verify before trusting

A green gate proves nothing until it has been seen red. Every probe below was
run against this tree and observed failing; re-run them after changing a
threshold.

```sh
# shell: SC2164 + SC2115 -> exit 1
printf '#!/bin/bash\ncd /tmp/x\nrm -rf "${B}/"*\n' > _p.sh
LINT_ONLY=sh ci/linter/run-all.sh _p.sh ; rm _p.sh

# C + nginx conventions: malloc/strcpy -> exit 1 from both lint-c and lint-nginx
printf '#include <ngx_core.h>\nvoid f(void){char*p=malloc(4);strcpy(p,"ab");}\n' > src/_probe.c
LINT_ONLY="c nginx" ci/linter/run-all.sh src/_probe.c ; rm src/_probe.c

# python: unused import -> exit 1
printf 'import os\nx=1\n' > _p.py
LINT_ONLY=python ci/linter/run-all.sh _p.py ; rm _p.py

# perl: string eval + interpolated system() -> exit 1
printf 'my $x = 1;\nsystem("ls $x");\neval "1";\n' > _p.pl
LINT_ONLY=perl ci/linter/run-all.sh _p.pl ; rm _p.pl

# yaml: unterminated flow sequence -> exit 1
printf 'a: [1,\n' > _p.yml
LINT_ONLY=yaml ci/linter/run-all.sh _p.yml ; rm _p.yml

# workflow security: zizmor -> exit 1 on template-injection, artipacked,
# unpinned-uses and excessive-permissions, all from these seven lines
cat > .github/workflows/_probe.yml <<'EOF'
name: probe
on: [pull_request]
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
EOF
LINT_ONLY=yaml ci/linter/run-all.sh .github/workflows/_probe.yml
rm .github/workflows/_probe.yml

# CI runner policy: a self-hosted runner on a PR-reachable workflow -> exit 1
cat > .github/workflows/_probe.yml <<'EOF'
name: probe
on:
  pull_request:
jobs:
  p:
    runs-on: [self-hosted, linux]
    steps:
      - run: python3 ci/tools/test_runtime.py --nginx x --module y
EOF
LINT_ONLY=ci-runners  ci/linter/run-all.sh    # -> runs-on is not a trust split
LINT_ONLY=ci-ports    ci/linter/run-all.sh    # -> starts the driver, no band
LINT_ONLY=docs-drift  ci/linter/run-all.sh    # -> workflow not in README.md
rm .github/workflows/_probe.yml

# Runner LABELS, on a workflow no pull request can reach. Nothing else reads
# these: actionlint validates labels for a literal `runs-on` only, and every
# self-hosted selector here is a fromJSON(...) ternary it stays silent on.
cat > .github/workflows/_probe.yml <<'EOF'
name: probe
on:
  schedule:
    - cron: "0 4 * * 1"
jobs:
  p:
    runs-on: ${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || fromJSON('["self-hosted","buidler02","lxc"]') }}
    steps:
      - run: echo probe
EOF
LINT_ONLY=ci-runners  ci/linter/run-all.sh    # -> not an approved selector (label typo)
rm .github/workflows/_probe.yml

# a secret wired at the caller that the member never declared -- both halves
# read as correct on their own; the secret is dropped at the call boundary
LINT_ONLY=ci-secrets ci/linter/run-all.sh    # (see fixtures/policy/secrets-*)

# an unstamped file in the shared set. A NEW probe rather than an edit to a
# tracked workflow: the cleanup for that is `git checkout <file>`, which also
# discards any uncommitted work you had in it.
cat > .github/workflows/_probe.yml <<'EOF'
name: probe
on:
  workflow_dispatch:
jobs:
  p:
    runs-on: ubuntu-latest
    steps:
      - run: echo probe
EOF
LINT_ONLY=sync-stamp ci/linter/run-all.sh    # -> MISSING stamp
rm .github/workflows/_probe.yml

# docs drift, the other direction: a README reference to a workflow that is gone
printf '\nSee .github/workflows/nosuch.yml\n' >> README.md
LINT_ONLY=docs-drift ci/linter/run-all.sh ; git checkout README.md

# a citation naming a step ci/PROMPT.md does not define -- what a renumber or a
# deleted step leaves behind, and what nothing else in the tree can see
printf '\nSee step 99 for details.\n' >> README.md
LINT_ONLY=prompt-steps ci/linter/run-all.sh ; git checkout README.md

# the other direction, a hole in the sequence itself. selftest.sh covers this
# against a generated tree, so no edit to the real 2100-line spec is needed:
#   ci/linter/selftest.sh 2>&1 | grep prompt-steps

# missing tool -> exit 2, never a silent skip
printf 'x = 1\n' > _p.py
PATH="$(echo "$PATH" | tr : '\n' | grep -v "$HOME/.local/bin" | paste -sd:)" \
    LINT_ONLY=python ci/linter/run-all.sh _p.py ; rm _p.py

# the hook itself blocks the commit
printf '#!/bin/bash\ncd /tmp/x\n' > _bad.sh && git add _bad.sh
git commit -m probe        # -> blocked
git reset -q HEAD _bad.sh && rm _bad.sh
```

Note SC2086 is INFO and correctly does **not** trip `lint-sh.sh`; probe with a
warning-severity finding or you will misread the gate.

### Workflow security (zizmor)

`actionlint` reads a workflow as syntax; `zizmor` reads it as an attack
surface — template injection into `run:`, `pull_request_target`, credentials
persisted by `actions/checkout`, actions pinned to a mutable tag, over-broad
`permissions:`. On a repo with **self-hosted runners** that class of mistake is
arbitrary code execution on the build host, which is why it is a gate and not
advice.

Run at `--persona=pedantic`: the default persona already passes on this tree,
so gating on it could never go red. Pedantic is what caught the `matrix.*`
interpolations in `ci-deep.yml` (now passed through `env:`) and the
undocumented CodeQL permissions.

`--offline`, so a commit hook never needs a token. The online audits only add
repo-settings context; that belongs in a periodic review.

Inapplicable finding → `# zizmor: ignore[rule]` on the line, with the reason.
Never a blanket disable in a `zizmor.yml`.

## In CI

`.github/workflows/lint.yml` runs `install-linters.sh` then
`LINT_ONLY="nginx sh python perl yaml spelling ci-runners ci-ports ci-cadence
ci-secrets sync-stamp docs-drift" run-all.sh` — the same entry point as the
hook, so a clone that never enabled `core.hooksPath` still cannot land a
regression.

That allowlist is narrower than the glob `run-all.sh` uses, so a checker added
to `ci/linter/` runs locally and in the hook while being **absent from every
PR** — a gate missing from the one path where it is load-bearing. `selftest.sh`
now cross-checks the two ("every checker is named in lint.yml LINT_ONLY") and
goes red on the gap; `c` is the one deliberate exclusion, for the reason below.
Before that control existed, `ci-cadence` shipped and had never run remotely.
A derived module's list will legitimately differ from this one.

`lint.yml` is wired into the `ci.yml` orchestrator and runs on `ubuntu-latest`,
taking no self-hosted slot.

The `c` checker is left out there because `security-scanners.yml` already runs
flawfinder/clang-tidy/semgrep over `src/` at the same thresholds. That is also
why `lint-c.sh` must be edited in the same commit as that workflow.

## Extending

- New repo-policy check: a subcommand in `workflow_policy.py` plus a thin
  `lint-<name>.sh` wrapper. Keep the wrapper's `lint_files` pattern as the
  RELEVANCE test only — every one of these checks compares whole SETS, so a
  narrowed file list would let a deletion through whenever the counterpart file
  was the only one staged.
  **Then add a fixture under `fixtures/policy/` and a `policy_` line in
  `selftest.sh`.** A policy check whose red path is never exercised is
  indistinguishable from one that cannot go red — all three of these shipped
  bypassable by valid YAML (a `.yaml` extension, an inline `on: [pull_request]`,
  a comment after a job key) and every one of them reported clean while doing it.
  Point a check at a fixture tree with `WORKFLOW_POLICY_ROOT=<dir>`.
- **Parse workflows with PyYAML, never with a regex over the file text.** The
  three checks here were originally regex-based, and the file argued in a
  docstring that a YAML parse would add a dependency that might be missing.
  Both halves were wrong: yamllint already makes PyYAML a hard dependency of
  the same gate, and every regex was walked past by valid YAML that GitHub
  reads exactly as the shape the regex expected. `workflow_policy.py` now exits
  2 when PyYAML is absent rather than degrading.
- New file type: drop a `ci/linter/lint-<name>.sh` in place — `run-all.sh`
  picks it up by glob. Keep "no files of this kind" exiting 0, and fail with
  exit 2 (via `need`) when the tool is absent.
- New nginx convention: one more `rule <name> <ere> <message>` call in
  `lint-nginx.sh`.
- New dependency: add it to `install-linters.sh` **and** to the apt/pip/cpan
  lists above, so a fresh clone is one command from armed.

## Coverage table — file type → linter → rule profile

Derived at skeleton-adoption step 37 (2026-08-22). Every tracked file type is
listed, with the checker that reaches it and the profile it is gated at. A type
with no checker carries the reason it needs none — an unexplained blank is a
gap, not a decision.

| Tracked type | Count | Checker(s) | Rule profile | Gated where |
|---|---|---|---|---|
| `src/*.c`, `src/*.h` | 4 | `lint-c`, `lint-nginx`, ast-grep | flawfinder ≥4 · cppcheck warning/perf/portability · semgrep ≥WARNING (`p/c`,`p/security-audit`) · nginx conventions · 11 own + vendored structural rules | `security-scanners.yml` (CI) + pre-commit; **not** `lint.yml` — see § the `c` exclusion |
| `ci/**/*.[ch]` | 9 | flawfinder, cppcheck, semgrep, ast-grep | same C profiles as `src/`, minus the nginx-convention pass (pool discipline does not apply to harness code) | pre-commit + `lint.yml` (ast-grep) |
| `*.sh`, `.githooks/*` | 32 | `lint-sh` | shellcheck `-S warning` | `lint.yml` + pre-commit |
| `*.py` | 17 | `lint-python` | `ruff check` + `ruff format --check` | `lint.yml` + pre-commit |
| `*.t`, `*.pl`, `*.pm` | 4 | `lint-perl` | `perl -c` + perlcritic ≥4 | `lint.yml` + pre-commit |
| `.github/workflows/*.yml` | 11 | `lint-yaml`, `lint-ci-{runners,ports,cadence,secrets}`, `lint-docs-drift` | yamllint · actionlint · zizmor `--persona=pedantic` · 5 repo policy checks | `lint.yml` + pre-commit |
| other `*.yml`, `*.yaml` | 65 | `lint-yaml` | yamllint only (actionlint/zizmor are workflow-scoped) | `lint.yml` + pre-commit |
| `*.md` | 30 | `lint-spelling`; `README.md` also `lint-docs-drift` | codespell · workflow/README set-equality | `lint.yml` + pre-commit |
| all tracked prose/comments | — | `lint-spelling` | codespell, vendored trees excluded in `lib.sh` | `lint.yml` + pre-commit |
| `*.key`, `*.zst`, `*.patch`, `*.dict`, `*.suppress` | 11 | none | binary/fixture/generated data with no syntax a linter can assert; `*.key` are test-only material | — |

### Justified exclusions

- **The `c` checker is absent from `lint.yml`'s `LINT_ONLY`** — flawfinder and
  semgrep already run over `src/` in `security-scanners.yml` at the *same*
  thresholds `lint-c.sh` mirrors. Running them twice per PR buys queue time,
  not coverage. `lint-c.sh` remains the local half of that mirror.
- **clang-tidy is CI-only.** It needs `ngx_auto_config.h`, i.e. a configured
  nginx tree, which a local hook cannot assume. A checker that skips itself when
  the tree is missing is a vacuous gate, so it lives only in
  `security-scanners.yml`, where the tree is built first.

### Gaps found at step 37 — both closed

1. **Three C files were reached by no checker at all.**
   `ci/fuzz/fuzz_accept_encoding.c`, `ci/fuzz/ngx_shim.h` and
   `ci/tests/unit/test_accept_encoding.c` fell outside both the linter
   selectors (`^src/.*\.[ch]$`) and the pre-commit hook globs, which stopped at
   `ci/tools/`. The fuzz harness is C that parses attacker-shaped input, so
   this was the gap worth closing first. The four C hooks now select
   `^(src|ci)/.*\.[ch]$`; all four pass on the newly covered files.
2. **ast-grep and gitleaks were hook-only.** Both run from
   `.pre-commit-config.yaml`, and no workflow runs pre-commit, so a clone that
   never set `core.hooksPath` bypassed both — exactly the failure mode
   `lint.yml`'s header says the remote run exists to prevent. `lint.yml` now
   runs each directly, as its own step, invoked the way the hook invokes it.

   `run-all.sh` still does not reach them: they are not `ci/linter/lint-*.sh`,
   and the selftest's set-equality control only covers checkers that are. If
   either step is removed from `lint.yml`, nothing will notice.

### Verifying these two gates

Both were confirmed able to fail, not just to run:

- **ast-grep** — a planted `strcpy()` in `ci/tests/unit/` produced
  `error[c-unbounded-string-copy]` and the pipeline exited 123.
- **gitleaks** — use a NON-EXAMPLE secret. AWS's own `AKIAIOSFODNN7EXAMPLE` is
  allowlisted by the default ruleset and reports "no leaks found", which reads
  exactly like a broken gate. The probe recipe above the hook in
  `.pre-commit-config.yaml` produces `leaks found: 1` and exit 1. Note that
  piping the run into `tail` masks that exit status — check it unpiped.
