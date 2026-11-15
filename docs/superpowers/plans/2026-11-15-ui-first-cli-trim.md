# UI-first: trim the CLI

**Goal:** Remove the CI-oriented `kubedelos scan` command and its output formats, so that the UI (and, in Phase 3, the
in-cluster schedule) is the only way to scan.

**Why:** On 2026-11-15 the product focus was set to the UI and to scheduled in-cluster scans with reports. CI gating is
a non-goal, because plain Trivy already does it well. The design spec records this under "Product focus".

**Approach:** delete, don't deprecate. No release exists yet, so nothing depends on the command, and the
`## Unreleased` changelog is edited to describe what ships.

## Global constraints

- Everything in AGENTS.md still applies: read-only cluster access, Trivy pinned with `--scanners vuln`, no credentials
  on disk or in logs, one test file per module, Ruff 120, and a docstring on every module.
- Keep the CLI commands `ui`, `trivy install`, `registry test` and `version`. `registry test` moves into the UI in a
  later PR, then goes.
- The scan service, cache, runlock and UI behaviour stay unchanged.

## Tasks

1. **CLI.** Remove `scan`, together with the code only it uses:
   - in `kubedelos/cli.py`: `OutputFormat`, `FailOn`, `_parse_severities`, `_update_bar`, and the Rich progress bar;
   - `kubedelos/output.py`, except `short_image`, which moves to `kubedelos/web/pages.py`;
   - `Repo.run_findings` and `Repo.run_errors`.

   Tests: delete `tests/test_cli_scan.py`, `tests/test_output.py` and the scan cases in `tests/test_cli.py`. Move the
   `short_image` test to `tests/web/test_pages.py`, and switch the store and service tests that used `run_findings` to
   direct queries. A new test checks that `kubedelos --help` no longer lists `scan`. Drop the `rich` dependency if
   nothing else imports it.
2. **e2e.** `scripts/e2e-kind.sh` scans by calling `run_scan` directly, through `python -I -c`, instead of the CLI.
   `tests/e2e/test_kind_scan.py` asserts on the database: a Critical nginx finding owned by `web@example.com`, and
   busybox scanned `ok`.
3. **Copy and docs:**
   - The empty dashboard and findings pages point to the Scans page.
   - The README and README.pypi lead with `kubedelos ui`. The scan, exit-code and CI sections go, and
     configuration is described through `KUBEDELOS_*` variables.
   - The bug report template no longer refers to `kubedelos scan`.
   - Docstrings stop mentioning `--fail-on` and `kubedelos scan` where those no longer apply.
   - The CHANGELOG `Unreleased` section is edited, and the design spec gets a "Product focus" section.

## Verification

- `pytest`: no scan or output-format tests remain, and the coverage floor of 80% still holds.
- Ruff and pre-commit pass.
- `kubedelos --help` lists `version`, `ui`, `trivy` and `registry`.
- On kind-lab, a scan started from the UI still works end to end.
