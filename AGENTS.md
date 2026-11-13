# AGENTS.md

Guidance for AI coding assistants (Claude Code, Codex, Copilot, Cursor and others)
working in this repository. Human contributors: see [CONTRIBUTING.md](CONTRIBUTING.md).
`CLAUDE.md` only imports this file, so keep the guidance here.

## Project

kubedelos is a Kubernetes image vulnerability scanner with a local web UI and scheduled
reports. It lists the container images running in a cluster (read-only), scans them with
a pinned Trivy, and stores the findings in SQLite. There is one command, `kubedelos`;
the local UI will be `kubedelos ui` (Phase 2).

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'      # setup
.venv/bin/pytest                                                # tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .       # lint
.venv/bin/pre-commit run --all-files                            # ruff, gitleaks, hygiene hooks
.venv/bin/kubedelos --help                                      # CLI
```

## Conventions (must follow)

- **Clean rewrite.** This project is an independent implementation. Do not copy or
  paraphrase code from other private or internal projects, and never add internal
  company names, hostnames or registries.
- **Read-only cluster access.** No code path may change cluster objects or read Secrets.
- **Trivy is pinned** (v0.76.1) with a per-platform SHA-256 in `kubedelos/trivy/pins.py`.
  Never resolve "latest". Scan with `--scanners vuln` only.
- **Credentials never touch disk or logs.** Registry tokens are not written to SQLite
  or logged, not even in error messages.
- **Data paths** come from `platformdirs`, overridable with `KUBEDELOS_CACHE_DIR` and
  `KUBEDELOS_DATA_DIR`.
- **TDD:** write a failing test first; one test file per module.
- **Python 3.12+.** Dependencies use a lower bound at the current stable release and an
  upper bound at the next major (`>=X.Y,<X+1`).
- **Ruff:** line length 120. Keep `ruff check` and `ruff format --check` clean.
- **Comments:** every module starts with a docstring explaining what and why.
- **GitHub Actions:** pin every action to a full SHA with a `# vX.Y.Z` comment, set
  `permissions: {}` at the top and grant least privilege per job, use
  `persist-credentials: false`, and never use `aquasecurity/trivy-action`.
- **Public repository.** Use placeholders (`example.com`, `my-cluster`) in code, tests,
  docs and examples.
- **Git:** Conventional Commits with lowercase subjects, no co-author or attribution
  lines. Work on a branch and open a PR; never push to `main`.
- **Changelog:** after the first release, release-please writes `CHANGELOG.md`; until
  then it holds a hand-written `## Unreleased` section. Do not bump versions by hand.
