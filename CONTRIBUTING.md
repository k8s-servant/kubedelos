# Contributing to kubedelos

Thanks for your interest! Bug reports, docs fixes and code are all welcome.

## Ground rules

- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues go through [private vulnerability reporting](https://github.com/k8s-servant/kubedelos/security/advisories/new)**, never public issues.
- **Cluster access is read-only.** Changes that let kubedelos modify cluster objects or
  read Secrets will not be accepted.
- Never paste real cluster data, kubeconfigs, tokens, registry credentials or internal
  hostnames into issues, PRs, test fixtures or examples.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pre-commit install      # ruff + gitleaks on every commit
.venv/bin/pytest                  # tests
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

### Dependencies

The container image installs its Python packages only from the hashed lock files in `requirements/`. When you add or
change a dependency in `pyproject.toml`, regenerate them with [uv](https://docs.astral.sh/uv/) and commit the result:

```bash
scripts/lock-image.sh
```

`tests/test_packaging.py` fails when the locks no longer satisfy `pyproject.toml`.

## Workflow

1. For anything bigger than a small fix, open an issue first so we can agree on the approach.
2. Fork, create a branch, and write a failing test before the code (one test file per module).
3. Keep PRs focused. Update docs alongside behavior changes.
4. **PR titles follow [Conventional Commits](https://www.conventionalcommits.org/)**
   (`feat: ...`, `fix(scanner): ...`, `docs: ...`), with a lowercase subject. PRs are
   squash-merged, and the title becomes the commit message that drives the changelog and
   version bumps. A breaking change uses `feat!:` or a `BREAKING CHANGE:` footer.
5. CI must be green: lint and tests.

## AI-assisted contributions

Using Claude Code or another assistant is fine. [`AGENTS.md`](AGENTS.md) holds the
project conventions those tools should follow (`CLAUDE.md` imports it). You remain
responsible for every line you submit.

Claude also reviews every non-draft PR from a branch in this repository. Maintainers can
mention `@claude` in an issue, a PR comment or a review to ask a question or have it fix
something and push a branch. It only runs when everyone in the thread is the owner, an
org member or a collaborator, and never on fork PRs, so outsider-written text never
reaches a model holding a write token.

## Releases

Maintainers merge the release PR that release-please keeps open. That tags the release
and publishes the package.

The chart is listed on [Artifact Hub](https://artifacthub.io/packages/helm/kubedelos/kubedelos), which reads each new chart version from GHCR, along with
the `artifacthub.io/*` annotations in `charts/kubedelos/Chart.yaml` and the chart's `README.md`. After the repository is
added on Artifact Hub, `scripts/artifacthub-metadata.sh REPOSITORY_ID` pushes the repository metadata once, which marks
it as a verified publisher.

`kubedelos mcp` is listed in the [MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.k8s-servant/kubedelos`. The registry reads `server.json` and checks the `mcp-name` comment in
`README.pypi.md`; release-please bumps the versions in `server.json`. After a release is on PyPI, an owner of the
k8s-servant org publishes it with `mcp-publisher login github --token <token with read:org>` and `mcp-publisher publish`
(`mcp-publisher login github` alone cannot publish to an org namespace yet).
