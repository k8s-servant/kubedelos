# kubedelos Phase 0 + 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A secure, CI-gated public repo for `kubedelos`, plus a working `kubedelos scan` CLI. The CLI inventories the images in the current kube-context, scans them with a pinned, verified Trivy running in server mode, stores the results in SQLite, and prints them as table, JSON, CSV or SARIF.

**Architecture:** A Python package `kubedelos` with focused modules:
- `kube/` takes the inventory from the Kubernetes API.
- `trivy/` manages the binary, runs the server and the scans, and parses the output.
- `store/` holds SQLite.
- `scan/` orchestrates a run.
- `cli.py` is the Typer CLI.

Trivy always runs as a local `trivy server` with parallel `trivy image --server` clients, scanning by digest with `--image-src remote --platform`.

**Tech Stack:** Python ≥3.12, Typer, pydantic v2 + pydantic-settings, the official `kubernetes` client, httpx, platformdirs, stdlib sqlite3, pytest, ruff, GitHub Actions (k8s-servant pattern), release-please.

**Spec:** `docs/superpowers/specs/2026-11-13-kubedelos-design.md`

## Global Constraints
- **Package and commands:**
  - PyPI name `kubedelos`, import package `kubedelos`.
  - Console scripts: `kubedelos = "kubedelos.cli:app"` and `delos = "kubedelos.cli:delos_main"`.
  - In this plan, `delos_main` prints "UI coming in Phase 2" and exits 0.
- **Licence and rewrite:**
  - Apache-2.0 with a `NOTICE` file and `authors = [{ name = "The kubedelos Authors" }]`.
  - **Clean rewrite.** Never open, copy from or paraphrase the earlier internal tool. No internal company names, hostnames, label domains or integrations anywhere.
- **Python:**
  - `requires-python = ">=3.12"`; CI matrix 3.12, 3.13, 3.14.
  - Dependencies: lower bound is the current stable release, upper bound is the next major (`>=X.Y,<X+1`).
  - Nothing cloud-specific in core dependencies.
- **Ruff:** use k8s-servant's settings verbatim (`line-length = 120`, `target-version = "py312"`, the same select and ignore lists, `tests/**` per-file ignores).
- **Trivy:**
  - Pinned to **v0.76.1**. A per-platform SHA-256 is embedded in `kubedelos/trivy/pins.py`. Only `linux/amd64`, `linux/arm64`, `darwin/amd64` and `darwin/arm64` are supported in this phase.
  - Never resolve "latest". Never use `aquasecurity/trivy-action` in CI.
- **Scanning rules:**
  - Scanners: `--scanners vuln` only.
  - Data paths come from `platformdirs`: `user_cache_dir("kubedelos")` and `user_data_dir("kubedelos")`. `KUBEDELOS_CACHE_DIR` / `KUBEDELOS_DATA_DIR` override them.
  - Credentials and registry tokens are never written to SQLite or logs.
  - Default namespace exclusions are none. Users pass `--exclude-namespace`.
- **GitHub Actions** (copy the patterns from `.github/workflows/` in the k8s-servant repo in the same org):
  - every action pinned to a full SHA with a `# vX.Y.Z` comment
  - `permissions: {}` at the top, least-privilege per job
  - `persist-credentials: false`
  - `concurrency` groups
  - no pip cache in publish jobs
- **Git and PRs:**
  - Conventional Commits with lowercase subjects. No co-author or attribution lines.
  - Work on branch `feat/bootstrap-and-scan`; open a PR, never push to `main`.
  - Update `CHANGELOG.md` only through release-please. Until the first release, the hand-written `CHANGELOG.md` holds an `## Unreleased` section.

## Review Focus
1. **A container whose `imageID` is empty or oddly prefixed** (pending pod, `docker-pullable://`, a bare `sha256:` with no repo) should fall back to the tag reference rather than crash. Test: `test_inventory_imageid_variants` (Task 6).
2. **A namespace the user may not list** (HTTP 403 on pods) should be skipped with a warning, and the run should go on. Test: `test_inventory_forbidden_namespace_skipped` (Task 6).
3. **When one image fails in Trivy** (auth, not found, timeout), that image should be recorded as `status="error"` with an `error_kind` and never counted as clean. `--fail-on` should exit 2 when any image errored. Tests: `test_runner_classifies_errors` (Task 9), `test_cli_scan_exit_codes` (Task 12).
4. **Ctrl-C or cancel during a scan** should stop the Trivy server and its child processes and mark the run `cancelled`. Tests: `test_trivy_server_stops_on_exit` (Task 9), `test_service_cancel` (Task 11).
5. **Images with no OS packages** (distroless, scratch: `Results` is null or has no `Vulnerabilities`) should give zero findings and `status="ok"`. Test: `test_parse_empty_results` (Task 8).

---

## Phase 0: Secure repo bootstrap

### Task 1: Package skeleton and CLI entrypoints

**Files:**
- Create: `pyproject.toml`, `kubedelos/__init__.py`, `kubedelos/cli.py`, `tests/test_cli.py`, `README.md` (stub: title, one-line pitch, "status: pre-alpha"), `README.pypi.md`, `CHANGELOG.md` (`## Unreleased`), `.gitignore`, `.editorconfig`

**Interfaces:**
- Produces:
  - `kubedelos.__version__: str`, read with `importlib.metadata.version("kubedelos")`
  - `kubedelos.cli.app: typer.Typer`, with the subcommand `version` for now
  - `kubedelos.cli.delos_main() -> None`

- [ ] **Step 1: Write failing tests**
```python
from typer.testing import CliRunner
from kubedelos.cli import app

def test_version_prints_package_version():
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert r.stdout.strip().startswith("kubedelos ")

def test_both_console_scripts_declared():
    import tomllib, pathlib
    scripts = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["scripts"]
    assert scripts == {"kubedelos": "kubedelos.cli:app", "delos": "kubedelos.cli:delos_main"}
```
- [ ] **Step 2:** Run `uv venv && uv pip install -e '.[dev]' && pytest tests/test_cli.py -v`. Expect FAIL, because there is no package yet.
- [ ] **Step 3: Write `pyproject.toml`.** Model it on `pyproject.toml` in the k8s-servant repo in the same org:
  - `version = "0.0.0" # x-release-please-version`
  - dependencies: typer, pydantic, pydantic-settings, kubernetes, httpx, platformdirs, rich
  - `dev` extra: pytest, pytest-cov, ruff, pre-commit
  - `[tool.pytest.ini_options] testpaths=["tests"]`, plus a marker `e2e: needs kind + network`, with `addopts = "-m 'not e2e'"`
  - packages found with `[tool.setuptools.packages.find] include=["kubedelos*"]`
- [ ] **Step 4:** `pytest -v && ruff check . && ruff format --check .` should all PASS.
- [ ] **Step 5:** Commit: `git switch -c feat/bootstrap-and-scan` (from `main`, after the docs PR merges or rebased on it), then commit with `chore: add package skeleton with kubedelos and delos entrypoints`.

### Task 2: Community, security and repo hygiene files

**Files:**
- **Create:**
  - `LICENSE` is already present
  - `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `AGENTS.md`, `CLAUDE.md`
  - `.pre-commit-config.yaml`, `.gitleaksignore`
  - `.github/CODEOWNERS` (`* @k8s-servant/maintainers`), `.github/dependabot.yml`, `.github/labels.yml`, `.github/release.yml`, `.github/pull_request_template.md`
  - `.github/ISSUE_TEMPLATE/{bug_report.yml,feature_request.yml,config.yml}`
  - `release-please-config.json`, `.release-please-manifest.json` (`{".":"0.0.0"}`)
- **Templates:**
  - `SECURITY.md` from `SECURITY.md` in the k8s-skills repo in the same org
  - everything else from the k8s-servant repo in the same org, at the same paths
  - replace k8s-servant names and URLs with kubedelos

**Interfaces:** none (repo metadata).

- [ ] **Step 1: Write the files.**
  - `CODE_OF_CONDUCT.md` is Contributor Covenant 2.1, with the private-advisory link as the contact.
  - `dependabot.yml` covers the ecosystems `pip` and `github-actions` (add `docker` in Phase 3), with `cooldown: default-days: 7`, grouped updates, and the prefixes `chore(deps)` and `ci(deps)`.
  - `release-please-config.json` is k8s-servant's file, with `"package-name": "kubedelos"` and no `extra-files` yet.
  - `CLAUDE.md` / `AGENTS.md` cover the dev commands, the clean-rewrite rule and Conventional Commits.
- [ ] **Step 2: Verify.** `pre-commit run --all-files` PASSES (ruff, gitleaks, detect-private-key, end-of-file). `python -c "import json;json.load(open('release-please-config.json'))"` exits 0.
- [ ] **Step 3:** Commit with `chore: add community, security and release-please config`.

### Task 3: GitHub Actions workflows

**Files:**
- **Create** in `.github/workflows/`: `ci.yml`, `security.yml`, `codeql.yml`, `scorecard.yml`, `pr-title.yml`, `labels.yml`, `release-please.yml`.
- **Templates:** use the same-named files in `.github/workflows/` of the k8s-servant repo in the same org, plus actionlint from `.github/workflows/security.yml` in the k8s-skills repo.

**Interfaces:** the required status check is named exactly `CI result`.

- [ ] **Step 1: Write the workflows.**
  - **`ci.yml`:**
    - jobs `lint`, `test` (matrix 3.12–3.14 with coverage) and `package` (`python -m build`, `twine check`, then install the wheel into a clean venv and run `kubedelos version` and `delos`)
    - no helm or docker jobs yet
    - a `ci-result` job named `CI result` with `if: always()` that fails if any needed job's result is `failure` or `cancelled`; skipped counts as pass
  - **`security.yml`:** gitleaks (checksum-verified download), zizmor, actionlint (checksum-verified), dependency-review on PRs (`fail-on-severity: high`, deny GPL-3.0 and AGPL-3.0).
  - **`codeql.yml`:** languages `actions` and `python`, the `security-and-quality` queries, and a weekly cron.
  - **`scorecard.yml`:** also triggers on `branch_protection_rule`.
  - **`release-please.yml`:**
    - a release-please job using the GitHub App token (`vars.RELEASE_APP_CLIENT_ID`, `secrets.RELEASE_APP_PRIVATE_KEY`)
    - `pypi-build` (no `id-token`) and `pypi` (trusted publishing, `attestations: true`, environment `pypi`)
    - both gated with `if: needs.release-please.outputs.release_created == 'true' && vars.PUBLISH_ENABLED == 'true'`
    - image and chart jobs are added in Phase 3
- [ ] **Step 2: Verify locally.** `uvx zizmor .github/workflows` reports 0 findings. `actionlint` exits 0, installed with `brew install actionlint` if missing.
- [ ] **Step 3:** Commit with `ci: add ci, security, codeql, scorecard and release workflows`.
- [ ] **Step 4: Hand off to the user** (outward-facing; ask before doing any of this with `gh`):
  - create `k8s-servant/kubedelos` (public) and push the branch
  - add a ruleset on `main`: require `CI result`, squash only, linear history, no force-push
  - enable private vulnerability reporting, secret scanning and push protection
  - add the release App to the repo
  - create the `pypi` environment and a PyPI pending trusted publisher (workflow `release-please.yml`, environment `pypi`)
  - leave `PUBLISH_ENABLED` unset until Phase 5

---

## Phase 1: Core scanning and `kubedelos scan`

### Task 4: Settings and paths

**Files:** Create `kubedelos/config.py`, `tests/test_config.py`.

**Interfaces:**
- Produces:
  - `class Settings(pydantic_settings.BaseSettings)` with `env_prefix="KUBEDELOS_"` and these fields:
    - `kubeconfig: Path | None = None`
    - `context: str | None = None`
    - `namespaces: list[str] = []` (empty means all)
    - `exclude_namespaces: list[str] = []`
    - `cache_dir: Path`, `data_dir: Path` (defaults from platformdirs)
    - `trivy_path: Path | None = None`
    - `parallelism: int = 4` (1..32)
    - `scan_timeout_s: int = 600`
    - `owner_annotation: str = "kubedelos.io/owner-email"`
    - `team_label: str = "kubedelos.io/team"`
  - `Settings.db_path -> Path`, which is `data_dir / "kubedelos.db"`

- [ ] **Step 1: Tests.**
  - `test_defaults_use_platformdirs`: with `monkeypatch` on `platformdirs.user_cache_dir`, `cache_dir` equals the patched value.
  - `test_env_overrides`: `KUBEDELOS_DATA_DIR=/x` gives `db_path == Path("/x/kubedelos.db")`.
  - `test_parallelism_bounds`: `Settings(parallelism=0)` raises `ValidationError`.
- [ ] **Step 2:** Run `pytest tests/test_config.py -v`. Expect FAIL.
- [ ] **Step 3:** Implement as specified.
- [ ] **Step 4:** Run the tests. Expect PASS.
- [ ] **Step 5:** Commit with `feat: add settings with platform-specific data paths`.

### Task 5: Domain models

**Files:** Create `kubedelos/models.py`, `tests/test_models.py`.

**Interfaces:**
- Produces (pydantic models, frozen where noted):
  - `Severity(StrEnum)`: `CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN`, with `.rank -> int` (CRITICAL=4 … UNKNOWN=0)
  - `ImageRef` (frozen):
    - fields: `ref: str` (what is passed to trivy), `repo: str`, `tag: str | None`, `digest: str | None`
    - `.key -> str` returns `digest or ref`, the cache and dedupe key
  - `Workload` (frozen): `namespace, kind, name, container: str`, `owner: str | None`, `team: str | None`
  - `InventoryItem`: `image: ImageRef`, `platform: str` (e.g. `"linux/amd64"`), `workloads: list[Workload]`
  - `Finding`:
    - `vuln_id, pkg_name, installed_version: str`
    - `fixed_version: str | None`
    - `severity: Severity`
    - `title: str | None`
    - `primary_url: str | None`
    - `target: str`
    - `pkg_type: str`
    - `.fixable -> bool`
  - `ImageResult`:
    - `image: ImageRef`, `platform: str`
    - `status: Literal["ok","error","cached"]`
    - `error_kind: Literal["auth","not_found","timeout","trivy","unknown"] | None`
    - `error: str | None`
    - `findings: list[Finding]`
    - `os_family: str | None`

- [ ] **Step 1: Tests.**
  - `test_severity_rank_order`: `[s.rank for s in Severity]` should be `[4, 3, 2, 1, 0]`.
  - `test_imageref_key_prefers_digest`.
  - `test_finding_fixable`: `fixed_version=""` gives False, `"1.2"` gives True.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: add scan domain models`.

### Task 6: Kubernetes inventory

**Files:** Create `kubedelos/kube/__init__.py`, `kubedelos/kube/client.py`, `kubedelos/kube/inventory.py`, `kubedelos/kube/owners.py`, `tests/kube/test_inventory.py`, `tests/kube/fakes.py`.

**Interfaces:**
- Consumes: `Settings`, `ImageRef`, `Workload`, `InventoryItem`.
- Produces:
  - `kube.client.load(settings) -> KubeApi`: a small Protocol wrapping CoreV1, AppsV1 and BatchV1, with these methods:
    - `list_namespaces() -> list[V1Namespace]`
    - `list_pods(ns)`
    - `list_deployments(ns)`
    - `list_statefulsets(ns)`
    - `list_cronjobs(ns)`
    - `list_nodes()`
    - `current_context() -> str`
  - `kube.owners.resolve(ns: V1Namespace, settings) -> tuple[str | None, str | None]`, returning `(owner, team)` from the configured annotation or label on the namespace. Phase 4 adds rules on top.
  - `kube.inventory.parse_image_id(image: str, image_id: str) -> ImageRef`
  - `kube.inventory.collect(api: KubeApi, settings) -> tuple[list[InventoryItem], list[str]]`, returning `(items, warnings)`

- **Rules for `collect`:**
  - **Pods:** include containers, init containers and ephemeral containers. The digest comes from the matching `containerStatuses[].imageID`.
  - **Templates:** include the pod templates of CronJobs, and of Deployments and StatefulSets with `spec.replicas == 0`. These have tag refs only.
  - **Grouping:** group by `(ImageRef.key, platform)`.
  - **Platform:** `linux/<node.status.nodeInfo.architecture>` of the pod's node. Fall back to the most common node arch, then to `linux/amd64`.
  - **Workload kind:** taken from the top `ownerReferences`, with ReplicaSet mapped to Deployment by stripping the hash suffix through the RS's own owner. If there is no owner, the kind is `Pod`.
  - **Errors:** a 403 on a namespace adds the warning `"skipped namespace <ns>: forbidden"`.
- **Rules for `parse_image_id`:**
  - strip the `docker-pullable://` and `docker://` prefixes
  - `repo@sha256:…` gives a digest ref
  - a bare `sha256:…` or an empty value gives a tag ref with `digest=None`
  - a ref without a tag gets `:latest`
  - Docker Hub short names are normalised to `docker.io/library/…`

- [ ] **Step 1: Tests**, using hand-built `kubernetes.client.V1*` objects in `fakes.py`:
  - `test_inventory_dedupes_by_digest`: two pods with the same digest produce one item with two workloads.
  - `test_inventory_includes_init_ephemeral_and_templates`: a CronJob, and a Deployment scaled to 0.
  - `test_inventory_imageid_variants`: parametrised over `""`, `"sha256:abc"`, `"docker-pullable://nginx@sha256:abc"`, `"nginx"`, with the expected `ImageRef` values.
  - `test_inventory_forbidden_namespace_skipped`: the fake raises `ApiException(status=403)` for one namespace; the other namespace's items are present and one warning is returned.
  - `test_inventory_platform_from_node`: an arm64 node gives `linux/arm64`.
  - `test_owner_from_namespace_annotation`: the annotation `kubedelos.io/owner-email: a@x.io` and the label `kubedelos.io/team: pay` are reflected in each `Workload`.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: collect cluster image inventory with digests, templates and owners`.

### Task 7: Pinned Trivy binary manager

**Files:** Create `kubedelos/trivy/__init__.py`, `kubedelos/trivy/pins.py`, `kubedelos/trivy/binary.py`, `tests/trivy/test_binary.py`.

**Interfaces:**
- Produces:
  - `pins.TRIVY_VERSION = "0.76.1"`
  - `pins.ASSETS: dict[tuple[str, str], tuple[str, str]]`, mapping `(os, arch)` to `(asset_filename, sha256)`
  - `binary.ensure_trivy(settings, *, download: bool = True) -> Path`:
    - returns `settings.trivy_path` if it is set and executable
    - otherwise `<cache_dir>/trivy/<version>/trivy` if present
    - otherwise downloads `https://github.com/aquasecurity/trivy/releases/download/v{V}/{asset}`, verifies its SHA-256, safely extracts the `trivy` member only (the tarfile `filter="data"`; reject other paths) and sets the mode to 0755
    - a hash mismatch raises `TrivyVerificationError` and leaves no file behind
  - `binary.TrivyVerificationError(Exception)`
  - CLI: `kubedelos trivy install`, which calls `ensure_trivy` and prints its path and version.

- [ ] **Step 1: Fill `pins.py`.**
  - Download `trivy_0.76.1_checksums.txt` and its `.sigstore.json` bundle.
  - Verify them with `cosign verify-blob --bundle … --certificate-identity-regexp 'https://github.com/aquasecurity/trivy/.github/workflows/' --certificate-oidc-issuer https://token.actions.githubusercontent.com`.
  - Only then copy the 4 hashes in, and record the verification command in a comment at the top of `pins.py`.
  - If the signature does not verify, **stop and tell the user**.
- [ ] **Step 2: Tests.** Use httpx `MockTransport` to serve a tiny tar.gz built in the test, and patch the `ASSETS` hash to match it.
  - `test_ensure_trivy_downloads_and_verifies`
  - `test_ensure_trivy_hash_mismatch_raises_and_cleans`
  - `test_ensure_trivy_rejects_path_traversal_member`
  - `test_ensure_trivy_prefers_explicit_path`
  - `test_ensure_trivy_unsupported_platform` (windows raises `RuntimeError`)
- [ ] **Steps 3–5:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 6:** Commit with `feat: download and verify pinned trivy release`.

### Task 8: Trivy JSON parser

**Files:** Create `kubedelos/trivy/parse.py`, `tests/trivy/fixtures/{alpine.json,distroless_empty.json,null_results.json,multi_target.json}`, `tests/trivy/test_parse.py`.

**Interfaces:**
- Produces: `parse.parse_report(data: dict) -> tuple[list[Finding], str | None]`, returning `(findings, os_family)`.
- **Fixtures:** produce them with local `trivy image --format json --scanners vuln` on `alpine:3.18`, `gcr.io/distroless/static`, and `python:3.12-slim` (trimmed to fewer than 30 vulnerabilities by hand). `null_results.json` is `{"SchemaVersion":2,"Results":null}`.

- [ ] **Step 1: Tests.**
  - `test_parse_alpine_counts`: assert the exact count of findings and of CRITICAL findings, taken from the fixture with `jq` when it is generated.
  - `test_parse_empty_results`: both empty fixtures give `([], …)`.
  - `test_parse_multi_target_sets_target_and_pkg_type`.
  - `test_parse_unknown_severity_maps_to_unknown`.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: parse trivy json reports into findings`.

### Task 9: Trivy server and scan runner

**Files:** Create `kubedelos/trivy/runner.py`, `tests/trivy/test_runner.py`, `tests/trivy/fake_trivy.py` (an executable Python script that imitates `trivy server` and `trivy image` from env-var instructions).

**Interfaces:**
- Consumes: `ensure_trivy`, `parse_report`, `ImageRef`, `ImageResult`, `Settings`.
- Produces:
  - **`class TrivyServer`** (context manager), created with `TrivyServer(trivy: Path, cache_dir: Path)`:
    - on `__enter__` it updates the DB once (`trivy image --download-db-only`, then `--download-java-db-only`)
    - it then starts `trivy server --listen 127.0.0.1:<free port> --cache-dir <cache>/trivy-cache` in its own process group, and polls `GET /healthz` until ready (30 s, otherwise `RuntimeError`)
    - `.url: str`
    - on `__exit__` it sends SIGTERM to the process group, waits 5 s, then SIGKILL
  - **`scan_image(trivy, server_url, item_ref: ImageRef, platform: str, timeout_s: int, docker_config: Path | None = None) -> ImageResult`** runs:
    `[trivy, "image", "--server", url, "--format", "json", "--scanners", "vuln", "--image-src", "remote", "--platform", platform, "--quiet", "--timeout", f"{timeout_s}s", ref]`
    - `DOCKER_CONFIG` is set only when `docker_config` is given
    - **Error classification:** match on stderr, case-insensitively.
      - `unauthorized|denied|authentication required` → `auth`
      - `manifest unknown|not found|name unknown` → `not_found`
      - the subprocess timeout → `timeout`
      - any other non-zero exit → `trivy`
  - **`scan_many(items, *, server, trivy, settings, on_result: Callable[[ImageResult], None], cancel: threading.Event) -> None`** uses a ThreadPoolExecutor with `settings.parallelism` workers. Once `cancel` is set, no new image starts.

- [ ] **Step 1: Tests.** Point `trivy` at `fake_trivy.py`.
  - `test_runner_builds_expected_args`: the fake echoes its argv into the JSON.
  - `test_runner_classifies_errors`: parametrised over the 4 stderr patterns plus a timeout.
  - `test_trivy_server_stops_on_exit`: after the `with` block, the fake server's PID is gone (`os.kill(pid, 0)` raises).
  - `test_scan_many_respects_cancel`: 10 items with the fake sleeping 0.2 s and parallelism 2; setting cancel after the first result leaves fewer than 10 results.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: run trivy in server mode with parallel remote image scans`.

### Task 10: SQLite store

**Files:** Create `kubedelos/store/__init__.py`, `kubedelos/store/db.py`, `kubedelos/store/repo.py`, `tests/store/test_repo.py`.

**Interfaces:**
- Produces:
  - **`db.connect(path: Path) -> sqlite3.Connection`**:
    - creates the parent dirs
    - sets `journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`
    - applies migrations ordered by `PRAGMA user_version`
  - **Schema v1:**
    - `scan_run(id INTEGER PK, started_at TEXT, finished_at TEXT, status TEXT CHECK(status IN ('running','ok','partial','cancelled','failed')), context TEXT, trigger TEXT, trivy_version TEXT, images_total INT, images_error INT)`
    - `image_result(id PK, run_id FK, image_key TEXT, ref TEXT, repo TEXT, tag TEXT, digest TEXT, platform TEXT, status TEXT, error_kind TEXT, error TEXT, os_family TEXT)`
    - `workload(id PK, image_result_id FK, namespace, kind, name, container, owner, team)`
    - `finding(id PK, image_result_id FK, vuln_id, pkg_name, installed_version, fixed_version, severity, title, primary_url, target, pkg_type)`
    - `image_cache(image_key TEXT, platform TEXT, trivy_db_version TEXT, scanned_at TEXT, report_json BLOB, PRIMARY KEY(image_key, platform))`
    - indexes on `finding(severity)`, `image_result(run_id)`, `workload(namespace)`
  - **`class Repo(conn)`**, with:
    - `start_run(context, trigger, trivy_version) -> int`
    - `add_result(run_id, item: InventoryItem, result: ImageResult) -> None`
    - `finish_run(run_id, status) -> None`, which also sets the counts
    - `get_cached(image_key, platform, max_age: timedelta) -> dict | None`
    - `put_cache(image_key, platform, report: dict) -> None`
    - `latest_run_id() -> int | None`
    - `run_findings(run_id) -> list[sqlite3.Row]`, which joins the workloads
  - Only digest keys (`sha256:` in the key) are cached. Tag refs are always rescanned.

- [ ] **Step 1: Tests** (using `tmp_path`):
  - `test_migrations_idempotent`: connect twice and `user_version == 1`.
  - `test_run_roundtrip_counts`: 2 ok results and 1 error give `images_total=3, images_error=1`.
  - `test_cache_hit_and_expiry`.
  - `test_tag_refs_not_cached`.
  - `test_finish_run_rejects_bad_status`.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: add sqlite store for runs, results and digest cache`.

### Task 11: Scan service

**Files:** Create `kubedelos/scan/__init__.py`, `kubedelos/scan/service.py`, `tests/scan/test_service.py`.

**Interfaces:**
- Consumes: `collect`, `ensure_trivy`, `TrivyServer`, `scan_many`, `parse_report`, `Repo`.
- Produces:
  - `Progress` dataclass: `total: int`, `done: int`, `errors: int`, `current: str | None`
  - **`run_scan(settings, *, api=None, repo=None, trigger="cli", on_progress: Callable[[Progress], None] = lambda p: None, cancel: threading.Event | None = None, cache_max_age=timedelta(hours=24)) -> int`**, which returns the run_id. It works in this order:
    1. inventory
    2. cache lookup by `(key, platform)` (cached results get `status="cached"`)
    3. a `TrivyServer` only when there are uncached items
    4. `scan_many`, then persisting each result as it arrives
  - **Final status:**
    - `cancelled` if cancel is set
    - `failed` on an exception (re-raised)
    - `partial` if any image errored
    - otherwise `ok`
  - **Mockability:** `scan_many` and `TrivyServer` are injected through module-level names, so tests can monkeypatch them.

- [ ] **Step 1: Tests** (fake api, monkeypatched runner):
  - `test_service_persists_results_and_status_partial`
  - `test_service_uses_cache_second_run`: the second run calls `scan_many` with 0 items and starts no server.
  - `test_service_cancel`: status is `cancelled`.
  - `test_service_failed_on_exception`
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: orchestrate scan runs with cache, progress and cancel`.

### Task 12: `kubedelos scan` command and output formats

**Files:** Create `kubedelos/output.py`, `tests/test_output.py`, `tests/test_cli_scan.py`; modify `kubedelos/cli.py`.

**Interfaces:**
- Consumes: `run_scan`, `Repo.run_findings`.
- Produces:
  - **CLI:** `kubedelos scan` with these options:
    - `--context`, `--kubeconfig`
    - `-n/--namespace` (repeatable), `--exclude-namespace` (repeatable)
    - `-o/--output [table|json|csv|sarif]`, default `table`
    - `--severity` (comma list, default `CRITICAL,HIGH`)
    - `--fail-on [none|low|medium|high|critical]`, default `none`
    - `--parallelism`, `--trivy-path`, `--no-cache`
    - `--output-file PATH`
  - The scan shows a rich progress bar on stderr, and the results go to stdout or `--output-file`.
  - **Exit codes:**
    - `0`: ok
    - `1`: the threshold was reached by any finding at or above `--fail-on`
    - `2`: one or more images errored and `--fail-on != none`, or a fatal error occurred
    - `130`: cancelled (Ctrl-C sets the cancel event)
  - **Formatters in `output.py`:**
    - `render_table(rows) -> str`: rich table, one row per finding: namespace/workload, image, vuln, severity, installed, fixed
    - `render_json(rows) -> str`
    - `render_csv(rows) -> str`
    - `render_sarif(rows) -> str`: SARIF 2.1.0, with one rule per vuln_id and severity mapped to `level` (critical/high → error, medium → warning, others → note). `artifactLocation.uri` is the image ref.

- [ ] **Step 1: Tests.**
  - `test_render_sarif_schema_shape`: check `version == "2.1.0"`, the rule ids, and that a CRITICAL finding has level `error`.
  - `test_render_csv_header`: the header is exactly `namespace,kind,workload,container,image,vuln_id,severity,pkg_name,installed_version,fixed_version,owner,team`.
  - `test_cli_scan_exit_codes`: monkeypatch `run_scan` with a pre-filled temp DB and parametrise over (`none`, has crit) → 0, (`high`, has crit) → 1, (`high`, an image errored) → 2.
  - `test_cli_scan_severity_filter`.
- [ ] **Steps 2–4:** Run the tests (FAIL), implement, run again (PASS).
- [ ] **Step 5:** Commit with `feat: add kubedelos scan with table, json, csv and sarif output`.

### Task 13: kind end-to-end test, docs touch-up, PR

**Files:** Create `tests/e2e/test_kind_scan.py` (marked `e2e`), `scripts/e2e-kind.sh`; modify `README.md` (Quickstart: `pipx install kubedelos` and `kubedelos scan`) and `CHANGELOG.md` (Unreleased entries).

- [ ] **Step 1: Write `scripts/e2e-kind.sh`.**
  - Create the kind cluster `kubedelos-e2e`.
  - Deploy `nginx:1.19` in ns `web`, with the annotation `kubedelos.io/owner-email=web@example.com`.
  - Add a CronJob with `busybox:1.36` in ns `jobs`.
  - Run `KUBEDELOS_CACHE_DIR=$(mktemp -d) kubedelos scan --context kind-kubedelos-e2e -o json --output-file out.json --fail-on critical`.
  - Expect exit 1, `out.json` with at least 1 CRITICAL for nginx and `owner == "web@example.com"`, and a busybox row present.
  - Clean up with a trap that deletes the cluster.
- [ ] **Step 2:** `tests/e2e/test_kind_scan.py` runs the script via subprocess and asserts on `out.json`. Run `pytest -m e2e -v` locally; it should PASS (this downloads Trivy and its DB, so it needs network).
- [ ] **Step 3:** Update the README Quickstart and the CHANGELOG `## Unreleased` section, listing scan, output formats and pinned Trivy.
- [ ] **Step 4: Check the whole branch.**
  - `pytest --cov=kubedelos --cov-report=term-missing` should report coverage of at least 80% for `kubedelos/` excluding `cli.py`.
  - `ruff check . && ruff format --check .`
  - `pre-commit run --all-files`
  - `uvx zizmor .github/workflows`
- [ ] **Step 5:** Commit with `test: add kind end-to-end scan test`. **Ask the user before pushing and opening the PR** with `gh pr create`.
