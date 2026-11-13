# kubedelos Phase 1b: laptop registry access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** private images scan on a laptop with whatever the user is already logged in with. `kubedelos registry test <image>` reports whether kubedelos can read an image, and auth failures tell the user how to log in.

**Architecture:** no credential code. Trivy already reads `DOCKER_CONFIG` or `~/.docker/config.json`, including `credHelpers` and `credsStore` (`docker login`, `az acr login`, `gcloud auth configure-docker`, the ECR credential helper), and `scan_image` passes the environment through unchanged. This phase pins that behaviour with a test, adds `kubedelos registry test` on top of the existing `TrivyCache` + `scan_image`, prints a login hint for auth failures, and documents it.

**Tech Stack:** Python 3.12+, Typer, pytest with `tests/trivy/fake_trivy.py`.

**Spec:** `docs/superpowers/specs/2026-11-13-kubedelos-design.md`, which this plan re-scopes (decided 2026-11-13):
- Phase 1b covers the laptop only.
- The `registries:` config, the cloud providers (ACR exchange, aws, gcp) and the opt-in Secret-backed auth (`secretRef`, `pod-pull-secrets`) move to Phase 3, together with the Helm chart and its RBAC.
- AGENTS.md's "never read Secrets" rule stays as it is until Phase 3.

**Depends on:** PR #4 (standalone Trivy, `TrivyCache`, `scan_image(trivy, item_ref, platform, timeout_s, docker_config=None, *, cache_dir=None)`). Branch from `main` after #4 merges.

## Global Constraints

- Read-only cluster access. No Secrets are read in this phase.
- Credentials never touch disk or logs. kubedelos never reads or prints docker config contents; Trivy reads them itself.
- Trivy stays pinned at v0.76.1 with `--scanners vuln` only. `--` stays before the ref, and refs are checked with `is_valid_ref` before they reach Trivy.
- One test file per module; failing test first. Ruff line length 120. Every module starts with a docstring.

## Review Focus

1. **A user-set `DOCKER_CONFIG`** (for example a CI job's) must reach Trivy unchanged when kubedelos isn't given its own. (Task 1: `test_runner_inherits_docker_config_from_env`)
2. **A ref typed by the user, such as `-oyaml` or one with spaces,** is rejected before Trivy runs, as cluster refs already are. (Task 1: `test_registry_test_rejects_invalid_ref`)
3. **Docker Hub short names** (`nginx`, `library/nginx:1.19`) give the hint host `docker.io`, not `nginx`. (Task 1: `test_registry_host_of_short_names`)
4. **Many images failing auth on the same registry** produce one hint per host, not one per image. (Task 2: `test_scan_prints_one_auth_hint_per_host`)
5. **Ctrl-C during `registry test`** exits 130 and leaves no Trivy process running. (Task 1: `test_registry_test_cancel_exits_130`)

---

### Task 1: `kubedelos registry test <image>`

**Files:**
- Modify: `kubedelos/models.py` (add `registry_host`) and `tests/test_models.py`
- Modify: `kubedelos/cli.py` (a `registry` sub-app with a `test` command) and `tests/test_cli.py`
- Modify: `tests/trivy/test_runner.py` (the env pass-through test)

**Interfaces:**
- Consumes: `TrivyCache(trivy, cache_dir)` / `.dir`, `scan_image(...)`, `ensure_trivy(settings)`, `parse_image_id(image, "")` from `kubedelos/kube/inventory.py` (an empty image ID takes the spec-image path), `is_valid_ref`, `_signals_as_interrupt`, `_one_line`.
- Produces:
  - `registry_host(image: ImageRef) -> str`: the first path segment of the normalised `image.repo`, for example `docker.io` or `registry.example:5000`.
  - `_LOGIN_HINT: str` in `cli.py`, reused by Task 2.

Command: `kubedelos registry test IMAGE [--platform linux/amd64] [--trivy-path PATH]`, with timeout `settings.scan_timeout_s`.

| Outcome | stdout / stderr | Exit |
|---|---|---|
| `status == "ok"` | stdout: `ok: <ref> is readable (<N> findings)` | 0 |
| `error_kind == "auth"` | stderr: `error: <ref>: authentication failed on <host>: <first line>`, then `hint: ` + `_LOGIN_HINT.format(host=host)` | 1 |
| `error_kind == "not_found"` | stderr: `error: <ref>: not found on <host>: <first line>` | 1 |
| other error, invalid ref, or setup failure (for example a DB download error) | stderr: `error: ...` | 2 |
| Ctrl-C, SIGTERM or SIGHUP | stderr: `cancelled` | 130 |

`_LOGIN_HINT = "log in to {host} first, for example `docker login {host}`, `az acr login --name <registry>`, `gcloud auth configure-docker {host}` or an ECR credential helper; kubedelos uses the same Docker credentials"`

- [ ] **Step 1: Write the failing tests:**
  - `tests/test_models.py`:
    - `test_registry_host_of_short_names`: `nginx`, `library/nginx:1.19` and `docker.io/library/nginx` all give `docker.io`.
    - `test_registry_host_keeps_port`: `registry.example:5000/team/app:1` gives `registry.example:5000`.
  - `tests/trivy/test_runner.py::test_runner_inherits_docker_config_from_env`: with `DOCKER_CONFIG=/x/docker` in the environment and no `docker_config=`, the fake echoes `FakeEnv["DOCKER_CONFIG"] == "/x/docker"`.
  - `tests/test_cli.py`, running the CLI with `--trivy-path` pointing at `FAKE_TRIVY` and `KUBEDELOS_CACHE_DIR=tmp_path`:
    - `test_registry_test_ok`: exit 0, and stdout starts with `ok: docker.io/library/nginx:1.19 is readable`.
    - `test_registry_test_auth_failure_prints_hint`: `FAKE_TRIVY_STDERR="UNAUTHORIZED: authentication required"` and `FAKE_TRIVY_EXIT=1` give exit 1, stderr contains `authentication failed on registry.example` and `hint: log in to registry.example first`.
    - `test_registry_test_not_found`: `MANIFEST_UNKNOWN: manifest unknown` gives exit 1, stderr contains `not found on`.
    - `test_registry_test_rejects_invalid_ref`: `-oyaml` (passed after `--`) gives exit 2, and the fake is never called (`FAKE_TRIVY_RECORD` file absent).
    - `test_registry_test_cancel_exits_130`: in the subprocess style of `tests/test_cli_scan.py::_SIGTERM_SCRIPT`, a fake scan with `FAKE_TRIVY_SLEEP=30` and `FAKE_TRIVY_PID_FILE` gets SIGTERM once the PID file exists. It must exit 130, and the PID must be gone.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_models.py tests/test_cli.py tests/trivy/test_runner.py -q`. Expected: the new tests fail (`ImportError: registry_host`, `No such command 'registry'`). `test_runner_inherits_docker_config_from_env` may already pass. If so, it pins existing behaviour; note that in the ledger.
- [ ] **Step 3: Implement** `registry_host` and the `registry test` command as specified. The command builds `ImageRef` with `parse_image_id(image, "")`, checks `is_valid_ref(ref.ref)`, then runs `with _signals_as_interrupt(), TrivyCache(trivy, settings.cache_dir) as cache: scan_image(trivy, ref, platform, settings.scan_timeout_s, cache_dir=cache.dir)`.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`, `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`. Expected: all pass.
- [ ] **Step 5: Commit** `feat: add kubedelos registry test`

### Task 2: One login hint per registry in `kubedelos scan`

**Files:**
- Modify: `kubedelos/cli.py` (after the per-image `error:` lines in `scan`) and `tests/test_cli_scan.py`

**Interfaces:**
- Consumes: `registry_host`, `_LOGIN_HINT` (Task 1), and the `failed` rows from `repo.run_errors(run_id)`, which have `ref` and `error_kind`.

After the existing per-image error lines, collect the hosts of the rows where `error_kind == "auth"`. Rows only have the ref string, so take the host from `parse_image_id(row["ref"], "")`. Print `hint: ` + `_LOGIN_HINT.format(host=h)` once per host, in sorted order. Exit codes don't change.

- [ ] **Step 1: Write the failing tests** in `tests/test_cli_scan.py`, using the file's existing fake-run fixtures:
  - `test_scan_prints_one_auth_hint_per_host`: three auth failures, two on `registry.example` and one on `other.example`, give exactly two `hint:` lines, for `other.example` then `registry.example`.
  - `test_scan_no_hint_without_auth_errors`: only a `not_found` error gives no `hint:` line.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/test_cli_scan.py -q`. Expected: the two new tests fail.
- [ ] **Step 3: Implement** the hint loop.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `feat: hint how to log in when images fail registry auth`

### Task 3: Docs and a real private-registry check

**Files:**
- Modify: `README.md` and `README.pypi.md`. Add a `## Private registries` section after `## Trivy` that covers:
  - kubedelos uses your Docker credentials (`DOCKER_CONFIG` or `~/.docker/config.json`, including credential helpers), with one line each for `docker login`, `az acr login`, `gcloud auth configure-docker` and the ECR credential helper
  - `kubedelos registry test <image>` and its exit codes
  - in-cluster registry auth comes with the Helm chart
- Modify: `CHANGELOG.md`, under Unreleased Features: "`kubedelos registry test <image>` checks that an image is readable with your current registry login, and scans print a login hint for registries that refuse access."
- Modify: `docs/superpowers/specs/2026-11-13-kubedelos-design.md`:
  - rewrite the Phase 1b paragraph as the laptop scope above
  - add "registry auth providers, the `registries:` config and opt-in Secret-backed auth (`secretRef`, `pod-pull-secrets`)" to Phase 3
  - in "Container registry authentication", add one line saying the laptop uses the existing Docker login and that the providers are the in-cluster mode

- [ ] **Step 1: Edit the docs** as listed above.
- [ ] **Step 2: Real check against a private registry.** Start a local `registry:2` with htpasswd on `127.0.0.1:5000` and push `alpine:3.18` to it as `127.0.0.1:5000/alpine:3.18`. Use a throwaway `DOCKER_CONFIG` in the scratchpad, so the user's own Docker login isn't touched. Run `kubedelos registry test 127.0.0.1:5000/alpine:3.18` before and after `docker --config <tmp> login 127.0.0.1:5000`.
  Expected: exit 1 with the hint before login, and exit 0 `ok:` after. Remove the container afterwards.
  If Trivy refuses plain-HTTP localhost, set `TRIVY_INSECURE=true` for this check only, and add a README line saying that a plain-HTTP registry needs it.
- [ ] **Step 3: Run** `.venv/bin/pre-commit run --all-files`. Expected: all hooks pass.
- [ ] **Step 4: Commit** `docs: document laptop registry access and the phase 1b re-scope`, then open the PR `feat: add kubedelos registry test and registry login hints`.
