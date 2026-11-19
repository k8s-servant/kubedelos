# Registry login (in-cluster) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kubedelos serve` can scan private images: through the pod's cloud identity (the `cloud.provider` presets),
through mounted Docker config Secrets, and (opt-in) through the pull secrets a pod names, without credentials reaching
SQLite, logs or node disk.

**Architecture:** A new `kubedelos/registry/` package decides, per image, which Docker config `auths` Trivy gets
(`dockerconfig.py`, `pullsecrets.py`). The cloud identity needs no code: the chart's presets set up the environment and
Trivy's own providers use it, only for vendor-run registry hosts (spec, Approaches, Registry login).
`access.py` combines them into a per-image context manager that `scan_many` enters around each image's attempts; it
writes a 0700 temporary `DOCKER_CONFIG` under the memory-backed `KUBEDELOS_SECRETS_DIR` and removes it on exit. The
chart adds the `cloud.provider` presets, the Secret mounts, per-namespace Roles and the memory volume.

**Tech Stack:** Python 3.12+, pydantic-settings, kubernetes client, FastAPI + Jinja + HTMX, Helm 4, kind, `registry:2`.

**Spec:** `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md` (sections "Registry login" under Approaches, 7,
8 and Delivery item 4). Issue #14.

## Global Constraints

- Read-only cluster access. The only new API call is `get` on a Secret a pod names in its `imagePullSecrets`, in a
  namespace listed in `KUBEDELOS_POD_PULL_SECRET_NAMESPACES`. Never `list` Secrets, never read ServiceAccounts.
- Registry tokens and Secret contents never go to SQLite, logs, error messages or the Settings page. Secret *names* may
  be logged at debug level and stored in SQLite (they are not credentials).
- A per-scan Docker config is the only credential file, and only under `KUBEDELOS_SECRETS_DIR` (an `emptyDir` with
  `medium: Memory`, `sizeLimit: 16Mi`, mounted at `/run/kubedelos`). Directory mode 0700, file mode 0600. Deleted when
  that image's scan ends, on success, error, cancel or exception. With `KUBEDELOS_SECRETS_DIR` unset (the laptop), no
  file is ever written.
- Only `auths` entries are written. `credHelpers`, `credsStore` and every other key of a mounted config are dropped.
- A Secret whose `type` is not `kubernetes.io/dockerconfigjson` is dropped unread and unlogged.
- Trivy is pinned (v0.76.1) with `--scanners vuln`. No new Trivy flags.
- AGENTS.md conventions: TDD, one test file per module, ruff 120, module docstrings, placeholders only (`example.com`,
  `my-cluster`, `registry.example.com`), conventional lowercase commits, no attribution lines.
- Never touch real registries or work clusters. kind clusters named `kubedelos-*` only; leave `lab` and `onboard-test`.
- CHANGELOG under `## Unreleased`. AGENTS.md rule change lands in this PR (spec section 7.5).

## Rulings made while planning (the spec did not decide these)

1. **Pod pull secrets are enabled by a non-empty `KUBEDELOS_POD_PULL_SECRET_NAMESPACES`** (spec: kubedelos reads only
   that list). There is no separate boolean setting; the chart's `registries.podPullSecrets` only gates rendering.
2. **Retries keep pull secrets.** The secret *names* an image's pods named are stored with each `image_result`
   (migration 11, column `pull_secrets`, JSON `[[namespace, name], ...]`), so a retry of an auth failure reads the same
   Secrets. Contents are read again at retry time, never stored.
3. **Precedence.** Mounted configs in the listed order, first wins per host; then pod pull secrets override them for the
   image's host, first in (namespace, pod order) wins among several. Cloud identity vs Docker config is Trivy's call;
   Task 7 documents it from the Trivy source.
4. **A Docker config is written only when there is at least one `auths` entry for the image's host.** Otherwise
   `DOCKER_CONFIG` is left as it is.
5. **"Test an image" (Settings page, serve only)** uses the cloud identity and the mounted configs, not pod pull
   secrets (there is no pod). One test at a time (a lock; a second request gets "a test is already running"); Trivy
   timeout `min(scan_timeout_s, 120)`. Read-only mode refuses it, as `install_serve` already refuses every POST.
6. **The cloud identity shown on Settings** comes from `KUBEDELOS_CLOUD_PROVIDER` and `KUBEDELOS_CLOUD_IDENTITY`, which
   the chart sets from the preset values (client id, role ARN or GCP service account), never from a token.
7. **Image ENV.** The Dockerfile sets `KUBEDELOS_SECRETS_DIR=/run/kubedelos` and creates that directory owned by
   65532, so `docker run` without the chart still works; the chart mounts the memory volume over it.

## Review Focus

1. **Two pods in different namespaces run the same image and name different pull secrets** → both Secrets are
   tried in (namespace, pod order) for that image's host, the first that has an entry wins, and neither Secret's
   entries for other hosts reach the written config (Task 2 `test_pull_secrets_from_two_namespaces`).
2. **Docker Hub entries keyed `https://index.docker.io/v1/`, `index.docker.io`, `registry-1.docker.io` or `docker.io`**
   in a mounted config → they apply to `docker.io/...` images and are written under the key Trivy looks up (Task 1
   `test_docker_hub_keys_normalise`).
3. **A scan cancelled, timed out, or killed by an exception mid-image** → its temporary config directory is gone
   afterwards (Task 3 `test_temp_config_removed_when_scan_raises`).
4. **A pod naming a Secret that does not exist, is forbidden, or is not a dockerconfigjson** → the image is
   scanned with what remains, a debug line names the Secret (never its content), and the run does not fail (Task 2
   `test_missing_or_forbidden_secret_is_skipped`, `test_non_docker_secret_dropped_unread`).
5. **A mounted config file that is missing, empty or not JSON** (a Secret of the wrong type, mid-rotation) → that file
   is skipped with a warning naming the path, the others still apply (Task 1 `test_bad_mounted_config_skipped`).

---

### Task 1: Docker configs: read, merge, write per scan

**Files:**
- Create: `kubedelos/registry/dockerconfig.py`
- Modify: `kubedelos/config.py` (`secrets_dir`, `docker_configs`)
- Test: `tests/registry/test_dockerconfig.py`, `tests/test_config.py`

**Interfaces:**
- Produces:
  - `Settings.secrets_dir: Path | None = None`; `Settings.docker_configs: list[Path] = []` (JSON list or comma list).
    A validator refuses `docker_configs` or `pod_pull_secret_namespaces` (Task 2) without `secrets_dir`:
    "KUBEDELOS_SECRETS_DIR is required for registry credentials".
  - `Auths = dict[str, dict[str, str]]` (normalised host → `{"auth": ...}` or `{"username": ..., "password": ...}`).
  - `parse(raw: bytes) -> Auths`: only `auths`; keys normalised by `normalise_host(key) -> str` (scheme, path and
    trailing slash dropped, lowercased; `index.docker.io`, `registry-1.docker.io`, `https://index.docker.io/v1/` →
    `docker.io`); entries without `auth` or `username`+`password` (string values) dropped. Raises `ValueError` with no
    content in the message for bad JSON.
  - `load_mounted(paths: list[Path]) -> Auths`: first file wins per host; a missing or bad file is skipped with
    `logger.warning("skipped docker config %s: %s", path, reason)` (reason is the exception class name, never content).
  - `for_host(auths: Auths, host: str) -> Auths`: the entries for that host only.
  - `@contextmanager temp_config(secrets_dir: Path, auths: Auths) -> Iterator[Path]`: creates a `mkdtemp` directory
    (mode 0700) under `secrets_dir`, writes `config.json` (0600, opened with `O_CREAT|O_EXCL`) as `{"auths": ...}`, with
    `docker.io` written under the key `https://index.docker.io/v1/`; removes the directory on exit, also on exception.
  - `clear(secrets_dir: Path) -> None`: removes every entry inside `secrets_dir` (not the directory itself); a missing
    directory is fine.

- [ ] **Step 1: Write the failing tests**: `test_parse_keeps_only_auths` (a config with `credHelpers`, `credsStore`,
  `HttpHeaders` keeps only `auths`), `test_docker_hub_keys_normalise` (all four spellings → `docker.io`, and
  `temp_config` writes `https://index.docker.io/v1/`), `test_host_with_port_kept` (`registry.example.com:5000`),
  `test_first_mounted_config_wins`, `test_bad_mounted_config_skipped` (missing, empty, `not json` files; caplog shows
  the
  path and no file content), `test_temp_config_modes_and_removal` (0700 dir, 0600 file, gone after the `with`),
  `test_temp_config_removed_on_exception`, `test_clear_empties_dir_keeps_it`, `test_parse_error_message_has_no_content`
  (a config whose bad JSON contains `s3cr3t`; the message does not).
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the suite and ruff; commit** `feat: merge mounted docker configs into a per-scan config`.

### Task 2: Pod pull secrets: names in the inventory, contents at scan time

**Files:**
- Create: `kubedelos/registry/pullsecrets.py`
- Modify: `kubedelos/config.py` (`pod_pull_secret_namespaces`), `kubedelos/kube/client.py` (`read_secret`),
  `kubedelos/models.py` (`InventoryItem.pull_secrets`), `kubedelos/kube/inventory.py`, `kubedelos/store/db.py`
  (migration 11), `kubedelos/store/repo.py` (`add_result`, `failed_items`)
- Test: `tests/registry/test_pullsecrets.py`, `tests/kube/test_inventory.py`, `tests/kube/test_client.py`,
  `tests/store/test_repo.py`

**Interfaces:**
- Consumes: `dockerconfig.parse`, `normalise_host`, `for_host`, `Auths` (Task 1).
- Produces:
  - `Settings.pod_pull_secret_namespaces: list[str] = []`.
  - `KubeApi.read_secret(ns: str, name: str) -> V1Secret` (`read_namespaced_secret` with `REQUEST_TIMEOUT`).
  - `InventoryItem.pull_secrets: list[tuple[str, str]] = []`: `(namespace, name)` in first-seen order, deduped; filled
    only for pods (not templates) in a listed namespace. Templates of CronJobs and scaled-to-zero workloads also carry
    their pod spec's `imagePullSecrets` when in a listed namespace.
  - Migration 11: `ALTER TABLE image_result ADD COLUMN pull_secrets TEXT;` (JSON, `NULL` when none).
    `Repo.add_result` stores it; `Repo.failed_items` restores it.
  - `class PullSecrets` with `__init__(self, api: KubeApi, namespaces: Collection[str])` and
    `auths_for(self, refs: list[tuple[str, str]], host: str) -> Auths`: reads each Secret at most once per instance (an
    in-memory dict, dropped with the instance at the end of the run), skips namespaces not listed (defence in depth),
    drops a non-`kubernetes.io/dockerconfigjson` Secret before touching `data`, decodes `.dockerconfigjson`, keeps
    `for_host(..., host)`, first ref wins. `ApiException` 403/404 and bad content: `logger.debug("pull secret %s/%s
    skipped: %s", ns, name, reason)` and continue.

- [ ] **Step 1: Write the failing tests**: `test_inventory_records_pull_secret_names_in_listed_namespaces` (two pods in
  `web` naming `regcred` and `other`, a pod in `jobs` not listed → its item has none),
  `test_pull_secrets_off_by_default`,
  `test_non_docker_secret_dropped_unread` (a `V1Secret` of type `Opaque` whose `data` is a property that fails the
  test when read), `test_missing_or_forbidden_secret_is_skipped` (404 and 403; caplog at debug shows `web/regcred`
  and no content), `test_only_the_image_host_is_kept`, `test_secret_read_once_per_run`,
  `test_unlisted_namespace_never_read`, `test_pull_secrets_from_two_namespaces`,
  `test_failed_items_keep_pull_secret_names` (round trip through the repo), and
  the migration test the store tests already use for each migration.
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.** Keep `collect` reading only what it reads today plus `spec.image_pull_secrets`.
- [ ] **Step 4: Run the suite and ruff; commit** `feat: read the pull secrets a pod names, in opted-in namespaces`.

### Task 3: Wire access into scans, retries, `registry test` and `serve`

**Files:**
- Create: `kubedelos/registry/access.py`
- Modify: `kubedelos/trivy/runner.py` (`scan_many` takes `access`), `kubedelos/scan/service.py`, `kubedelos/cli.py`
  (`registry test`, `_serve`)
- Test: `tests/registry/test_access.py`, `tests/trivy/test_runner.py`, `tests/scan/test_service.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces:
  - `@dataclass(frozen=True) class ScanAccess: docker_config: Path | None`.
  - `class RegistryAccess` with `__init__(self, settings: Settings, api: KubeApi | None = None)` (loads mounted configs
    once per run; builds `PullSecrets` when `api` and namespaces are given) and
    `@contextmanager for_item(self, item: InventoryItem) -> Iterator[ScanAccess]`: `docker_config` is a `temp_config`
    when `secrets_dir` is set and the
    merged auths for the host are non-empty, else `None`.
  - `RegistryAccess.none() -> RegistryAccess`: no configs (used where no settings apply, and in tests).
  - `scan_many(..., access: RegistryAccess | None = None)`: `work` enters `access.for_item(item)` around both attempts
    and passes `docker_config` to `scan_image` (its existing parameter).
  - `run_scan` builds `RegistryAccess(settings, api)`; `retry_failed` builds it with `kube_client.load(settings)` only
    when `settings.pod_pull_secret_namespaces` is set and a stored item has pull secrets (otherwise no API is loaded,
    keeping "the cluster is not read" for plain retries; update the docstring).
  - `registry test` uses `RegistryAccess(settings).for_item(...)` for its one image (on a laptop: no secrets dir, so
    nothing changes).
  - `_serve` calls `dockerconfig.clear(settings.secrets_dir)` before the
    worker starts, when `secrets_dir` is set.

- [ ] **Step 1: Write the failing tests**: `test_pull_secret_overrides_mounted_config` (same host in both; the written
      config holds the pull secret's entry),
  `test_no_file_without_secrets_dir`, `test_no_file_without_entries_for_host`,
  `test_temp_config_removed_when_scan_raises`
  (a `scan_image` stub that raises inside `scan_many`; the secrets dir is empty afterwards),
  `test_scan_many_passes_access_to_each_image` (stubbed `scan_image` records `docker_config` per ref),
  `test_serve_clears_secrets_dir_at_start`, `test_registry_test_uses_mounted_configs`.
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the full suite and ruff; commit** `feat: give each scan its registry credentials`.

### Task 4: Settings page: Registries section and "Test an image"

**Files:**
- Modify: `kubedelos/config.py` (`cloud_provider`, `cloud_identity`), `kubedelos/web/routes/settings.py`,
  `kubedelos/web/templates/settings.html`, `kubedelos/web/static/app.css`
  (only if the existing classes do not cover it)
- Create: `kubedelos/web/templates/partials/registry_test.html`
- Test: `tests/web/test_settings_page.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: `RegistryAccess` (Task 3), `scan_image`, `TrivyCache`, `ensure_trivy`, `cli` helpers `error_cause` and
  `login_hint` (move them only if importing from `cli` would be circular).
- Produces:
  - `Settings.cloud_provider: Literal["azure", "aws", "gcp", "none"] = "none"`, `Settings.cloud_identity: str | None`.
  - A "Registries" card, shown in both modes: cloud provider and identity (or "none: your own cloud logins apply" on
    the laptop), the registry hosts Trivy uses that identity for (fixed text per provider, from the spec), mounted
    Docker config files (the Secret name is the
    parent directory name), pull-secret namespaces (or "off").
  - `POST /settings/registry-test` (serve only; 404 in `ui` mode), form field `image`, HTMX target the card's result
    area. Validates the ref as `registry test` does; one at a time via a module `threading.Lock` (busy → "A test is
    already running"); Trivy timeout `min(scan_timeout_s, 120)`; renders `ok: <ref> is readable`, or the error kind,
    `error_cause`, and for `auth` the `login_hint` plus, for a cloud registry host, a pointer to the matching docs page.

- [ ] **Step 1: Write the failing tests**: `test_registries_card_shows_identity_not_tokens` (env holds
  `AZURE_FEDERATED_TOKEN_FILE` pointing at a file containing `tok3n`; the page shows the client id and never `tok3n`),
  `test_registry_test_refused_in_read_only` (403 from `install_serve`), `test_registry_test_needs_csrf`,
  `test_registry_test_rejects_bad_ref`, `test_registry_test_busy`, `test_registry_test_uses_mounted_configs` (stubbed
  `scan_image` gets the temporary `docker_config`), `test_registry_test_absent_in_ui_mode`.
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement**, following the existing card and form markup (the Scans form is the model for HTMX + CSRF).
- [ ] **Step 4: Run the suite and ruff, look at the page in a browser against a local `serve` on `kind-lab`; commit**
  `feat: show registry access on the settings page and test an image from it`.

### Task 5: Chart and image: presets, mounts, Roles, memory volume

**Files:**
- Modify: `charts/kubedelos/values.yaml`, `values.schema.json`, `templates/deployment.yaml`, `serviceaccount.yaml`,
  `configmap.yaml`, `_validate.tpl`, `NOTES.txt`, `ci/all-on-values.yaml`; `Dockerfile`; `scripts/image-smoke.sh`
- Create: `charts/kubedelos/templates/pullsecret-rbac.yaml`
- Test: `tests/chart/test_chart.py`

**Interfaces:**
- Values:
  ```yaml
  cloud:
    provider: none # azure | aws | gcp | none
    azure: { clientId: "" }
    aws: { roleArn: "" }
    gcp: { serviceAccount: "" }
  registries:
    dockerConfigSecrets: [] # kubernetes.io/dockerconfigjson Secrets in the release namespace, first wins
    podPullSecrets: false
    podPullSecretNamespaces: [] # required when podPullSecrets is on
  ```
- Rendering:
  - `azure`: SA annotation `azure.workload.identity/client-id: <clientId>`, pod label
    `azure.workload.identity/use: "true"`. `aws`: SA annotation `eks.amazonaws.com/role-arn`. `gcp`: SA annotation
    `iam.gke.io/gcp-service-account`. Merged with `serviceAccount.annotations` (the preset wins on a clash).
  - ConfigMap: `KUBEDELOS_CLOUD_PROVIDER`, `KUBEDELOS_CLOUD_IDENTITY` (when set),
    `KUBEDELOS_DOCKER_CONFIGS` (JSON list of `/etc/kubedelos/docker-configs/<name>/.dockerconfigjson`),
    `KUBEDELOS_POD_PULL_SECRET_NAMESPACES` (JSON, only when on).
  - Deployment: volume `secrets` (`emptyDir: {medium: Memory, sizeLimit: 16Mi}`) at `/run/kubedelos`; one read-only
    `secret` volume per `dockerConfigSecrets` entry (`items: [{key: .dockerconfigjson, path: .dockerconfigjson}]`,
    `defaultMode: 0400`) at `/etc/kubedelos/docker-configs/<name>`. The pod's `fsGroup` 65532 makes 0440 readable.
  - `pullsecret-rbac.yaml`: per listed namespace a Role (`get` on `secrets`, no `resourceNames`, no `list`/`watch`) and
    a RoleBinding to the chart's ServiceAccount. Nothing cluster-wide.
- Guards (`_validate.tpl`, each a clear `fail` message): the provider's id value empty when `cloud.provider` is not
  `none`; `podPullSecrets` on with empty namespaces; namespaces given with `podPullSecrets` off.
- Dockerfile: `ENV KUBEDELOS_SECRETS_DIR=/run/kubedelos`, `RUN mkdir /run/kubedelos && chown 65532:65532 /run/kubedelos
  && chmod 0700 /run/kubedelos`. The smoke test runs with `--read-only --tmpfs /run/kubedelos:uid=65532,mode=0700`.
- NOTES.txt: with pod pull secrets on, one line naming the namespaces and what it permits (spec 7.3).

- [ ] **Step 1: Write the failing chart tests**: one per rendering bullet (SA annotation and pod label per provider;
  ConfigMap keys; the memory volume with `sizeLimit: 16Mi`; a Secret volume per name in order; Roles only in the listed
  namespaces with exactly `verbs: ["get"]` on `secrets`; no ClusterRole change), one per guard, and
  `test_default_render_reads_no_secrets` (no Role, no Secret volume, ClusterRole unchanged).
- [ ] **Step 2: Run** `KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q`, **expect failures.**
- [ ] **Step 3: Implement**; extend `ci/all-on-values.yaml` so kubeconform covers the new objects.
- [ ] **Step 4: Run chart tests, `helm lint`, kubeconform on default and all-on, build the image and run
  `scripts/image-smoke.sh`; commit** `feat: add cloud identity presets and registry credentials to the chart`.

### Task 6: kind e2e with a private `registry:2`

**Files:**
- Modify: `scripts/e2e-chart.sh`, `tests/e2e/test_kind_chart.py`, `charts/kubedelos/ci/e2e-values.yaml`
- Create: `tests/e2e/registry/` (htpasswd generation in the script, manifests for the registry Deployment + Service)

**Approach (decided):** go-containerregistry, which Trivy uses, talks plain HTTP to RFC 1918 hosts, so the registry is a
`registry:2` Deployment with htpasswd auth behind a Service with a fixed ClusterIP (`10.96.200.50`, inside kind's
default service CIDR) on port 5000. The script pushes `nginx:1.19` there through `kubectl port-forward` to
`localhost:5000`, with test-only credentials generated in the run and never printed. Pods only need to *name* the image:
the kubelet does not have to pull it, because the inventory reads the pod spec.

Scenarios, each a pod in its own namespace naming `10.96.200.50:5000/e2e/nginx:1.19`:
- `e2e-mounted`: no pull secret; the release has `dockerConfigSecrets: [e2e-regcred]` → scanned (`status != 'error'`).
- `e2e-pull`: names `e2e-pull-cred` (listed namespace; the mounted config is for another host) → scanned.
- `e2e-unlisted`: names a valid pull secret, namespace not listed, and the mounted config does not cover it → `auth`
  error.
- `e2e-opaque`: names an `Opaque` Secret holding a valid `.dockerconfigjson` key → `auth` error (dropped unread).

- [ ] **Step 1: Extend the e2e test** to assert those four outcomes from the newest sweep's `image_result` rows, joined
  by workload namespace, and that `kubectl exec` finds `/run/kubedelos` empty after the sweep.
- [ ] **Step 2: Extend the script and values**; it still creates and deletes only `kubedelos-e2e`.
- [ ] **Step 3: Run `scripts/e2e-chart.sh` locally; expect PASS. Confirm `kind get clusters` lists only `lab` and
  `onboard-test` afterwards.**
- [ ] **Step 4: Commit** `test: cover registry credentials in the kind e2e with a private registry`.

### Task 7: Docs, AGENTS.md rule change, README, CHANGELOG, spec

**Files:**
- Create: `docs/registries/acr.md`, `docs/registries/ecr.md`, `docs/registries/gar.md`,
  `docs/registries/pull-secrets.md`
- Modify: `AGENTS.md`, `README.md`, `CHANGELOG.md`, `docs/in-cluster.md`, the spec

- [ ] **Step 1: Check in the Trivy v0.76.1 source** which wins for a host covered by both a cloud provider and a Docker
  config (spec "Left to the builder"), and what happens when the provider fails. Write the answer, with the source file,
  into each registry page and the spec.
- [ ] **Step 2: Write the three cloud pages as setup guides** an operator can follow start to finish, with
  placeholders only (`my-cluster`, `my-rg`, `myregistry`, `123456789012`, `my-project`). Each page has the same
  sections: *What you need* (cluster feature flags), *1. Create the identity*, *2. Let it read the registry*,
  *3. Link it to the kubedelos ServiceAccount* (the ServiceAccount is `<release>-kubedelos`, or the release name when it
  contains `kubedelos`, in the release namespace), *4. Install or upgrade the chart* (the exact values), *5. Check it*
  (the Settings page's Registries card and "Test an image", then a sweep), *Troubleshooting* (the auth errors you see
  and their usual cause), *Limits*. The CLI commands are `az`, `aws`/`eksctl` and `gcloud`; check every flag against the
  current docs of each CLI when writing (Microsoft Learn MCP for `az`).
  - `acr.md` (AKS): cluster with `--enable-oidc-issuer --enable-workload-identity`; a user-assigned managed identity;
    `AcrPull` on the registry (`az role assignment create --assignee-object-id ... --scope <acr id>`); a federated
    credential for `system:serviceaccount:<ns>:<sa>` against the cluster's OIDC issuer; values `cloud.provider: azure`,
    `cloud.azure.clientId`. Limits: an ACR behind a custom domain is not recognised by Trivy, so use a pull secret;
    attaching the ACR to the cluster (`az aks update --attach-acr`) grants the *kubelet* identity, not kubedelos's, and
    is not enough on its own.
  - `ecr.md` (EKS): IRSA (an OIDC provider for the cluster and an IAM role whose trust policy names the
    ServiceAccount, e.g. `eksctl create iamserviceaccount --role-only`), a policy with `ecr:GetAuthorizationToken`,
    `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` (or `AmazonEC2ContainerRegistryReadOnly`); values
    `cloud.provider: aws`, `cloud.aws.roleArn`. Note EKS Pod Identity as an alternative only if Trivy's AWS SDK
    version supports its credential source (check `go.mod`); otherwise say IRSA is required.
  - `gar.md` (GKE): Workload Identity Federation for GKE on the cluster and node pool; a Google service account with
    `roles/artifactregistry.reader` (and `roles/storage.objectViewer` for legacy `gcr.io` buckets); the
    `roles/iam.workloadIdentityUser` binding for `<project>.svc.id.goog[<ns>/<sa>]`; values `cloud.provider: gcp`,
    `cloud.gcp.serviceAccount`.
  - Each page states which hosts Trivy uses the identity for (from the spec), and that the identity never goes
    anywhere else, so which registries kubedelos can read is decided by the role assignment in step 2.
- [ ] **Step 3: Write `pull-secrets.md`**: mounted Docker config Secrets (create one with `kubectl create secret
  docker-registry`, list it in `registries.dockerConfigSecrets`, no Secret RBAC needed) and opt-in pod pull secrets
  (`registries.podPullSecrets`, the namespaces, the Roles it creates), the precedence from Step 1 and ruling 3, and the
  security note from spec 7.3 in substance.
- [ ] **Step 4: AGENTS.md:** replace the two rules exactly as spec 7.5 states them. README: a short "Private registries"
  section linking the four pages. `docs/in-cluster.md`: replace the "not in the chart yet" paragraph, add the new values
  and the memory volume. CHANGELOG `## Unreleased`: one entry per user-visible change. Spec: record rulings 2 and 3
  under "Decisions recorded here".
- [ ] **Step 5: Run pre-commit; commit** `docs: document registry login for acr, ecr, gar and pull secrets`.
