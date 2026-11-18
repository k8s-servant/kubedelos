# kubedelos container image and Helm chart Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `kubedelos serve` as a hardened container image with the pinned Trivy inside it, plus a Helm chart that
deploys it into one cluster, sweeps that cluster on schedule, and refuses unsafe identity-header setups.

**Architecture:**
- **Image.** A multi-stage `Dockerfile` on `python:3.13-alpine` (pinned by digest). The build stage installs the wheel
  into a venv and installs the pinned Trivy with `kubedelos trivy install`, so the SHA-256 check is the same code
  path. The final stage runs `kubedelos serve` as `65532:65532` and works on a read-only root filesystem.
- **Bundled Trivy.** A new setting, `KUBEDELOS_TRIVY_DIR`, points at the read-only copy baked into the image. Runs
  record the pinned version, not `custom`.
- **Chart.** `charts/kubedelos/` holds the Deployment, Service, PVC, ServiceAccount, ClusterRole, ConfigMap and
  NetworkPolicy, plus optional Ingress and HTTPRoute templates. `fail` guards refuse header trust unless the
  NetworkPolicy restricts ingress, and `NOTES.txt` warns about open exposure.
- **Tests.** pytest tests render the chart with `helm template`. A shell smoke test runs the image. A kind e2e installs
  the chart and waits for a sweep. CI runs all three, and the release workflow signs and pushes the image and the chart.

**Tech Stack:** Python 3.12+, Docker Buildx, Helm (chart `apiVersion: v2`), kubeconform, kind, cosign, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md`:
- section 4: the trust boundary, CSRF, Hosts and `NOTES.txt`;
- section 5: Container image;
- section 6: Helm chart;
- "Delivery" item 3.

Carried from the PR 2 reviews: a `Secure` flag on the CSRF cookie, and the NetworkPolicy guard before
`trustProxyHeaders` is documented.

## Rulings made while planning (record them in the spec in Task 7)

- **Cloud presets (`cloud.provider`) move to PR 4.** Turning on workload identity before `registries.cloudHosts` and
  the environment scrubbing exist would let the pod's identity reach registries the operator did not name, which is an
  anti-goal.
- **`KUBEDELOS_SECRETS_DIR` and its memory-backed `emptyDir` move to PR 4.** They are used only by the per-scan Docker
  config.
- **`KUBEDELOS_TRIVY_DIR` replaces "`KUBEDELOS_TRIVY_PATH` set to `/usr/local/bin/trivy`".** A set `trivy_path`
  labels every run `custom` (`scan/service.py`), and the retry check compares against that label.
- **`KUBEDELOS_SECURE_COOKIES`** (default `false`; chart value `secureCookies`, default `true`) adds `Secure` to the
  serve CSRF cookie. Browsers accept `Secure` cookies on `http://localhost`, so `kubectl port-forward` still works.
- **The trust guard also refuses** an `ipBlock` whose `cidr` is `0.0.0.0/0` or `::/0`. Such an entry admits every pod,
  just like `{}`.
- **The CI image scan fails only on fixable `CRITICAL` findings** (`--severity CRITICAL --ignore-unfixed`). Anything
  stricter would block every PR on the base image's release cadence.

## Global Constraints

- Trivy v0.76.1, verified against `kubedelos/trivy/pins.py`; never "latest"; `--scanners vuln` only.
- Read-only cluster access: the ClusterRole has `get`/`list` on `namespaces`, `pods` and `nodes`, and `list` on
  `deployments`, `statefulsets` and `cronjobs`, nothing else. No Secret RBAC in this PR.
- Image: `python:3.13-alpine@sha256:<digest at PR time>`, user `65532:65532`, `KUBEDELOS_DATA_DIR=/data`,
  `KUBEDELOS_CACHE_DIR=/data/cache`, `TMPDIR=/tmp`, entrypoint `kubedelos serve`, platforms `linux/amd64` and
  `linux/arm64`. Only `/data` and `/tmp` are written.
- Deployment: `replicas: 1` (not a value), `strategy: Recreate`, `runAsNonRoot`, `readOnlyRootFilesystem`, all
  capabilities dropped, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: true`, probes on `/healthz`,
  `terminationGracePeriodSeconds` 60.
- Service: ClusterIP, port 80 to 8080. PVC: RWO, `10Gi` by default.
- NetworkPolicy: on by default; ingress only from `networkPolicy.ingressFrom`; egress open unless
  `networkPolicy.egress` is set.
- Ingress and HTTPRoute are both off by default. The chart forces no proxy, gateway or Ingress controller.
- GitHub Actions: every action pinned to a full SHA with a `# vX.Y.Z` comment, `permissions: {}` at the top, least
  privilege per job, `persist-credentials: false`, never `aquasecurity/trivy-action`. Downloaded tools (helm,
  kubeconform, kind) are checksum-verified, as the gitleaks job does.
- Public repo: placeholders only (`example.com`, `my-cluster`); never an internal name or registry.
- Python changes: TDD, one test file per module, ruff 120, a module docstring. Conventional lowercase commits, no
  attribution lines. `CHANGELOG.md` under `## Unreleased`.
- Never scan the user's real clusters or registries: kind clusters named `kubedelos-*` and public images only.

## Review Focus

1. **A list value in the ConfigMap.** `namespaces: [web, jobs]` must reach pydantic as JSON (`["web","jobs"]`), and
   `extraAllowedHosts` as a comma list. Rendering one wrongly means a sweep of all namespaces or a 400 on every page.
   Task 3 tests both.
2. **The Host the browser sends.** With an Ingress host `kubedelos.example.com`, that host must be in
   `KUBEDELOS_ALLOWED_HOSTS`, or every page is a 400. Task 4 tests the Ingress, HTTPRoute, extra and Service names.
3. **A selector that looks narrow but admits everything:** `{podSelector: {}}`, `{namespaceSelector: {}}`,
   `{podSelector: {matchLabels: {}}}`, `{}`, or `ipBlock 0.0.0.0/0`. With trust on, each must fail to render. Task 4
   tests each one.
4. **A fresh PVC.** The volume is mounted empty and owned by root. `fsGroup: 65532` must let the pod create
   `/data/cache` and the DB. Task 6's e2e proves it on kind.
5. **A missing `clusterName`.** `helm install` must fail with a clear message, not deploy a pod that crash-loops on
   "KUBEDELOS_CLUSTER_NAME is required". Task 3 tests it.

---

### Task 1: Secure CSRF cookie and bundled Trivy settings

**Files:**
- Modify: `kubedelos/config.py`, `kubedelos/web/security.py:279-280`, `kubedelos/trivy/binary.py`
- Test: `tests/test_config.py`, `tests/web/test_security.py`, `tests/trivy/test_binary.py`

**Interfaces:**
- Produces: `Settings.secure_cookies: bool = False` (env `KUBEDELOS_SECURE_COOKIES`) and
  `Settings.trivy_dir: Path | None = None` (env `KUBEDELOS_TRIVY_DIR`). Tasks 2 and 3 set them through the image and
  the chart.

- [ ] **Step 1: Write the failing tests**

```python
# tests/web/test_security.py
def test_serve_csrf_cookie_is_secure_when_configured(make_serve_client):
    client = make_serve_client(secure_cookies=True)
    cookie = client.get("/").headers["set-cookie"]
    assert "kubedelos_csrf=" in cookie and "Secure" in cookie

def test_serve_csrf_cookie_is_not_secure_by_default(serve_client):
    assert "Secure" not in serve_client.get("/").headers["set-cookie"]

# tests/trivy/test_binary.py
def test_bundled_trivy_is_used_and_never_downloaded(tmp_path):
    bundled = tmp_path / "bundled" / TRIVY_VERSION / "trivy"
    bundled.parent.mkdir(parents=True); bundled.write_text("#!/bin/sh\n"); bundled.chmod(0o755)
    settings = Settings(trivy_dir=tmp_path / "bundled", cache_dir=tmp_path / "cache")
    assert ensure_trivy(settings, client=_failing_client()) == bundled

def test_bundled_trivy_dir_without_the_pinned_version_falls_back_to_the_cache(tmp_path): ...
    # trivy_dir set but <dir>/<version>/trivy missing: the cached path is returned (seed it), no download

# tests/test_config.py
def test_secure_cookies_and_trivy_dir_from_env(monkeypatch): ...
```

`_failing_client()` is an `httpx.Client` over a `MockTransport` that fails the test if it is called. Reuse the file's
existing helper if there is one.

- [ ] **Step 2: Run them and see them fail:** `.venv/bin/pytest tests/web/test_security.py tests/trivy/test_binary.py tests/test_config.py -q`
- [ ] **Step 3: Implement.**
  - `ensure_trivy` checks, in order: `trivy_path`, then `<trivy_dir>/<TRIVY_VERSION>/trivy` if it is executable, then
    the cache, then a download.
  - `scan/service.py` keeps labelling only a set `trivy_path` as `custom`, so a bundled binary records `0.76.1`.
  - The serve CSRF `set_cookie` passes `secure=settings.secure_cookies`; update the comment above it. The laptop
    session cookie stays as it is.
- [ ] **Step 4: Run the full suite:** `.venv/bin/pytest -q`, then ruff. All pass.
- [ ] **Step 5: Commit:** `feat: add a bundled trivy directory and an optional secure csrf cookie`

### Task 2: Dockerfile and image smoke test

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `scripts/image-smoke.sh`
- Modify: `.github/dependabot.yml` (add a `docker` ecosystem entry for `/`, the same cooldown, prefix `build(deps)`,
  label `dependencies`)

**Interfaces:**
- Consumes: `KUBEDELOS_TRIVY_DIR` (Task 1).
- Produces: image paths that Tasks 3 and 5 rely on: the bundled Trivy at
  `/usr/local/lib/kubedelos/trivy/0.76.1/trivy`, `KUBEDELOS_TRIVY_DIR=/usr/local/lib/kubedelos/trivy`, user
  `65532:65532`, port 8080, and the entrypoint `["kubedelos", "serve"]`.
  `scripts/image-smoke.sh IMAGE` exits 0 when the checks pass.

- [ ] **Step 1: Write `scripts/image-smoke.sh IMAGE`** (`set -euo pipefail`, header comment). It fails on the first
  problem. Every container runs with `--read-only --tmpfs /tmp --user 65532:65532` and a named volume on `/data`,
  which the script removes on exit. The checks:
  - `docker run IMAGE version` prints `0.76.1` in its Trivy line. Check what `kubedelos version` prints and match it.
  - `docker run -d -e KUBEDELOS_CLUSTER_NAME=my-cluster -e KUBEDELOS_SWEEP_ENABLED=false -e KUBEDELOS_KUBECONFIG=/kc
    -v <a minimal kubeconfig pointing at https://127.0.0.1:1>:/kc:ro IMAGE`. Then `/healthz` answers 200 within 30 s.
    Use `docker exec … python -c` with urllib, since there is no curl. If `serve` refuses an unreachable kubeconfig
    at start-up, point it at a running kind cluster instead.
  - `docker exec … id -u` prints `65532`.
  - After 10 s, the container's logs contain no traceback.
- [ ] **Step 2: Run it against a missing image to see it fail:** `scripts/image-smoke.sh kubedelos:none` exits non-zero.
- [ ] **Step 3: Write the `Dockerfile`.**
  - **Builder stage** (same base): `pip install build`, then build the wheel, then
    `python -m venv /opt/kubedelos && /opt/kubedelos/bin/pip install dist/*.whl`.
  - Then `KUBEDELOS_CACHE_DIR=/build/cache /opt/kubedelos/bin/kubedelos trivy install`, and copy the binary to
    `/usr/local/lib/kubedelos/trivy/0.76.1/`. Read the version from `pins.py`, not a literal.
  - **Final stage:** the venv and the Trivy directory. `PATH` includes `/opt/kubedelos/bin`.
    `PYTHONDONTWRITEBYTECODE=1`, plus the Global Constraints env vars and `KUBEDELOS_TRIVY_DIR`. `USER 65532:65532`,
    `EXPOSE 8080`, `ENTRYPOINT ["kubedelos", "serve"]`. OCI labels: `source`, `licenses=Apache-2.0`.
  - `.dockerignore` keeps out `.git`, `.venv`, `.worktrees`, `build`, `*.egg-info`, `.superpowers`, `tests` and `docs`.
  - Pin the base image by its multi-arch index digest:
    `docker buildx imagetools inspect python:3.13-alpine --format '{{json .Manifest.Digest}}'`.
- [ ] **Step 4: Build and smoke-test locally:** `docker buildx build --load -t kubedelos:dev . && scripts/image-smoke.sh kubedelos:dev`.
  Expected: exit 0. Also check that `docker buildx build --platform linux/arm64,linux/amd64 .` builds.
- [ ] **Step 5: Commit:** `build: add the container image with the pinned trivy bundled`

### Task 3: Chart core (Deployment, Service, PVC, RBAC, ConfigMap, schema)

**Files:**
- Create: `charts/kubedelos/{Chart.yaml,values.yaml,values.schema.json,.helmignore}` and
  `charts/kubedelos/templates/{_helpers.tpl,deployment.yaml,service.yaml,pvc.yaml,serviceaccount.yaml,clusterrole.yaml,clusterrolebinding.yaml,configmap.yaml}`
- Test: `tests/chart/test_chart.py` (with an empty `tests/chart/__init__.py` if the tests tree uses them)

**Interfaces:**
- Produces, for Task 4:
  - `values.yaml` keys, exactly:

    ```yaml
    image: {repository: ghcr.io/k8s-servant/kubedelos, tag: "", digest: "", pullPolicy: IfNotPresent}
    imagePullSecrets: []
    clusterName: ""            # required
    scope: {namespaces: [], excludeNamespaces: [], namespaceSelector: "", selector: "", excludeImages: []}
    sweep: {enabled: true, schedule: "0 3 * * *", timezone: UTC}
    retentionDays: 180
    scan: {parallelism: 4, timeoutSeconds: 600}
    readOnly: false
    auth: {trustProxyHeaders: false, identityHeader: X-Auth-Request-Email}
    secureCookies: true
    extraAllowedHosts: []
    clusterDomain: cluster.local
    logLevel: info
    persistence: {size: 10Gi, storageClassName: "", existingClaim: ""}
    resources: {requests: {cpu: 100m, memory: 512Mi}, limits: {memory: 2Gi}}
    serviceAccount: {annotations: {}}
    podAnnotations: {}
    podLabels: {}
    nodeSelector: {}
    tolerations: []
    affinity: {}
    networkPolicy: {enabled: true, ingressFrom: [], egress: []}
    ingress: {enabled: false, className: "", annotations: {}, hosts: [], tls: []}
    httpRoute: {enabled: false, parentRefs: [], hostnames: [], annotations: {}}
    ```

  - Helpers `kubedelos.fullname`, `kubedelos.labels`, `kubedelos.selectorLabels`, and `kubedelos.allowedHosts`, which
    returns the comma list. Task 3 seeds the list with the Service names; Task 4 adds the rest.
  - The test helpers `render(values: dict | None = None) -> list[dict]` (the documents of `helm template t
    charts/kubedelos -n kd -f <tmp values>`), `kind(docs, "Deployment") -> dict` and `render_error(values) -> str`
    (stderr of a failed render).
  - The tests skip when `helm` is not on `PATH`, unless `KUBEDELOS_REQUIRE_HELM=1` is set (CI sets it), in which case
    they fail.

- [ ] **Step 1: Write the failing tests** in `tests/chart/test_chart.py`. Each one renders with
  `clusterName: my-cluster` unless it says otherwise:
  - `test_missing_cluster_name_fails_to_render`: `render_error({})` contains `clusterName is required`.
  - `test_deployment_is_one_hardened_replica`: `replicas == 1`, `strategy.type == "Recreate"`.
    - Pod: `runAsNonRoot`, `runAsUser == 65532`, `fsGroup == 65532`, `seccompProfile.type == "RuntimeDefault"`.
    - Container: `readOnlyRootFilesystem`, `allowPrivilegeEscalation is False`, `capabilities.drop == ["ALL"]`.
    - `automountServiceAccountToken is True`, `terminationGracePeriodSeconds == 60`.
    - Liveness and readiness probes are `httpGet` on `/healthz`, port `http`.
    - Mounts: `/data` from the PVC and `/tmp` from an `emptyDir`.
  - `test_replicas_is_not_a_value`: `render_error({"replicas": 2})` fails, because the schema has
    `additionalProperties: false` at the top level.
  - `test_image_defaults_to_app_version_and_digest_wins`: the default tag is `Chart.appVersion`; with a digest set,
    the image is `repo@sha256:…`.
  - `test_service_maps_80_to_8080`.
  - `test_pvc_defaults_and_existing_claim`: `10Gi` RWO by default; with `existingClaim`, no PVC is rendered and the
    Deployment uses that claim.
  - `test_clusterrole_is_read_only_and_exact`: the rules equal the Global Constraints list exactly. Verb sets are
    compared as sets. There is no `secrets`, `create`, `update`, `patch`, `delete` or `watch`.
  - `test_configmap_env`:
    - `KUBEDELOS_CLUSTER_NAME == "my-cluster"`.
    - With `scope.namespaces: [web, jobs]`, `json.loads(KUBEDELOS_NAMESPACES) == ["web", "jobs"]`, and the same for
      the exclude and image lists.
    - Empty selectors are left out rather than set to `""`.
    - `KUBEDELOS_SWEEP_*`, `KUBEDELOS_RETENTION_DAYS`, `KUBEDELOS_READ_ONLY`, `KUBEDELOS_TRUST_PROXY_HEADERS`,
      `KUBEDELOS_IDENTITY_HEADER`, `KUBEDELOS_SECURE_COOKIES`, `KUBEDELOS_PARALLELISM`, `KUBEDELOS_SCAN_TIMEOUT_S` and
      `KUBEDELOS_LOG_LEVEL` are all set.
    - Every value is a string.
  - `test_configmap_values_load_as_settings`: feed the rendered ConfigMap's data, as the environment, into
    `Settings()` via monkeypatch. It loads, and `namespaces == ["web", "jobs"]`. This is the Review Focus 1 pin.
  - `test_allowed_hosts_include_the_service_names`: `kubedelos-t`, `kubedelos-t.kd`, `kubedelos-t.kd.svc` and
    `kubedelos-t.kd.svc.cluster.local`. Adjust the names to what `fullname` gives for release `t`.
  - `test_deployment_rolls_on_config_change`: a `checksum/config` pod annotation that changes when a value changes.
- [ ] **Step 2: Run them and see them fail:** `KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q`.
- [ ] **Step 3: Write the chart.**
  - `Chart.yaml`: `apiVersion: v2`, `name: kubedelos`, `version: 0.0.0`, `appVersion: "0.0.0"`, `type: application`,
    `kubeVersion: ">=1.29.0-0"`, `home`, `sources`, `license: Apache-2.0`.
  - Required values use `required`. The Deployment's `envFrom` names the ConfigMap. Container port `http` is 8080.
    Default resources are as in `values.yaml`.
  - `values.schema.json` types every key and sets `additionalProperties: false` at the top level and on each object.
- [ ] **Step 4: Verify.**
  - `KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q` passes.
  - `helm lint charts/kubedelos --set clusterName=my-cluster` is clean.
  - `helm template t charts/kubedelos --set clusterName=my-cluster | kubeconform -strict -summary` reports no errors.
- [ ] **Step 5: Commit:** `feat: add the helm chart for kubedelos serve`

### Task 4: Exposure, NetworkPolicy, trust guards and NOTES.txt

**Files:**
- Create: `charts/kubedelos/templates/{networkpolicy.yaml,ingress.yaml,httproute.yaml,_validate.tpl,NOTES.txt}`
- Modify: `charts/kubedelos/templates/_helpers.tpl` (`kubedelos.allowedHosts`), `values.schema.json`
- Test: `tests/chart/test_chart.py`

**Interfaces:**
- Consumes: the Task 3 values and test helpers.
- Produces: `kubedelos.validate` (included from `deployment.yaml`), which fails the render for the cases below.

- [ ] **Step 1: Write the failing tests:**
  - `test_networkpolicy_on_by_default_admits_nothing`: one NetworkPolicy selecting the pod, with
    `policyTypes == ["Ingress"]` and `ingress == []`. Egress is unrestricted: the policy type is absent.
  - `test_networkpolicy_ingress_from_and_egress`: `ingressFrom` entries become `ingress[0].from`, on port 8080. A set
    `egress` adds `Egress` to `policyTypes`, with those rules.
  - `test_trust_requires_a_restricting_networkpolicy`, parametrized:
    - `networkPolicy.enabled: false`;
    - `ingressFrom: []`;
    - `[{}]`;
    - `[{podSelector: {}}]`;
    - `[{podSelector: {matchLabels: {}}}]`;
    - `[{namespaceSelector: {}}]`;
    - `[{namespaceSelector: {}, podSelector: {matchLabels: {app: proxy}}}]`;
    - `[{ipBlock: {cidr: 0.0.0.0/0}}]`;
    - `[{ipBlock: {cidr: "::/0"}}]`.

    With `auth.trustProxyHeaders: true`, every one of them fails, and the stderr names `networkPolicy.ingressFrom`.
  - `test_trust_renders_with_a_named_proxy`: `[{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name:
    auth}}, podSelector: {matchLabels: {app: oauth2-proxy}}}]` renders.
  - `test_ingress_and_allowed_hosts`: with `ingress.enabled` and `hosts: [{host: kubedelos.example.com}]`, the
    Ingress routes `/` (`Prefix`) to the Service on port 80, and its className, annotations and tls are passed
    through. `kubedelos.example.com` is in `KUBEDELOS_ALLOWED_HOSTS`.
  - `test_httproute_and_allowed_hosts`: an `HTTPRoute` (`gateway.networking.k8s.io/v1`) with `parentRefs` and
    `hostnames` passed through, and a backendRef to the Service on port 80. The hostnames are in
    `KUBEDELOS_ALLOWED_HOSTS`.
  - `test_extra_allowed_hosts`.
  - `test_notes`, run with `helm install --dry-run` or `helm template --show-notes`, whichever the pinned helm
    supports:
    - **Exposed, trust off:** an Ingress or HTTPRoute on with trust off warns that anyone who can reach the host can
      read the whole vulnerability inventory. Unless `readOnly` is set, it adds that they can start scans and accept
      risks, unless the operator's proxy guards it.
    - **Writes open, trust off:** writes open and trust off warns that accepting risks hides findings.
    - **Trust on:** trust on names both bypasses, `kubectl port-forward` and a CNI that does not enforce
      NetworkPolicy.
    - **Read-only:** `readOnly: true` drops the write warnings.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.**
  - **Empty selector:** a selector counts as empty when it has neither non-empty `matchLabels` nor non-empty
    `matchExpressions`.
  - **An entry admits every pod when** it:
    - has no keys;
    - has an empty `namespaceSelector`;
    - has an empty `podSelector` and no `namespaceSelector`;
    - is an `ipBlock` with cidr `0.0.0.0/0` or `::/0`.
  - **Allowed hosts:** the Service names, then the Ingress hosts, then the HTTPRoute hostnames, then
    `extraAllowedHosts`, deduplicated.
- [ ] **Step 4: Verify.** The tests pass, `helm lint` is clean, and kubeconform passes with Ingress and NetworkPolicy
  on. Validate the HTTPRoute with kubeconform's `-schema-location` for the Gateway API CRDs, or skip that kind with
  `-skip HTTPRoute` and say so in the report.
- [ ] **Step 5: Commit:** `feat: guard header trust with the networkpolicy and add ingress and httproute`

### Task 5: CI and release jobs

**Files:**
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release-please.yml`, `release-please-config.json`

**Interfaces:**
- Consumes: `scripts/image-smoke.sh` (Task 2), `tests/chart` (Task 3), and `scripts/e2e-chart.sh` (Task 6, whose job is
  added there).

- [ ] **Step 1: `ci.yml`: add a `chart` job** (`contents: read`).
  - Install helm and kubeconform at pinned versions, checksum-verified. Use the current stable releases, and put the
    versions in `env` as the gitleaks job does.
  - `helm lint charts/kubedelos --set clusterName=my-cluster`.
  - `pip install -e '.[dev]'`, then `KUBEDELOS_REQUIRE_HELM=1 pytest tests/chart -q --no-cov`.
  - `helm template … | kubeconform -strict -summary` for the default values and for an "everything on" values file.
    Keep that file at `charts/kubedelos/ci/all-on-values.yaml`.
- [ ] **Step 2: `ci.yml`: add an `image` job** (`contents: read`).
  - Set up Buildx with `docker/setup-buildx-action` (pinned SHA).
  - Build `linux/amd64` with `--load -t kubedelos:ci` and run `scripts/image-smoke.sh kubedelos:ci`.
  - Then build `linux/arm64` without loading it, through `docker/setup-qemu-action` (pinned).
  - Scan the image with the pinned Trivy: `pip install -e .`, then `kubedelos trivy install`. Run the binary it
    prints with `image --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 kubedelos:ci`.
  - Add `chart` and `image` to the `result` job's `needs`.
- [ ] **Step 3: `release-please.yml`: replace the Phase 3 placeholder with three jobs.**
  - **`image`:**
    - `needs: release-please`, gated on `release_created`, not on `PUBLISH_ENABLED`.
    - Permissions: `contents: read`, `packages: write`, `id-token: write`.
    - Log in to GHCR with `GITHUB_TOKEN`.
    - `docker/build-push-action` with both platforms, `provenance: mode=max` and `sbom: true`. Tags:
      `ghcr.io/k8s-servant/kubedelos:<version>` and `:<major>.<minor>`.
    - `cosign sign --yes <repo>@<digest>`, keyless, through `sigstore/cosign-installer` (pinned).
    - Output: the digest.
  - **`chart`:**
    - `needs: [release-please, image]`.
    - Permissions: `contents: read`, `packages: write`, `id-token: write`.
    - `helm package charts/kubedelos`, using the version from release-please. Then
      `helm push … oci://ghcr.io/k8s-servant/charts` and `cosign sign` the pushed chart digest.
  - Comment each job the way the existing ones are commented.
- [ ] **Step 4: `release-please-config.json`:** add `extra-files` for `charts/kubedelos/Chart.yaml` (`type: yaml`,
  `jsonpath: $.version` and `$.appVersion`). Check the schema URL's documentation for the exact shape.
- [ ] **Step 5: Verify.**
  - `actionlint` and `zizmor` on the changed workflows are clean. Run them locally if they are installed; otherwise
    the PR's Security workflow checks them.
  - `pre-commit run --all-files` passes.
- [ ] **Step 6: Commit:** `ci: build, smoke-test and scan the image, check the chart, and sign both on release`

### Task 6: kind e2e that installs the chart and waits for a sweep

**Files:**
- Create: `scripts/e2e-chart.sh`, `tests/e2e/test_kind_chart.py`, `charts/kubedelos/ci/e2e-values.yaml`
- Modify: `.github/workflows/ci.yml` (an `e2e-chart` job)

**Interfaces:**
- Consumes: the image (Task 2) and the chart (Tasks 3 and 4).

- [ ] **Step 1: Write `tests/e2e/test_kind_chart.py`**, following `tests/e2e/test_kind_scan.py`:
  - `pytestmark = pytest.mark.e2e`; skip without docker.
  - Run the script in its own process group, killed on timeout so its trap deletes the cluster.
  - Assert exit 0 and that stdout has a line `sweep run <n>: ok` or `sweep run <n>: partial`.
- [ ] **Step 2: Write `scripts/e2e-chart.sh`**, following `scripts/e2e-kind.sh`:
  - Use the cluster `kubedelos-e2e-chart`. Refuse to reuse an existing one. Use a temporary kubeconfig and delete the
    cluster in the EXIT trap.
  - Build `kubedelos:e2e`, `kind load` it, and create the `web` namespace with `nginx:1.19`, as the existing script
    does.
  - `helm install kd charts/kubedelos -n kubedelos --create-namespace -f charts/kubedelos/ci/e2e-values.yaml
    --set image.repository=kubedelos,image.tag=e2e,image.pullPolicy=Never --wait`.
  - `e2e-values.yaml` holds:
    - `clusterName: kind-e2e`;
    - `scope.namespaces: [web]`;
    - `sweep.schedule: "* * * * *"`;
    - `extraAllowedHosts: [localhost]`;
    - `secureCookies: false`;
    - the NetworkPolicy left on.
  - Poll for up to 15 minutes, as long as the first Trivy DB download may take. Read the newest run's status with
    `kubectl exec deploy/kd-kubedelos -- python -c` through `sqlite3` against `/data/kubedelos.db`, read-only URI.
    Print `sweep run <id>: <status>`, and exit 0 on `ok` or `partial`, 1 on `failed`.
  - On failure, print `kubectl logs` and `describe pod`.
- [ ] **Step 3: Run it locally:** `.venv/bin/pytest -m e2e tests/e2e/test_kind_chart.py -q`. Expected: pass.
  Afterwards, `kind get clusters` no longer lists `kubedelos-e2e-chart`.
- [ ] **Step 4: Add the `e2e-chart` CI job.**
  - Permissions: `contents: read`.
  - Install pinned, checksum-verified kind and helm. kubectl is on the runner image.
  - Run the script with `timeout-minutes: 30`.
  - Run it on `pull_request` and `push`, and add it to `result.needs`.
- [ ] **Step 5: Commit:** `test: install the chart on kind and wait for a sweep`

### Task 7: Docs, changelog and spec updates

**Files:**
- Create: `docs/in-cluster.md`, `docs/exposure-oauth2-proxy-envoy-gateway.md`
- Modify: `README.md`, `CHANGELOG.md`, `AGENTS.md` (the Commands block: the chart tests and the image smoke test),
  `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md` (the rulings above)

- [ ] **Step 1: `docs/in-cluster.md`.**
  - Install with `helm install … oci://ghcr.io/k8s-servant/charts/kubedelos --set clusterName=my-cluster`.
  - The values table: every key from Task 3, with its default and what it does.
  - Storage sizing (the Java DB alone is about 1 GB).
  - Exposure options: port-forward, Ingress, HTTPRoute.
  - The security model:
    - Writes are open by default; `readOnly` turns them off.
    - The trust boundary: the proxy must overwrite the header, and only the proxy may reach the pod.
    - The guard and what it refuses.
    - The two bypasses: `kubectl port-forward` RBAC, and a CNI that does not enforce NetworkPolicy.
    - Why `secureCookies` defaults to `true`, and what to do when the browser reaches the UI over plain HTTP on a
      host other than localhost.
  - Verifying the release with `cosign verify` for the image and the chart, keyless, with the identity of
    `release-please.yml` on `main`.
- [ ] **Step 2: `docs/exposure-oauth2-proxy-envoy-gateway.md`.** It is a worked example, not chart templates.
  - Pin the current oauth2-proxy version.
  - An Envoy Gateway `SecurityPolicy` with ext auth to oauth2-proxy, using `headersToBackend: [X-Auth-Request-Email]`
    and `failOpen: false`. Before writing that `headersToBackend` overwrites a client's copy of the header, confirm
    it in the Envoy Gateway source and cite the file. If it does not, say what does.
  - oauth2-proxy with `--set-xauthrequest` and a group restriction.
  - The kubedelos values: `auth.trustProxyHeaders: true`, plus `networkPolicy.ingressFrom` naming the Envoy proxy
    pods.
  - Placeholders only: `kubedelos.example.com`, `auth.example.com`.
- [ ] **Step 3: README, CHANGELOG and AGENTS.md.**
  - README: replace any "comes with the Helm chart" wording, and link the two docs.
  - CHANGELOG, under `## Unreleased` (Features):
    - the image;
    - the chart;
    - the guards;
    - `KUBEDELOS_TRIVY_DIR` and `KUBEDELOS_SECURE_COOKIES`.
  - AGENTS.md: the commands for the chart tests and the image smoke test.
- [ ] **Step 4: The spec.**
  - Section 4: add the `Secure` cookie setting.
  - Section 5: replace `KUBEDELOS_TRIVY_PATH`/`/usr/local/bin/trivy` with `KUBEDELOS_TRIVY_DIR`, and move
    `KUBEDELOS_SECRETS_DIR` to section 7.
  - Section 6: move the cloud presets to section 7, and add the `ipBlock` guard.
  - Delivery: PR 4 gains the cloud presets and the secrets volume.
- [ ] **Step 5: Verify:** `pre-commit run --all-files` passes, and every link in the new docs resolves.
- [ ] **Step 6: Commit:** `docs: document the in-cluster install, exposure and security model`
