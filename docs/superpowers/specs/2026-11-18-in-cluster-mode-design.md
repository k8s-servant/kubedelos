# kubedelos in-cluster mode (Phase 3) design

Covers #12 (serve, scheduler), #24 (scheduled sweeps and on-demand scans), #13 (Helm chart and image) and #14
(in-cluster registry login). Notifications (#15) stay in Phase 4. The main spec is
`docs/superpowers/specs/2026-11-13-kubedelos-design.md`; where this document differs from it, this one wins.

## Intent

kubedelos runs inside each cluster it watches. It sweeps the cluster on a schedule, keeps the history, and serves the
same UI the laptop has. Sign-in is not kubedelos's job. How the UI is exposed and who signs users in is the operator's
choice: any authenticating proxy that puts the user in a request header works, for example
oauth2-proxy behind Envoy Gateway, an Ingress controller's external auth, or a service mesh. kubedelos only trusts that
header when told to.

Who uses it and for what:
- Most people **view** results: dashboard, findings, compare, reports.
- **Sweeps run on a schedule.**
- A user can also **start a scan now** and **make a report** (CSV and print-friendly HTML, as today).

## Goals

1. `kubedelos serve`: the UI, a scheduler and one scan worker in one process, for a pod.
2. Scheduled sweeps of the whole configured scope, plus on-demand scans from the UI, through one queue so only one scan
   runs at a time.
3. Writes (scan, retry, cancel, accept a risk) open by default, an optional read-only mode, and the user's name from a
   trusted proxy header when there is one.
4. A hardened container image with the pinned Trivy inside it, and a Helm chart that deploys all of this.
5. Private registries through workload identity (ACR, ECR, GAR/GCR) and Kubernetes pull secrets.
6. Old runs are pruned so the volume does not fill up.

## Non-goals

- Authentication or roles inside kubedelos. Access is decided by the operator's proxy.
- Forcing a particular gateway, Ingress controller or auth proxy.
- Notifications and "first sweep never notifies" (Phase 4, #15).
- Delta schedules (a second, smaller schedule between sweeps) from #24. A sweep plus "scan now" covers the need.
- "Trend from sweeps only" from #24. Runs are already compared only with runs of the same scope, level and
  exclusions (Phase 2), so a narrow on-demand scan never pairs with a sweep. A full-scope "scan now" is a sweep in all
  but name, and comparing it is correct.
- More than one replica, Postgres, or an RWX volume.
- Scanning other clusters from the pod. The pod scans its own cluster.
- Air-gapped clusters. The pod needs egress to Trivy's DB registry and to the image registries;
  a DB mirror setting can come later.
- Changes to the laptop UI's behaviour, beyond what shared code needs.

## Anti-goals (would be a failure even if it works)

- Any code path that creates, changes or deletes cluster objects. kubedelos never starts Jobs or Pods.
- Writes on an instance set read-only.
- A pod inside the cluster able to fake the identity header, and so act under someone else's name.
- Registry tokens or pull-secret contents in SQLite, logs, error messages, the Settings page, on node disk, or in a
  file that outlives one scan.
- The pod's cloud identity token sent to a registry the operator did not name.
- Reading any Secret the user did not opt into.

## Constraints

From AGENTS.md: read-only cluster access, Trivy pinned at v0.76.1 with `--scanners vuln`, credentials never touch disk
or logs, Python 3.12+, dependency bounds `>=X.Y,<X+1`, TDD with one test file per module, ruff 120, a docstring at the
top of every module, placeholders only (`example.com`, `my-cluster`), conventional lowercase commits, PRs only.

## Approaches

### Where scans run

| | Approach | Trade-off |
|---|---|---|
| **A (picked)** | One Deployment running `kubedelos serve`: UI, scheduler and scan worker in one process. 1 replica, Recreate, an RWO PVC. | Simple and close to the laptop code. The UI is down while the pod restarts. |
| B | UI Deployment plus a CronJob for sweeps. | Two pods write one SQLite file on one RWO volume, which only works if both land on the same node, and "scan now" still runs in the UI pod. More parts, no gain. |
| C (dropped) | The UI starts Kubernetes Jobs. | Needs permission to create Jobs, which breaks the read-only rule. |

### Registry login

| | Approach | Trade-off |
|---|---|---|
| **A (picked)** | Trivy logs in itself through the cloud SDKs, and kubedelos only sets up the environment (the workload identity webhook already does). | Almost no code, and no token passes through kubedelos. Trivy only does this for registry hosts it recognises (see below). |
| B | kubedelos gets the ACR token itself (Entra token exchanged at `/oauth2/exchange`) and writes a Docker config. | More code, and kubedelos then holds the token. Only worth it if a host Trivy does not recognise needs it. |

Checked against the Trivy v0.76.1 source (`pkg/fanal/image/registry/`):
- Trivy registers Google, ECR and Azure credential providers.
- For a host ending in `.azurecr.io` (or `.azurecr.cn`), it calls `azidentity.NewDefaultAzureCredential`, which includes
  the workload identity credential that reads `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE`.
  It then exchanges the Entra token for an ACR refresh token and requires `AZURE_TENANT_ID`.
- When the call fails, Trivy logs it only at debug level and carries on without credentials. kubedelos therefore sees
  an ordinary auth error.

Limits that follow:
- **Trivy sends the token to any matching host, so kubedelos limits which hosts get it.** Trivy exchanges the Entra
  token (scope `https://management.azure.com/.default`) with whatever `*.azurecr.io` host an image ref names, and anyone
  can create one. A workload author could run a pod from `attacker.azurecr.io/x` and have the scan send the pod's token
  there. So `registries.cloudHosts` (exact hosts or `*` globs, empty by default) lists the registries that may receive
  the cloud identity. For any image whose host is not on the list, kubedelos starts Trivy with the cloud-identity
  environment removed (`AZURE_*`, `AWS_*` web-identity and `GOOGLE_*`/ADC variables, plus the projected token file
  paths), so Trivy pulls it anonymously or with Docker-config credentials only. The "Test an image" box (section 7)
  applies the same rule. With `cloud.provider` set and `cloudHosts` empty, the chart fails to render.
- An ACR behind a custom domain is not recognised; pull secrets cover that case.
- The identity needs `AcrPull` (or the cloud's equivalent). That is set up outside kubedelos, and the docs cover it.

## The design

### 1. `kubedelos serve` (#12)

- **Command.** `kubedelos serve` binds `0.0.0.0:8080` (`--host`, `--port`). It never opens a browser and prints no token
  URL. The kube client uses the in-cluster config, as `kube/client.py` already does when there is no kubeconfig.
- **Cluster name.** `KUBEDELOS_CLUSTER_NAME` names the cluster (for example `my-cluster`). Runs are stored under that
  name as their `context`, so pages, reports and exports show it instead of `in-cluster`. `serve` refuses to start
  without it. Changing it later starts a new history under the new name; the old runs stay under the old one.
- **Scheduler.** APScheduler `>=3.11,<4`, with a `BackgroundScheduler` started and stopped in the FastAPI lifespan.
  - **Schedule:** `KUBEDELOS_SWEEP_SCHEDULE` (a 5-field cron, default `0 3 * * *`) in `KUBEDELOS_SWEEP_TIMEZONE`
    (default `UTC`).
  - **Master switch:** `KUBEDELOS_SWEEP_ENABLED` (default `true`).
  - **Job settings:** `coalesce=True`, `max_instances=1`, `misfire_grace_time=3600`.
  - **What a sweep does:** it does not scan by itself. It adds a `schedule` request to the queue.
  - **Sweeps skip the result cache**. A sweep rescans every image, as "Rescan every image"
    does, so its findings match the current Trivy DB rather than a result up to 24 h old. The on-disk layer cache
    (`kubedelos/trivy/layers.py`) still applies, so an image whose layers were analysed before is only matched against
    the DB again, which keeps a full sweep fast.
- **One process owns the data.** At start, `serve` takes an exclusive `flock` on `<data dir>/serve.lock`, held for its
  lifetime. A second `serve` on the same volume exits with a clear error.
  - This replaces #12's DB lease. `store/runlock.py` already uses `flock` to tell a live run from a stale
    one, and an RWO volume is mounted on one node only, so `flock` holds.
  - On start, `serve` closes stale `running` rows with the existing `close_stale_runs`.
- **Health.** `GET /healthz` returns 200 once the DB is open and the scheduler is running. It skips the Host and
  identity checks, and the chart's probes use it.
- **Shutdown.** On SIGTERM: stop the scheduler, cancel the running scan (as the laptop `shutdown` does), then exit. The
  chart's `terminationGracePeriodSeconds` (default 60) covers it. A run cut off this way ends `cancelled`. Queued
  requests stay queued for the next start. The request that was running stays `started` with no run linked, and the
  next `serve` start marks it `cancelled` (`abandon_started`), after closing stale `running` runs.

### 2. The scan queue (#24)

A new table holds what is waiting. The worker is a thread in `serve` that takes the oldest request when no scan is
running.

```
scan_request(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('scan', 'retry')),
  trigger TEXT NOT NULL CHECK (trigger IN ('schedule', 'ui')),
  requested_by TEXT,          -- the identity header's value; NULL for the schedule
  requested_at TEXT NOT NULL,
  target_run_id INTEGER REFERENCES scan_run(id),  -- the run a retry re-scans; NULL for a scan
  overrides TEXT NOT NULL,    -- canonical JSON: for a scan, the scope, level, parallelism and rescan options the Scans
                              -- form sends; for a retry, the error kinds and parallelism retry_failed takes
  state TEXT NOT NULL CHECK (state IN ('queued', 'started', 'cancelled')),
  run_id INTEGER REFERENCES scan_run(id)
)
```

- **States.** `queued` → `started` (claimed) → finished, which is `started` with `run_id` set, or `cancelled`
  (cancelled while queued, or abandoned at start-up). A claim is one `BEGIN IMMEDIATE` transaction that reads the oldest
  `queued` row and marks it `started`, so a request cancelled first is never started, and two claimers never get the
  same row. Retention never deletes a run a queued request names, and deletes finished request rows past the retention
  period.
- **Sweeps carry `{"rescan": true}`.** A `schedule` request's overrides are `{"rescan": true}`: the saved settings,
  without the result cache.
- **Requester on the run.** `scan_run` gains a `requested_by` column (migration 10, together with the table above).
  `scan_run.trigger` is set to `schedule` or `ui`.
- **Coalesced.** A `schedule` request is not added while another `schedule` request is still queued. A `ui` request with
  the same overrides as one already queued is not added either; the UI says it is already queued.
- **Retries are queued too**. A retry of failed images is a `retry` request for its run, so it never races
  the queue worker for the one scan slot. A retry for a run that already has a queued retry is not added.
- **Bounded.** At most 10 queued requests. Past that, the UI shows "the queue is full".
- **Cancellable.** A queued request can be cancelled from the Scans page. The running scan is cancelled as today.
- **Scope is narrow-only**. A `ui` scan may cover the configured scope or a subset of it (fewer
  namespaces, an extra label selector, more exclusions, a level the configured one includes). A request that reaches
  outside it, such as a namespace the configured scope leaves out, is rejected with a message naming what was outside.
  The check runs on the canonical overrides, which are also the "already queued" key.
- **"Scan now".** It is a `ui` request with the saved settings, the same as pressing Scan with the form unchanged. It is
  not stored as a sweep.
- **On the Scans page in `serve`:** the running scan, then the queue (trigger, requester, time, cancel), then the run
  history with a "by" column. On the laptop, the page and `ScanBusy` stay as they are (no queue on a laptop).
- **Shared code.** `web/jobs.py`'s `ScanRunner` keeps running one scan at a time. The queue worker calls it. The queue
  code lives in a new `kubedelos/store/queue.py` with its own tests.

### 3. Retention

- **Setting:** `KUBEDELOS_RETENTION_DAYS` (default 180; `0` keeps everything).
- **When:** after each finished sweep, runs older than that are deleted with their image rows, findings, workloads and
  warnings, all in one transaction. The newest finished run of each scope is always kept, however old.
- **Cache:** `image_cache` rows older than the cache TTL are deleted at the same time.
- **Not touched:** accepted risks. They have their own expiry.
- **Space:** no vacuum. SQLite reuses the freed pages, so with steady retention the file stops growing. It
  never shrinks, which is fine on a PVC, and laptop databases are untouched.

### 4. Writes, identity and read-only mode

Applies to `serve` only. `kubedelos ui` keeps its loopback, token and session model unchanged, and is never read-only.

- **Writes are open by default.** Anyone who reaches the UI can scan, retry, cancel and accept or revoke risks, as on
  the laptop. This fits the usual install, where the pod is reached only through the operator's signing-in proxy. The
  chart's `NOTES.txt` warns when writes are open and trust is off: anyone who can reach the UI can then start scans
  and accept risks, which hides findings from the dashboard and reports.
- **Read-only mode is optional.** `KUBEDELOS_READ_ONLY=true` (chart value `readOnly`, default `false`) turns every
  write off, for an instance meant only for looking. Its pages hide the forms and show a notice
  (`View-only: this kubedelos is read-only.`), and any POST gets a 403 page saying so. Scheduled sweeps still run.
- **The user's name, when there is one.** `KUBEDELOS_TRUST_PROXY_HEADERS=true` makes kubedelos read the identity
  header, `KUBEDELOS_IDENTITY_HEADER` (default `X-Auth-Request-Email`; oauth2-proxy's other modes use
  `X-Forwarded-Email`, and other proxies use names such as `Remote-User`). Both are chart values, off by default.
  kubedelos does not know or care which proxy sets the header. With trust off the header is ignored.
- **What the name is used for:**

  | | Trusted identity | No identity |
  |---|---|---|
  | A scan or retry from the UI | `requested_by` is the identity | `requested_by` is empty; the By column shows `anonymous` |
  | Accepting a risk | the owner field is prefilled with the identity; left empty, the identity is the owner | the owner field is required, as on the laptop |
  | The access log | the identity is the last field | `-` |

- **The trust boundary is the network, not kubedelos.** Trust is safe only when (a) the operator's proxy overwrites or
  strips any copy of the header a client sends, and (b) nothing but that proxy can reach the pod. kubedelos cannot check
  (a); the docs say so plainly, with what to check for common proxies. The chart enforces (b): with trust on it refuses
  to render unless the NetworkPolicy is on and its `ingressFrom` names at least one source, and it also refuses any
  entry that admits every pod: `{}` or an entry with none of `podSelector`, `namespaceSelector` and `ipBlock`; a
  selector with no non-empty `matchLabels` and no `In` expression (so `Exists`, `DoesNotExist` and `NotIn`-only
  selectors count as empty); an empty `namespaceSelector`; a `namespaceSelector` that names only the release namespace
  with an empty or absent `podSelector`; and an `ipBlock` whose prefix length is 0 (`0.0.0.0/0`, `::/0`, `0.0.0.0/00`).
  A null `namespaceSelector` counts as absent. The guard catches common mistakes and is not a proof: an `ipBlock` that
  covers the pod network is the operator's to get right, NetworkPolicies are additive, and the docs name the bypasses:
  `kubectl port-forward` (anyone with that RBAC), a CNI that does not enforce NetworkPolicy, and `hostNetwork` and node
  traffic on many CNIs. `NOTES.txt` repeats them when trust is on.
- **The header value is untrusted text.** kubedelos strips control characters, caps it at 256 characters and treats
  an empty result as no identity, before it is used for `requested_by`, an acceptance's owner or the access log.
- **Hosts.** `KUBEDELOS_ALLOWED_HOSTS` (comma-separated) replaces the loopback Host check. The chart fills it from its
  own names, in this order: the Service's DNS names, `localhost` and `127.0.0.1` (so `kubectl port-forward` works), the
  Ingress hosts, the HTTPRoute hostnames and `extraAllowedHosts`. Wildcard hosts are refused, because kubedelos compares
  the Host header exactly; an enabled Ingress needs at least one host and an enabled HTTPRoute at least one `parentRef`.
- **CSRF.** Every write needs an Origin (or Referer) naming an allowed host and a CSRF token. There is no session, so
  the token is bound to a per-browser cookie (`kubedelos_csrf`, random, `HttpOnly`, `SameSite=Strict`, set on the
  first page) and, when there is one, to the identity: an HMAC of both, keyed by a secret made at start-up. A restart
  makes old forms fail once; the page reloads with a fresh one. `KUBEDELOS_SECURE_COOKIES` (default `false`; chart value
  `secureCookies`, default `true`) adds `Secure` to that cookie. Browsers accept `Secure` cookies on `http://localhost`,
  so `kubectl port-forward` still works; a browser that reaches the UI over plain HTTP on another host drops the cookie,
  so writes fail, and the operator then terminates TLS or sets `secureCookies: false`.
- **CSP and the other security headers stay as they are.** The access log adds the identity value (it is the user's
  email or user name, which the proxy already logs) and still never logs query strings.

### 5. Container image (#13)

- **Base.** `python:3.13-alpine`, pinned by digest, in a multi-stage `Dockerfile` at the repo root.
- **Build stage.** Builds the wheel and installs it into a venv. Downloads the pinned Trivy for the target arch and
  checks it against the SHA-256 in `kubedelos/trivy/pins.py`, reusing the code `kubedelos trivy install` runs.
- **Final stage:**
  - The venv and the pinned Trivy at `/usr/local/lib/kubedelos/trivy/<version>/trivy`, with `KUBEDELOS_TRIVY_DIR` set to
    its parent. It replaces setting `KUBEDELOS_TRIVY_PATH`: a set `trivy_path` labels every run `custom`
    (`scan/service.py`), and the retry check compares against that label.
  - User `65532:65532`, no shell tools needed at run time.
  - `KUBEDELOS_DATA_DIR=/data` and `KUBEDELOS_CACHE_DIR=/data/cache`, so the Trivy DBs and the layer cache sit on the PVC.
  - `TMPDIR=/tmp`, from an `emptyDir`.
  - The entrypoint is `kubedelos serve`.
- **Root filesystem.** It works read-only; only `/data` and `/tmp` are written.
- **Platforms.** `linux/amd64` and `linux/arm64`.
- **CI.** CI builds the image, runs `kubedelos version` and `serve` against `/healthz` in a smoke test, and scans the
  image with the pinned Trivy. The signed GHCR image with SBOM and provenance goes in `release-please.yml`, where the
  Phase 3 placeholder already is.

### 6. Helm chart (#13)

`charts/kubedelos/`, with `values.schema.json`, `helm lint` and `helm template` in CI. It is published as a cosign-signed
OCI chart at `oci://ghcr.io/k8s-servant/charts/kubedelos` from `release-please.yml`.

**Always rendered:**
- **Deployment:** `replicas: 1`, which is not a value; `strategy: Recreate`.
  - Pod security: `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities dropped, `seccompProfile: RuntimeDefault`,
    `automountServiceAccountToken: true`.
  - Probes on `/healthz`.
  - Volumes: `/data` on the PVC and `/tmp` on an `emptyDir`.
- **Service:** ClusterIP, port 80 to 8080.
- **PVC:** RWO, default `10Gi`. The Java DB alone is about 1 GB.
- **ServiceAccount.**
- **ClusterRole and binding:** `get`/`list` on namespaces, pods and nodes; `list` on deployments, statefulsets and
  cronjobs. That is what `kube/client.py` calls, and nothing else.
- **ConfigMap:** the `KUBEDELOS_*` settings (scope, schedule, time zone, retention, cluster name, allowed hosts,
  read-only mode, header trust).
- **NetworkPolicy (on by default):**
  - Ingress only from `networkPolicy.ingressFrom`: raw NetworkPolicy `from` entries, so any proxy, gateway or Ingress
    controller can be named. Empty by default, which with the policy on means nothing but the kubelet probes gets in
    (and `kubectl port-forward`, which bypasses NetworkPolicy).
  - Egress: open by default, because registries and the Trivy DB mirror can be anywhere. A value can narrow it.

**Exposure is the operator's choice**. The chart forces no gateway, Ingress controller or auth
proxy. It offers two generic, optional templates, both off by default:
- **`ingress`:** a plain `networking.k8s.io/v1` Ingress with `className`, `annotations` (for example an Ingress
  controller's external-auth annotations), `hosts` and `tls` as values.
- **`httpRoute`:** a Gateway API HTTPRoute with `parentRefs`, `hostnames` and `annotations` as values.

Anything else (an Envoy Gateway `SecurityPolicy`, oauth2-proxy, a mesh's auth policy, a LoadBalancer Service) the
operator deploys alongside. The docs carry one worked example, oauth2-proxy behind Envoy Gateway with ext auth (
a docs page, not chart templates, so the chart has no proxy to keep up to date). The example spells out
`--set-xauthrequest`, `headersToBackend` naming the identity header, `failOpen: false` and a group restriction.

**Guards and warnings:**
- `auth.trustProxyHeaders: true` without `networkPolicy.enabled` and a non-empty `networkPolicy.ingressFrom` fails to
  render, because any pod in the cluster could then claim to be anyone. So does an `ingressFrom` entry that admits every
  pod, including an `ipBlock` with prefix length 0 (see section 4, which lists every refused shape and what the guard
  does not cover).
- A wildcard Ingress host or HTTPRoute hostname fails to render, as does an enabled Ingress with no host or an enabled
  HTTPRoute with no `parentRefs`.
- `ingress` or `httpRoute` on with trust off renders, and `NOTES.txt` says that anyone who can reach the host can read
  the whole vulnerability inventory, and, unless `readOnly` is set, start scans and accept risks, unless the operator's
  proxy guards it.

### 7. Registry login (#14)

Most of the work is the environment; kubedelos adds pull secrets.

1. **Cloud identity:** the chart's `cloud.provider` preset (below) and Trivy's own providers. kubedelos has no code for
   it. The Registries part of the Settings page shows the detected identity: provider and client id, never a token.
**Cloud presets (PR 4).** They ship with the registry login, not with the chart in PR 3: turning on workload identity
before `registries.cloudHosts` and the environment scrubbing exist would let the pod's identity reach registries the
operator did not name, which is an anti-goal. `cloud.provider`: `azure` | `aws` | `gcp` | `none`.
- `azure`: the ServiceAccount annotation `azure.workload.identity/client-id` and the pod label
  `azure.workload.identity/use: "true"`. The webhook then injects the variables Trivy needs.
- `aws`: `eks.amazonaws.com/role-arn` on the ServiceAccount.
- `gcp`: `iam.gke.io/gcp-service-account` on the ServiceAccount.

2. **Mounted Docker configs:** `registries.dockerConfigSecrets: [name, ...]` mounts each named
   `kubernetes.io/dockerconfigjson` Secret as a read-only file.
   - The kubelet does the reading, so kubedelos needs no Secret RBAC for this.
   - kubedelos merges them into each scan's Docker config, the first secret winning on a host clash.
3. **Pod pull secrets (opt-in):** `registries.podPullSecrets: false` by default. When on:
   - RBAC is per namespace: `registries.podPullSecretNamespaces: [ns, ...]` makes the chart create
     a Role with `get` on `secrets` (never `list`) and a RoleBinding in each listed namespace, and nothing cluster-wide.
     The list is required when the option is on; an empty list fails to render. Pods in other namespaces get no pull
     secrets, and their images fall back to the mounted configs.
   - No `serviceaccounts` access is needed: the ServiceAccount admission controller already copies a ServiceAccount's
     `imagePullSecrets` into each pod's spec.
   - kubedelos reads only `KUBEDELOS_POD_PULL_SECRET_NAMESPACES` (the same list, set by the chart). For each image in
     one of them, it reads the pod's `imagePullSecrets`. A Secret whose `type` is not `kubernetes.io/dockerconfigjson`
     is dropped at once, unread and unlogged. From the rest it keeps only the `auths` entries for that image's host and
     merges them over the mounted configs. The host match is also what limits where those credentials are sent.
   - The security note says plainly what this permits: anyone who can create pods in a listed namespace can make
     kubedelos read any `dockerconfigjson` Secret they can name there, and kubedelos sends its credentials only to the
     host they are for. A test covers a pod that names a non-docker Secret.
   - The Secret contents live in memory for the scan only, and the Secret names are logged at debug level, never their
     contents.
4. **Per scan.** `KUBEDELOS_SECRETS_DIR=/run/kubedelos` is an `emptyDir` with `medium: Memory` (size limit 16Mi), added
   to the image and the chart in this PR, so per-scan Docker configs never reach node disk. One temporary `DOCKER_CONFIG` directory per Trivy process, mode 0700 under `KUBEDELOS_SECRETS_DIR`
   (the memory-backed volume; on a laptop, unset, so no file is written and the user's Docker login applies as today).
   `scan_image` already takes `docker_config`. It is deleted when that process ends, even on error or cancel. A SIGKILL
   or OOM kill skips that, so `serve` empties `KUBEDELOS_SECRETS_DIR` at start, and the volume is gone with the pod. Only `auths` entries
   are written; credential helpers in a mounted config are dropped, since the image has none.
5. **Rule change.** AGENTS.md's "never read Secrets" becomes "never read Secrets, except the pull secrets a pod names,
   in namespaces the operator listed for that, and only when `podPullSecrets` is on", in the same PR. Its "credentials
   never touch disk" rule gains "except a per-scan Docker config on the memory-backed secrets volume". The README and a security note say what this permits.
6. **Unchanged:** anonymous pulls of public images, and on a laptop the user's own Docker login.

`kubedelos registry test` gains no new options. In `serve`, a "Test an image" box on the Settings page runs the same
check with the same credentials a scan would use, and the same `cloudHosts` rule. It is a POST, so it needs an
identity.

### 8. Settings page in `serve`

It lists the in-cluster settings and where each came from (the ConfigMap's environment variables). It also shows:
- the schedule and the next sweep time;
- retention, read-only mode, the trust and identity header settings;
- the detected cloud identity and the mounted Docker config Secret names.

Nothing on it is editable. Changes go through Helm values.

## Delivery: four PRs, in this order

1. **`serve`, scheduler, queue, retention.** Migration 10, `store/queue.py`, `serve.lock`, `/healthz`, Scans page queue.
   It is testable on a laptop: `serve` runs outside a cluster with `KUBEDELOS_CONTEXT=kind-lab`, so the cluster name
   and kubeconfig still work. PR 1 ships it view-only; PR 2 opens the writes.
2. **Writes, identity and read-only mode.** UI scans, retries and cancels through the queue, narrow-only scope,
   header trust, CSRF, the optional read-only mode,
   requester shown.
3. **Image and chart.** Dockerfile, chart, CI image build, smoke test, kind e2e that installs the chart and waits for a
   sweep. Release signing jobs go into `release-please.yml`. The exposure docs with the oauth2-proxy and Envoy Gateway
   example.
4. **Registry login.** The `cloud.provider` presets, the memory-backed secrets volume (`KUBEDELOS_SECRETS_DIR`),
   `registries.cloudHosts` and the cloud-identity environment scrubbing, mounted Docker configs,
   opt-in pod pull secrets, the memory-backed temporary Docker config, the Settings
   Registries section, the AGENTS.md change, docs pages for ACR + workload identity, ECR, GAR and pull secrets.
   Tested against a `registry:2` with htpasswd in kind, plus a unit test with the Azure path mocked at the environment
   level. There is no ACR in CI, and the user's work registries are off limits.

Each PR updates `CHANGELOG.md` under `## Unreleased` and the README.

## Left to the builder

- The exact page layout of the queue and read-only notices, following the existing templates and CSS.
- The default `python:3.13-alpine` digest, and the oauth2-proxy version used in the docs example, at the time of the PR.
- For the docs example, confirm in the Envoy Gateway source that `headersToBackend` overwrites a client's copy of the
  identity header.
- How the kind e2e waits for the first sweep (a one-minute schedule in test values is fine).
- Whether Trivy reads a mounted Docker config before or after its cloud providers. The docs must say which wins for a
  host covered by both; check it in the Trivy source when writing the docs.

## Decisions recorded here

- `flock` on the volume instead of a DB lease.
- No queue on the laptop; `ScanBusy` stays.
- Retention by days (180) instead of the months in #24, always keeping the newest run of each scope.
- Delta schedules and "trend from sweeps only" dropped.
- `KUBEDELOS_CLUSTER_NAME` is required in `serve`.
- Docker configs from mounted Secrets need no Secret RBAC; only pod pull secrets do.
- The chart is proxy-neutral: generic Ingress and HTTPRoute templates only; the oauth2-proxy and Envoy Gateway setup is
  a docs example, not part of the chart.
- Retries go through the queue.
- No vacuum after pruning.
- The settings stay read-only in the UI; Helm values are the only way to change them in-cluster.
