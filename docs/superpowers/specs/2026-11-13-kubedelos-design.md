# kubedelos: open-source Kubernetes vulnerability scanner with a web UI and scheduled reports

## Context
An earlier internal tool proved the idea but was tied to one company's environment: its owner lookup, secret store, mail setup, label conventions, registry and ingress were all specific to that setup. We want a community open-source tool built from the same idea that works on any cluster, in two modes that matter equally:
1. **Laptop:** type `kubedelos ui` and a local web UI opens against the current kube-context, as in skyhook-io/radar.
2. **In-cluster:** `helm install` runs scheduled scans, keeps history and sends reports (email or webhooks).

**Market gap:** no existing tool lets you run a single command against your current context and get a Trivy-focused UI. trivy-operator-dashboard needs an in-cluster install, and the Headlamp, Lens and Argo CD plugins need a host app.

## Decisions (made by you)
| Topic | Decision |
|---|---|
| Name | **kubedelos**. PyPI, GitHub `k8s-servant/kubedelos` and Homebrew are all free (checked 2026-11-13). Bare "delos" clashes with Delos Cloud (SAP sovereign cloud), and the PyPI name `delos` is taken. |
| Command | The package `kubedelos` installs one command, `kubedelos`. There is no separate `delos` command (decided 2026-11-13). |
| Org | `k8s-servant` GitHub org, reusing its release GitHub App and its `maintainers` team. |
| Code origin | **Clean rewrite.** No code is copied from the earlier tool. It serves only as a reference for features and UX. |
| Language | Python 3.12+ |
| Scan source | Trivy CLI only. kubedelos lists pod images and runs `trivy image`. No Trivy Operator. |
| UI | FastAPI + Jinja2 + HTMX, with no Node build. Static assets ship in the wheel. |
| Trivy on a laptop | Auto-download a pinned Trivy release into `~/.cache/kubedelos`, verified against the release checksums file. `--trivy-path` overrides it. |
| Storage | SQLite only (`~/.local/share/kubedelos/` locally; PVC with a single replica in-cluster). All SQL goes through a repository layer so Postgres can be added later. |
| Notifications v0.1 | Generic SMTP, Microsoft 365 (Graph `sendMail` via client secret or Azure workload identity), Slack and Teams webhooks. |
| Owners | Namespace annotations or labels such as `kubedelos.io/owner-email` and a configurable team label, plus a fallback recipient. |

| Scan scope | Images in running pods, including init and ephemeral containers, plus the pod templates of CronJobs and of Deployments or StatefulSets scaled to zero. |
| Scanners | Vulnerabilities only. Secret and misconfig scanning may come later as opt-in. |
| No-auth in-cluster | Read-only: view and export only. Write actions (scan, exceptions, settings, send) need `trustProxyHeaders` and an authenticated identity header, or else the CLI or the schedule. How the UI is exposed is the user's choice: chart templates for Ingress, Gateway API HTTPRoute, or Gateway API plus an oauth2-proxy sidecar, all off by default. |
| Report default | Critical and High, with a "fix available" list first and unfixable findings summarised. Shows what's new since the last report and hides accepted exceptions. All of it can be configured. |

## Container registry authentication (v0.1 feature)
Each registry is set up explicitly, in Helm values, the config file or flags. Hosts are matched with globs, and the first match wins:
```yaml
registries:
  - host: "*.azurecr.io"
    auth: azure-workload-identity   # SA annotated with azure.workload.identity/client-id
  - host: "123456789.dkr.ecr.eu-west-1.amazonaws.com"
    auth: aws                       # IRSA / EKS Pod Identity / instance profile
  - host: "europe-docker.pkg.dev"
    auth: gcp                       # GKE Workload Identity / ADC
  - host: "harbor.corp.local"
    auth: basic
    secretRef: harbor-creds         # k8s Secret with username/password keys
    caSecretRef: corp-ca            # optional private CA; insecure: false by default
  - host: "*"
    auth: dockerconfig
    secretRef: regcred              # kubernetes.io/dockerconfigjson
defaults:
  usePodPullSecrets: false          # opt-in; needs secrets/serviceaccounts get RBAC
  anonymous: true                   # public images need no config
```

**Supported auth types:**

| `auth` | How it works | Where |
|---|---|---|
| `azure-workload-identity` | `azure-identity` gets an Entra token, which is exchanged at ACR `/oauth2/exchange` for an ACR refresh token, then written to a temporary `DOCKER_CONFIG` for Trivy. In-cluster it uses the federated token the WI webhook injects (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`). On a laptop the same code path uses `az login`. The identity needs the `AcrPull` role. Works on AKS and on any cluster with an OIDC issuer and the WI webhook. | AKS, self-managed |
| `azure-managed-identity` | Same token exchange, using a managed identity (node or pod). | AKS |
| `aws` | Trivy's built-in ECR support through the AWS SDK default credential chain (IRSA, Pod Identity, profile). If that doesn't work for a host, kubedelos falls back to `ecr:GetAuthorizationToken` via boto3 (the `kubedelos[aws]` extra). | EKS, laptop |
| `gcp` | Trivy's built-in GCR/GAR support through Google ADC (GKE WI, `gcloud auth application-default login`). Fallback: an ADC access token as `oauth2accesstoken` (the `kubedelos[gcp]` extra). | GKE, laptop |
| `basic` | Username and password from a Kubernetes Secret or environment variables. | Harbor, Nexus, Artifactory, Quay, GitLab |
| `dockerconfig` | A mounted `dockerconfigjson` Secret, or the laptop's `~/.docker/config.json`, including credential helpers. | anywhere |
| `pod-pull-secrets` | Reads the pod's and ServiceAccount's `imagePullSecrets` and uses them for that pod's images. | on-prem, generic |
| `anonymous` | No credentials. | public registries |

**Design details:**
- `kubedelos/registry/` has a `CredentialProvider` protocol, a provider for each auth type, and a resolver that matches hosts.
- For each scan, the resolver builds a short-lived `DOCKER_CONFIG` in a temporary directory with 0700 permissions. It is passed only to that Trivy client process and deleted afterwards. kubedelos's own exchanged tokens are cached in memory until they expire. Credentials are never stored in SQLite and never logged.
- Helm `cloud.provider` presets the ServiceAccount annotations and pod labels that WI, IRSA and GKE WI need. `registries:` decides which auth goes with which host. On mixed clusters the two can be combined, for example AKS pulling from both ACR and Harbor.
- **The UI shows auth status:**
  - a "Registries" page lists each configured host, its auth type, and the result of the last token check
  - `kubedelos registry test <image>` checks the same thing from the CLI
  - scans that fail with auth errors are labelled as such and not counted as clean
- **Docs:** one page per registry type, with step-by-step setup: the ACR + WI page covers the federated credential, `AcrPull` and the SA annotation; ECR covers the IRSA policy; GAR covers the `roles/artifactregistry.reader` binding; Harbor covers a robot account.

## Corrections from the builder review (my calls)
- **Scan by digest.** Use `repo@sha256:…` from `containerStatuses[].imageID`, and fall back to the tag for templates. Always pass `--image-src remote` and `--platform linux/<node arch>`, so an arm64 Mac neither scans its local Docker copy nor picks the wrong arch.
- **Trivy concurrency (revised 2026-11-13).** No local `trivy server`. Each image is scanned by its own standalone `trivy image --cache-backend memory --skip-db-update --skip-java-db-update`. The only BoltDB lock fight between parallel Trivy processes is over the on-disk layer cache, so keeping it in memory removes it; the vulnerability and Java DBs are read-only and shared. A file lock on `<cache>/trivy-cache` lets one run download or update the DBs (exclusive) while scans hold it shared, and a run that finds the cache busy skips the update. Spike on Trivy 0.76.1: 6 parallel standalone scans with the default fs cache failed 4 of 6 with "cache may be in use by another process"; 10 parallel scans with the memory backend (including tomcat, jenkins and elasticsearch, which have JAR results) all passed, and findings matched server mode exactly for nginx:1.19, jenkins/jenkins:2.400 and python:3.11-slim. This also removes the port, the token and a long-lived process from the in-cluster pod.
- **Trivy pinning.** Pin the version and a per-platform SHA-256 inside the package. A checksums file from the same release only proves integrity. Never use "latest". In CI, pin Trivy by SHA, not `trivy-action` tags (there was a supply-chain incident in 2026).
- **Registry auth.** Trivy's built-in cloud support only triggers on matching hostnames, so kubedelos does the ACR token exchange itself (see above) rather than relying on Trivy. Pull secrets need `secrets:get` and `serviceaccounts:get` (opt-in).
- **M365.** Call the Graph `users/{sender}/sendMail` endpoint (POST) through `httpx` with an `azure-identity` token, not msgraph-sdk. Document how to scope `Mail.Send` with Exchange RBAC for Applications, and the 4 MB request limit, which means a large CSV becomes a UI link. Workload identity works on any cluster with an OIDC issuer.
- **Teams.** Use Workflows webhooks with an Adaptive Card payload. The old O365 connector webhooks are being retired.
- **APScheduler.** Pin `>=3.11,<4`. Run `AsyncIOScheduler` in the FastAPI lifespan with an in-memory job store, and the DB lease guards against double runs.
- **SQLite in-cluster:**
  - RWO block storage only; the docs warn against NFS, EFS and Azure Files
  - `strategy: Recreate`
  - `fsGroup`
  - `SQLITE_TMPDIR=/tmp`, an emptyDir with a `sizeLimit`; Trivy also extracts layers there
  - one writer with `busy_timeout`
  - PVC of at least 2Gi for the vulnerability DB and Java DB
  - NetworkPolicy egress to mirror.gcr.io and ghcr.io (DB) plus the registries
- **Proxy-header trust.** With `trustProxyHeaders` on, the app binds to 127.0.0.1 in the pod and the Service targets only the oauth2-proxy port.
- **Laptop hardening.** Check the Host header (DNS-rebinding defence) and put a random startup token in the URL that opens, as Jupyter does.
- **Data paths.** Use `platformdirs`, which handles macOS, Linux and Windows correctly.
- **Console scripts.** Only `kubedelos = "kubedelos.cli:app"`. The UI is a subcommand: `kubedelos ui --port 9000`.
- **krew.** Dropped for v0.1, because it needs native binaries.
- **Owner and team fields** go in the schema from Phase 1, to avoid a migration in Phase 4.
- **Release-please.** Set `initial-version: 0.1.0` and seed the manifest. Add `# x-release-please-version` markers in `Chart.yaml`. Gate the publish jobs until Phase 5, and keep the release PR unmerged until then.
- **CI growth.** CI jobs for Docker and Helm are added when those files land in Phase 3. The "CI result" check treats skipped jobs as passing.

## My calls (please check these)
- **CLI framework:** Typer. Commands:
  - `kubedelos ui` (local web UI)
  - `kubedelos scan` (output `table|json|csv|sarif`, with `--fail-on` for CI)
  - `kubedelos serve` (in-cluster: web plus scheduler)
  - `kubedelos report send|preview`
  - `kubedelos trivy install`
  - `kubedelos version`
- **Laptop UI:** binds to `127.0.0.1:9370` and opens the browser (`--no-browser`, `--port`, `--context`, `--namespace`). A non-loopback bind is refused unless `--allow-remote` is passed. The UI header always shows the active context.
- **In-cluster auth:** no auth is built into the app. Without a proxy the UI is read-only (see the decisions). CSRF protection and a strict CSP with a nonce are always on.
- **Cloud profiles:** Helm values `cloud.provider: generic|aks|eks|gke` set the ServiceAccount annotations and labels: `azure.workload.identity/client-id` plus the pod label (AKS), `eks.amazonaws.com/role-arn` or Pod Identity (EKS), `iam.gke.io/gcp-service-account` (GKE). "generic"/on-prem uses pull secrets or none.
- **Secrets:** read only from environment variables or mounted Kubernetes Secrets. The docs show External Secrets Operator, Vault and similar as the way to fill them. There are no cloud secret SDKs in core.
- **Microsoft 365 email:** Graph `sendMail` (`Mail.Send` application permission) through `azure-identity`. This is an optional extra, `pip install kubedelos[m365]`, so the core stays light.
- **Scheduling:** APScheduler inside `serve`, with one replica and a lease row in the DB to guard against double runs. Default schedules: a full sweep (cron, weekly by default), a nightly rescan of changed digests, and a retention prune. The first sweep after install sends no email. Mail can be set to `scan+notify | scan-only | off`.
- **Non-goals for v0.1:** Trivy Operator CRDs, Postgres, HA, multi-cluster aggregation, built-in OIDC, an MCP server, Go/brew single binaries (brew comes later as a Python formula in a tap), CMDB or ticketing integrations.
- The repo and local folder are named `kubedelos`.

## Architecture
```
kubedelos/
  cli.py            Typer app; the kubedelos entrypoint
  config.py         pydantic-settings: env / file / CLI flags, one Settings model
  kube/inventory.py namespaces, pods → unique (image, digest, namespace, workload, owners)
  kube/owners.py    annotation/label → owner/team rules + fallback
  trivy/binary.py   locate / download+verify pinned trivy
  trivy/runner.py   `trivy image --format json` subprocess, parallel pool, timeouts, DB update
  trivy/parse.py    trivy JSON → Finding models (pydantic)
  scan/service.py   orchestrates a run: inventory → cache-by-digest → scan → persist; progress/cancel
  store/db.py       SQLite schema + migrations (stdlib sqlite3, WAL)
  store/repo.py     runs, findings, image cache, exceptions, settings, diff, retention
  analytics.py      KPIs, trends, fix lists, exception matching
  notify/base.py    Notifier protocol; registry via entry points (plugin-friendly)
  notify/{smtp,m365,slack,teams}.py
  notify/render.py  Jinja email/report templates (per-owner + admin summary), CSV
  web/app.py        FastAPI app factory, security middleware (CSP nonce, CSRF, headers)
  web/routes/*.py   dashboard, findings, images, namespaces, runs, diff, exceptions, settings, reports
  web/templates, web/static (htmx.min.js vendored + pinned, CSS, SVG charts server-side)
  scheduler.py      APScheduler jobs + DB lease
charts/kubedelos/   Deployment, Service, PVC, SA, ClusterRole (namespaces/pods list; opt-in secrets get),
                    NetworkPolicy, ConfigMap, optional Ingress/HTTPRoute/oauth2-proxy, values.schema.json
```
**Reports in the UI:** CSV export, plus a print-friendly HTML page in place of WeasyPrint, which keeps the native dependencies out of the image.

## Implementation phases
Every phase ends green in CI. Tests are written first for the pure logic (TDD).

**Phase 0: secure repo bootstrap.** Use the k8s-servant repo in the same org as the template (its `.github/` directory) and adapt it:
- **Workflows:** `ci.yml` (ruff, pytest on 3.12–3.14, helm lint and template, docker build plus smoke test plus a Trivy self-scan, wheel and twine check), `security.yml` (gitleaks, zizmor, actionlint, dependency-review), `codeql.yml`, `scorecard.yml`, `release-please.yml` (signed multi-arch GHCR image with SBOM and provenance, cosign-signed OCI chart at `oci://ghcr.io/k8s-servant/charts/kubedelos`, PyPI trusted publishing with attestations), `docs.yml`, `pr-title.yml`, `labels.yml`, and optionally `claude*.yml`.
- **Practices:** SHA-pinned actions, `permissions: {}` at the top, `persist-credentials: false`, separate build and sign jobs.
- **Repo files:**
  - `dependabot.yml` with a 7-day cooldown, `CODEOWNERS`, issue and PR templates, `release.yml`, `labels.yml`
  - `SECURITY.md` (from k8s-skills), `CONTRIBUTING.md`, a new `CODE_OF_CONDUCT.md` (Contributor Covenant), `NOTICE`, Apache-2.0 `LICENSE` (already present)
  - `.pre-commit-config.yaml`, `.editorconfig`, `release-please-config.json` (python, initial 0.1.0, extra-files for `Chart.yaml`), `CHANGELOG.md`, `AGENTS.md`, `CLAUDE.md`
  - the spec at `docs/superpowers/specs/2026-11-13-kubedelos-design.md`
- **GitHub settings (done by you or with `gh`, after confirmation):**
  - create the `k8s-servant/kubedelos` repo
  - ruleset requiring the "CI result" check and squash merges
  - private vulnerability reporting, secret scanning and push protection
  - PyPI trusted publisher, and install the release App
  - optionally, register a domain: `kubedelos.dev` doesn't resolve yet

**Phase 1: core scanning plus the `kubedelos scan` CLI.** config, kube inventory, trivy binary and runner, parsing, store, scan service. Unit tests use recorded Trivy JSON fixtures and a fake kube client.

**Phase 1b: registry auth.** Build `kubedelos/registry/` with the providers and resolver. Unit tests cover host matching, `DOCKER_CONFIG` generation and cleanup, and the ACR exchange against a mocked endpoint. A local `registry:2` with htpasswd covers the basic, dockerconfig and pod-pull-secrets types in kind.

**Phase 2: laptop UI (`kubedelos ui`).** FastAPI app, dashboard, findings, images, namespaces, run history, diff, exceptions, CSV. The scan is started from the UI with live HTMX progress. The browser opens automatically.

**Phase 3: in-cluster mode.** `serve`, scheduler and lease, Helm chart with cloud profiles, NetworkPolicy, read-only root filesystem, non-root user, and the Dockerfile (python-alpine, pinned Trivy verified by checksum, Trivy cache on the PVC).

**Phase 4: owners and notifications.** Owner rules, notifier plugins (SMTP, M365, Slack, Teams), preview in the UI, `report send|preview`, and the three notify modes.

**Phase 5: docs and v0.1.0.**
- README in the k8s-servant structure: badges, a 60-second quickstart (`pipx install kubedelos && kubedelos ui`), and a kind demo.
- Docs site pages: cloud setup guides for AKS (WI), EKS (IRSA/Pod Identity), GKE (WI) and on-prem; notifications; security model; verifying releases.
- Merge the release-please PR to cut 0.1.0.

## Verification
- `pytest` with coverage of at least 80% on the pure modules. `ruff check` and `ruff format --check` pass.
- **Laptop end to end:** create a `kind` cluster with some vulnerable images (for example `nginx:1.19`), run `kubedelos ui` on a clean machine with no trivy installed, and check that Trivy downloads and verifies, the browser opens, a scan finishes, and findings and a diff show up.
- **CLI:** `kubedelos scan -o sarif --fail-on critical` returns a non-zero exit code on kind.
- **In-cluster:** `helm install` into kind, trigger a sweep through the UI, and have Mailpit (in-cluster SMTP) receive per-owner emails. Run a webhook test against a local echo server.
- **Registry auth on real clusters (done by you, before 0.1.0):**
  - AKS with WI pulling from a private ACR
  - EKS with IRSA pulling from ECR
  - GKE with WI pulling from GAR
  - `kubedelos registry test` succeeds on each, and the Registries page shows green
- **Chart:** `helm lint --strict`, `helm template` for each cloud profile, and a `kubeconform` schema check.
- **Release dry run:** a tag on a fork produces the signed image, chart and PyPI attestations. Then run `cosign verify` as described in `docs/verifying-releases.md`.
- Before release: a security review of the web layer (`/security-review`) and zizmor reporting zero findings.
