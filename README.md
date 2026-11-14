# kubedelos

[![CI](https://github.com/k8s-servant/kubedelos/actions/workflows/ci.yml/badge.svg)](https://github.com/k8s-servant/kubedelos/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/k8s-servant/kubedelos/badge)](https://scorecard.dev/viewer/?uri=github.com/k8s-servant/kubedelos)
[![License](https://img.shields.io/github/license/k8s-servant/kubedelos)](LICENSE)

Scan the container images running in a Kubernetes cluster with Trivy.

Status: pre-alpha. Interfaces and output may change.

## Quickstart

```bash
pipx install kubedelos        # or: uv tool install kubedelos
kubedelos scan
kubedelos scan -o sarif --fail-on high > results.sarif
```

`kubedelos scan` inventories the workloads in your current kube-context, scans each unique image
digest once, and prints a table. Other formats: `-o json`, `-o csv`, `-o sarif`. Use `--context`,
`--kubeconfig`, `--namespace` and `--exclude-namespace` to narrow what is scanned. Owners are read
from the `kubedelos.io/owner-email` namespace annotation.

Narrow a scan by labels or skip images:

```bash
kubedelos scan --namespace-selector team=payments,env!=dev   # namespaces by label
kubedelos scan -l app=web                                     # pods and workloads by label, in every namespace
kubedelos scan --exclude-image 'registry.k8s.io/*' --exclude-image 'nginx:*'
```

Selectors use kubectl syntax and are applied by the API server. Deployments, StatefulSets and CronJobs that are scanned
as templates (scaled to zero, or not running) match `-l` on their own labels, which can differ from their pod
template labels. `--exclude-image` globs match the normalised image name and the short Docker Hub forms, so `nginx:*`
skips `nginx:1.19` and `docker.io/library/nginx:1.19` alike; excluded images are never scanned and are counted on
stderr. Exclusions are deliberate, so excluded images never count towards `--fail-on`: anchor patterns on the
registry and repository (`registry.example/vendor/*`, not `*vendor*`), because `*` also matches across `/` and `:`,
and a broad pattern could match an image someone named to fit it. Each run records its scope, so runs that covered different things are never compared as if they were the same.

By default both OS packages and application libraries are scanned. `--pkg-types os` scans OS packages only and
skips the 1.5 GB Trivy Java DB; `--pkg-types library` scans application dependencies only. Each finding records its
class (`pkg_class`: `os` or `library`), and cached results are kept per level, so a narrower scan never answers
for a wider one.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Scan finished and no `--fail-on` threshold was reached |
| 1 | A finding at or above the `--fail-on` severity was found |
| 2 | With `--fail-on`: an image failed to scan, or a namespace or resource could not be listed so images may be missing; or a fatal error |
| 130 | Cancelled (Ctrl-C, SIGTERM or SIGHUP). Running Trivy scans are stopped and the run is recorded as cancelled |

With `--fail-on` unset (or `none`), image scan errors are only reported on stderr and the exit code stays 0, so check stderr before treating 0 as fully scanned. Each failed image gets one line there, with its ref, platform, error kind (`auth`, `not_found`, `timeout`, `trivy` or `unknown`) and the first line of the error.

Pass `--allow-partial` to accept an incomplete scan instead of exiting 2. Warnings that lose only detail, not images, are printed but never cause exit 2: a forbidden node list (the platform falls back to the most common one) and, with `--namespace`, a forbidden namespace list (owner info is unavailable). A namespace-scoped service account can therefore gate on `--fail-on` without `--allow-partial`.

`--fail-on` checks every finding, including those that `--severity` (default `CRITICAL,HIGH`) hides from the output. When the gate fires on hidden findings, kubedelos prints `N finding(s) at or above --fail-on are hidden by --severity` on stderr.

## Configuration

Every setting can also come from an environment variable. A command line flag wins over the variable.

| Variable | Flag | Default |
| -------- | ---- | ------- |
| `KUBEDELOS_KUBECONFIG` | `--kubeconfig` | the standard kubeconfig lookup |
| `KUBEDELOS_CONTEXT` | `--context` | the current context |
| `KUBEDELOS_NAMESPACES` | `--namespace` | all namespaces |
| `KUBEDELOS_EXCLUDE_NAMESPACES` | `--exclude-namespace` | none |
| `KUBEDELOS_NAMESPACE_SELECTOR` | `--namespace-selector` | none |
| `KUBEDELOS_SELECTOR` | `-l`, `--selector` | none |
| `KUBEDELOS_EXCLUDE_IMAGES` | `--exclude-image` | none (JSON list of globs) |
| `KUBEDELOS_PARALLELISM` | `--parallelism` | `4` images at once (1 to 32) |
| `KUBEDELOS_PKG_TYPES` | `--pkg-types` | `os,library` (comma-separated: `os`, `library` or both) |
| `KUBEDELOS_SCAN_TIMEOUT_S` | | `600` seconds per image |
| `KUBEDELOS_TRIVY_PATH` | `--trivy-path` | the pinned Trivy |
| `KUBEDELOS_CACHE_DIR` | | the user cache dir (`~/.cache/kubedelos` on Linux, `~/Library/Caches/kubedelos` on macOS): Trivy binary and DB |
| `KUBEDELOS_DATA_DIR` | | the user data dir (`~/.local/share/kubedelos` on Linux, `~/Library/Application Support/kubedelos` on macOS): `kubedelos.db` |
| `KUBEDELOS_OWNER_ANNOTATION` | | `kubedelos.io/owner-email` |
| `KUBEDELOS_TEAM_LABEL` | | `kubedelos.io/team` |

List variables take a JSON list, not a comma-separated string (`KUBEDELOS_PKG_TYPES` is the exception: `os,library`):

```bash
KUBEDELOS_NAMESPACES='["team-a","team-b"]' kubedelos scan
```

Inside a pod with no kubeconfig, kubedelos uses the in-cluster service account. It never does that when `--context` or `--kubeconfig` is set.

## Trivy

kubedelos runs a pinned Trivy release (v0.76.1) as one standalone process per image, sharing one locked DB cache. It runs on Linux and macOS (amd64 and arm64); Windows is not supported. `kubedelos trivy install` downloads it
and checks it against an embedded SHA-256. It never resolves "latest". Use `--trivy-path` to bring your own binary. Results from your own binary are
not cached and the run records its Trivy version as `custom`.

## Private registries

kubedelos uses the Docker credentials you already have: `DOCKER_CONFIG`, or `~/.docker/config.json`,
including credential helpers. Log in to a private registry the way you normally would, and scans can read it:

- any registry: `docker login registry.example`
- Azure Container Registry: `az acr login --name myregistry`
- Google Artifact Registry: `gcloud auth configure-docker europe-docker.pkg.dev`
- Amazon ECR: the [ECR credential helper](https://github.com/awslabs/amazon-ecr-credential-helper), or
  `aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com`

Check access to one image with:

```bash
kubedelos registry test registry.example/team/app:1.2.3
```

It exits 0 when the image is readable, 1 when the registry refuses access or the image is not found, and 2 for
other errors. When images fail registry auth during `kubedelos scan`, a `hint:` line names each registry to log in
to. Registry auth for the in-cluster mode (workload identity, pull secrets) comes with the Helm chart.

## Local web UI

`kubedelos ui` serves a read-only web UI on top of the scan data in your local SQLite database. It listens on loopback only
(`127.0.0.1`, `::1` or `localhost`; other hosts are refused), prints a URL with a token, and opens it in your browser:

```bash
kubedelos ui                          # http://127.0.0.1:9370/?token=...
kubedelos ui --port 9400 --no-browser
```

The token is swapped for a session cookie and stays valid until the server stops; a restart prints a new one. If the port
is in use, it exits 2 with `error: port N is in use; pass --port`. `--context` and `--kubeconfig` choose the cluster whose
runs are shown. `KUBEDELOS_LOG_LEVEL=info` prints one access line (path only) per request on stderr.

To use it on a remote machine, forward the port over SSH and open the printed URL locally:

```bash
ssh -L 9370:127.0.0.1:9370 my-host
```

Keep the same port on both ends: the UI checks the `Host` header against the port it listens on, so `-L 9400:...` fails.

- **Dashboard (`/`)**: the latest whole-cluster run (scope, package types, age; a stale badge after 24 hours, and an incomplete marker when
  some namespaces could not be listed), tiles with the change against the previous comparable run, severity bricks, a
  fix-first list (grouped by fix, or by image with `?by=image`), and failed images with the cause and a registry login hint. A newer, narrower run is mentioned with a link to its findings.
- **Findings (`/findings`)**: filter by URL query (`severity`, `namespace`, `cve`, `package`, `has_fix`, `pkg`, `q`), sort,
  100 per page.

Add `?run_id=N` to pin a page to one run.

## License

Apache-2.0
