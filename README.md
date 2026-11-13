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

## Coming soon

`kubedelos ui`, a local web UI on top of the same scan data, is not available yet.

## License

Apache-2.0
