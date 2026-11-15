# kubedelos

[![CI](https://github.com/k8s-servant/kubedelos/actions/workflows/ci.yml/badge.svg)](https://github.com/k8s-servant/kubedelos/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/k8s-servant/kubedelos/badge)](https://scorecard.dev/viewer/?uri=github.com/k8s-servant/kubedelos)
[![License](https://img.shields.io/github/license/k8s-servant/kubedelos)](LICENSE)

Scan the container images running in a Kubernetes cluster with Trivy.

Status: pre-alpha. Interfaces and output may change.

## Why kubedelos

[Trivy](https://github.com/aquasecurity/trivy) does the scanning, and kubedelos doesn't replace it: `trivy image` and
`trivy k8s` tell you what is vulnerable right now. kubedelos is for what comes after that report, across a whole cluster
and over time:

- **What actually runs.** It lists the images running in the cluster, including init and ephemeral containers,
  CronJobs and workloads scaled to zero. Access is read-only and Secrets are never read. Each unique image is scanned
  once per platform.
- **What to fix first.** The dashboard puts the Critical and High findings that have a fix on top, grouped by fix or by
  image, with the images worst hit and the images that failed to scan, plus a hint on which registry to log in to.
- **What changed.** Every run is kept in a local SQLite database, so the dashboard shows the change since the last
  comparable run, and the findings of any earlier run can be opened again.
- **One command, nothing to install in the cluster.** `kubedelos ui` opens a local web UI against your current
  kube-context. There is no operator, CRD or host app such as Lens or Headlamp to set up first.
- **Cheap repeat scans.** Results are cached by image, so a rescan only scans what changed.
- **Careful by default.** Trivy is pinned and checksum-verified, never "latest", and registry tokens are never written
  to disk or logs.

kubedelos doesn't gate CI pipelines: Trivy already does that well. Next on the roadmap is an in-cluster mode installed
with Helm, with scheduled scans, the same UI for each cluster, and reports sent to each namespace's owners by email,
Slack or Teams.

## Quickstart

```bash
pipx install kubedelos        # or: uv tool install kubedelos
kubedelos ui
```

`kubedelos ui` opens a local web UI against your current kube-context. Start a scan on the Scans page: kubedelos lists
the workloads in the cluster, scans each unique image once with Trivy, and shows the results on the dashboard. Owners
are read from the `kubedelos.io/owner-email` namespace annotation.

## Local web UI

`kubedelos ui` serves a web UI on top of the scan data in your local SQLite database, and can start scans of its
context. It listens on loopback only (`127.0.0.1`, `::1` or `localhost`; other hosts are refused), prints a URL with a
token, and opens it in your browser:

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

Every page has a sidebar with the kube-context and a freshness dot that turns from green to amber once the shown run is
over 24 hours old, and a footer naming the Trivy that scanned it ("Scanned with Trivy v0.76.1", or "a custom Trivy" for
`KUBEDELOS_TRIVY_PATH` runs); below 760 px the sidebar becomes a top bar, which leaves the footer out. The page head names the
run in chips: its number, scope, package types, age, image count and failures, and whether it is pinned or stale. The UI
follows the system light or dark theme.

- **Dashboard (`/`)**: the latest whole-cluster run, with an incomplete marker when some namespaces could not be listed.
  KPI tiles show the change against the previous comparable run; the all findings tile carries a severity bar and a
  legend whose entries link to the findings. A Worst images panel ranks images by Critical and High, and a fix-first list
  is grouped by fix, or by image with `?by=image`. Failed images are listed with the cause and a registry login hint, and
  a newer, narrower run is mentioned with a link to its findings.
- **Findings (`/findings`)**: filter by URL query (`severity`, `namespace`, `cve`, `package`, `has_fix`, `pkg`, `q`), sort,
  100 per page.
- **Scans (`/scans`)**: start a scan of the UI's context. The form takes namespaces, namespace exclusions, a namespace
  selector, a label selector, image exclusions, the number of images scanned in parallel (1–32) and package types, each
  prefilled from your settings and labelled with the saved value. What you change applies to that scan only.
  The UI runs one scan at a time; a second start while one runs is refused, but a scan from another `kubedelos ui`
  doesn't block it. Progress updates every 2 seconds without a reload: the phase (Trivy DB, inventory, scanning,
  saving), N of M images, scanned, cached and failed counts, the last finished image, and an estimate once 5 images
  have been scanned. When the scan ends, the page reloads once to show the finished run. Cancel stops the scan once the
  images in flight finish. The run history lists every run, newest first, 25 per page, with status, scope, packages,
  images, failures and duration; only `ok` and `partial` runs link to their results. Ctrl-C on `kubedelos ui` cancels
  a running scan, waits up to 10 seconds for the images in flight, then kills any Trivy process still running.

Add `?run_id=N` to pin a page to one run.

Each scan run holds a lock file under the data directory for as long as it runs. A run left
`running` by a process that died (killed, crashed, or a laptop that went to sleep for good) has no live lock, so
`kubedelos ui` marks it `failed` at startup, printing a note such as `note: closed 2 interrupted runs`, and again before
each UI scan starts. A scan still running in another process holds its lock and is never touched.

## What gets scanned

A scan covers the images of running pods, including init and ephemeral containers, plus the pod templates of CronJobs
and of Deployments and StatefulSets scaled to zero. The Scans page narrows it, for one scan, by namespaces, namespace
exclusions, a namespace label selector, a pod and workload label selector, and image exclusions; the defaults come from
the [configuration](#configuration).

Selectors use kubectl syntax (`team=payments,env!=dev`) and are applied by the API server. Deployments, StatefulSets and
CronJobs that are scanned as templates match the label selector on their own labels, which can differ from their pod
template labels. Image exclusions are globs matched against the normalised image name and the short Docker Hub forms,
so `nginx:*` skips `nginx:1.19` and `docker.io/library/nginx:1.19` alike, and excluded images are never scanned. Anchor
patterns on the registry and repository (`registry.example/vendor/*`, not `*vendor*`), because `*` also matches across
`/` and `:`, and a broad pattern could match an image someone named to fit it. Each run records its scope, so runs that
covered different things are never compared as if they were the same.

By default both OS packages and application libraries are scanned. OS packages only skips the 1.5 GB Trivy Java DB;
libraries only scans application dependencies. Each finding records its class (`os` or `library`), and cached results
are kept per level, so a narrower scan never answers for a wider one.

Results are cached for 24 hours by image digest, so a repeat scan only scans what changed. An image the node reports
without a registry digest, such as kind's preloaded images, is cached by its local image ID instead, and only when
Trivy scanned that exact image. An image known only by its tag is scanned every time, since a tag can be pushed again.

A namespace or resource kubedelos may not list is skipped with a warning, and the run is marked incomplete. A forbidden
node list only costs detail: the platform falls back to the most common one.

## Configuration

Settings come from environment variables. `kubedelos ui --context` and `--kubeconfig` win over theirs, and the Scans
page can change the scope, parallelism and package types for one scan.

| Variable | Default |
| -------- | ------- |
| `KUBEDELOS_KUBECONFIG` | the standard kubeconfig lookup |
| `KUBEDELOS_CONTEXT` | the current context |
| `KUBEDELOS_NAMESPACES` | all namespaces |
| `KUBEDELOS_EXCLUDE_NAMESPACES` | none |
| `KUBEDELOS_NAMESPACE_SELECTOR` | none |
| `KUBEDELOS_SELECTOR` | none |
| `KUBEDELOS_EXCLUDE_IMAGES` | none (JSON list of globs) |
| `KUBEDELOS_PARALLELISM` | `4` images at once (1 to 32) |
| `KUBEDELOS_PKG_TYPES` | `os,library` (comma-separated: `os`, `library` or both) |
| `KUBEDELOS_SCAN_TIMEOUT_S` | `600` seconds per image |
| `KUBEDELOS_TRIVY_PATH` | the pinned Trivy |
| `KUBEDELOS_CACHE_DIR` | the user cache dir (`~/.cache/kubedelos` on Linux, `~/Library/Caches/kubedelos` on macOS): Trivy binary and DB |
| `KUBEDELOS_DATA_DIR` | the user data dir (`~/.local/share/kubedelos` on Linux, `~/Library/Application Support/kubedelos` on macOS): `kubedelos.db` |
| `KUBEDELOS_OWNER_ANNOTATION` | `kubedelos.io/owner-email` |
| `KUBEDELOS_TEAM_LABEL` | `kubedelos.io/team` |

List variables take a JSON list, not a comma-separated string (`KUBEDELOS_PKG_TYPES` is the exception: `os,library`):

```bash
KUBEDELOS_NAMESPACES='["team-a","team-b"]' kubedelos ui
```

Inside a pod with no kubeconfig, kubedelos uses the in-cluster service account. It never does that when a context or kubeconfig is set.

## Compatibility

| Area | Supported | Notes |
|---|---|---|
| Python | 3.12, 3.13, 3.14 | Each is tested in CI. |
| Runs on | Linux and macOS, amd64 and arm64 | Windows is not supported. |
| Trivy | v0.76.1, pinned and checksum-verified | `KUBEDELOS_TRIVY_PATH` runs your own binary; its results are not cached. |
| Kubernetes | 1.35, tested on kind | Read-only `list` calls on stable APIs only: `v1` namespaces, pods and nodes, `apps/v1` Deployments and StatefulSets, `batch/v1` CronJobs. Secrets are never read. |
| Image platforms | Linux images | Tested on `linux/arm64` nodes. Windows nodes' images are scanned for their own platform but are untested. |
| Registries | Public registries, and private ones through your Docker credentials | Tested with Docker Hub and `registry.k8s.io`. See [Private registries](#private-registries) for ACR, Artifact Registry and ECR logins. |

Managed clusters (AKS, EKS, GKE) are not yet verified; they come with the in-cluster mode.

## Trivy

kubedelos runs a pinned Trivy release (v0.76.1) as one standalone process per image, sharing one locked DB cache. It runs on Linux and macOS (amd64 and arm64); Windows is not supported. `kubedelos trivy install` downloads it
and checks it against an embedded SHA-256. It never resolves "latest". Set `KUBEDELOS_TRIVY_PATH` to bring your own binary. Results from your own binary are
not cached and the run records its Trivy version as `custom`.

kubedelos is built on [Trivy](https://github.com/aquasecurity/trivy), an open source scanner by Aqua Security,
licensed under Apache-2.0. kubedelos is an independent project, not affiliated with or endorsed by Aqua Security.

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
other errors. When images fail registry auth in a scan, the dashboard lists them with the command to log in to each
registry. Registry auth for the in-cluster mode (workload identity, pull secrets) comes with the Helm chart.

## License

Apache-2.0
