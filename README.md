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

`kubedelos ui` serves a web UI on top of the scan data in your local SQLite database, and can start scans of any
context in your kubeconfig. It listens on loopback only (`127.0.0.1`, `::1` or `localhost`; other hosts are refused), prints a URL with a
token, and opens it in your browser:

```bash
kubedelos ui                          # http://127.0.0.1:9370/?token=...
kubedelos ui --port 9400 --no-browser
```

The token is swapped for a session cookie and stays valid until the server stops; a restart prints a new one. If the port
is in use, it exits 2 with `error: port N is in use; pass --port`. `--kubeconfig` chooses the kubeconfig, and `--context`
the context shown first (the current one by default). `KUBEDELOS_LOG_LEVEL=info` prints one access line (path only) per
request on stderr.

With more than one context, the sidebar's context card opens a list of them: every context in the kubeconfig, which is
read again on each page, plus any that only appear in the scan history, each with when it was last scanned. Picking one
shows that cluster on the same page. The context travels in the URL (`?context=prod-eu`), so two tabs can show two
clusters and a link keeps its cluster. A context known only from the history can be viewed but not scanned.

A scan runs the context's kubeconfig login, as kubectl does. If that login needs a browser or a device code (`kubelogin`,
`aws sso`, `gcloud`), it happens in the terminal running `kubedelos ui`, and the scan fails with an error if nobody
completes it; log in with kubectl first.

To use it on a remote machine, forward the port over SSH and open the printed URL locally:

```bash
ssh -L 9370:127.0.0.1:9370 my-host
```

Keep the same port on both ends: the UI checks the `Host` header against the port it listens on, so `-L 9400:...` fails.

Every page has a sidebar with the kube-context and a freshness dot that turns from green to amber once the shown run is
over 24 hours old, and a footer naming the Trivy that scanned it ("Scanned with Trivy v0.76.1", or "a custom Trivy" for
`KUBEDELOS_TRIVY_PATH` runs); below 760 px the sidebar becomes a top bar, which leaves the footer out. The page head names the
run in chips: its number (counted per cluster, so each cluster's first run is Run 1), scope, package types, age, image count and failures, and whether it is pinned or stale. The UI
follows the system light or dark theme.

- **Dashboard (`/`)**: the latest whole-cluster run, with an incomplete marker when some namespaces could not be listed.
  KPI tiles show the change against the previous comparable run; the all findings tile carries a severity bar and a
  legend whose entries link to the findings. A Worst images panel ranks images by Critical and High, and a fix-first list
  is grouped by fix, or by image with `?by=image`. Failed images are counted by kind (timeout, not_found, auth...), one
  line each with what it means and a link to just those failures, plus a registry login hint and, where the run can be
  retried, a Retry button. A newer, narrower run is mentioned with a link to its findings.
- **Findings (`/findings`)**: filter by URL query (`severity`, `namespace`, `cve`, `package`, `has_fix`, `pkg`, `q`,
  `accepted`), sort, 100 per page. **download CSV** (`/findings.csv`, same parameters) saves every row of the view as
  filtered, streamed, with cells a spreadsheet would run as a formula prefixed with `'`. Accepted findings are hidden by default (`accepted=hide`; `only` and `all` show them
  with a badge), and the page says how many it left out. Each row has an **Accept…** link.
- **Namespaces (`/namespaces`)**: one row per namespace of the dashboard's run, worst first (Critical, then High),
  with owner, team, a count per severity, the total and the images. Every column sorts; `q` filters by namespace,
  owner or team, and `has` keeps namespaces with at least one finding of a severity. A namespace counts a finding when
  the finding's image runs there, as the findings page's namespace filter does, so each count links to exactly those
  findings.
- **Reports (`/reports`)**: the place to produce a report. Pick a run of the shown cluster (newest first) and open its
  print report, or pick a run and the findings filters (severity, namespace, fix, package class, accepted; Critical and
  High ticked) and download the CSV. The forms send what `/report` and `/findings.csv` take, so a CSV from here holds
  the same rows as the Findings page with those filters.
- **Report (`/report`)**: a print sheet of the dashboard's run (or `?run_id=`): cluster, run, scope, the counts per
  severity, the fix-first list (50 fixes, with how many accepted findings it leaves out) and the failed images. Print
  it, or save it as PDF, from the browser; the sidebar is left off the print. Linked from the Reports page, the
  dashboard's Fix first card and each run in the Scans history.
- **Compare (`/diff`)**: what changed between two runs of the shown cluster. By default it compares the dashboard's run
  with its previous comparable run; `from` and `to` (or the two pickers) choose any two. Images are matched by
  repository, so a tag bump reads as a changed image and a CVE that survives it stays open instead of showing as fixed
  and new. Tiles count new findings, fixed or gone, and images added, gone and changed; tables list the findings worst
  first, 100 at most with the real total. A difference in scope or package types, failed images or coverage gaps is
  named above the numbers. A finding open in both runs is only counted ("still open"), even if its severity or fix
  changed. The dashboard's change figures and each run in the Scans history link here.
- **Failed images (`/scans/<run>/failed`)**: every image of a run that failed to scan, named as `repo:tag` plus a short
  digest, with platform, error kind, namespaces and the cause in a few words ("tag 1.2 is not in the registry"). The full
  ref and the redacted error text are folded away under each row, and auth failures add registry login hints. A pill per
  kind, with its count, narrows the list (`?kind=timeout`). It is linked from the failed count in the Scans history, from the dashboard's Failed images panel and from the progress readout, which also
  lists the newest failures while the scan runs. An image that fails with a passing network error (an interrupted
  download, a reset connection, a 502/503/504 or 429 from the registry) is scanned once more after 2 seconds before it
  counts as failed, and is marked "retried" when the second attempt fails too. Timeouts, auth and not-found errors are
  not retried.
  - **Retry failed images:** the newest run of a cluster, once it finished partial, has a "Retry failed images" form
    here (and a "retry" link in the Scans history). It scans the run's failed images of the ticked kinds again (every
    kind but `not_found` at first, or just the kind the page is narrowed to), with the run's
    package types, a time limit per image (default 3× `KUBEDELOS_SCAN_TIMEOUT_S`, 60–3,600 s) and 2 parallel images
    by default, and puts the results into the same run: it becomes `ok` once nothing fails. The cluster is not read;
    the refs and workloads come from the run. It takes the one scan slot and shows its progress on the Scans page, and
    leaves a note on this page ("retried 17 failed images (timeout) at 12:40 UTC: 15 scanned, 2 still failing"). Large
    images that ran out of time usually pass with a longer limit and fewer parallel images; a `not_found` image is gone
    from the registry and fails again until its tag is pushed.
- **Accepted (`/accepted`)**: the accepted risk register. An acceptance names a CVE, a reason, an owner (your OS user
  by default) and an expiry (90 days by default, at most a year), and optionally a namespace, an image repository (any
  tag) and a package. It applies to its cluster, or to all clusters when you choose so. It takes the findings it covers
  off the fix-first list and the findings page until it expires or is revoked; KPIs, the severity bar, the namespaces
  page and every other count stay as they are. A finding stays on the work lists while its image also runs in a
  namespace the acceptance doesn't name. Each entry shows its state, days left and how many findings it covers in the
  dashboard's run, and is flagged when it covers nothing.
- **Scans (`/scans`)**: start a scan of the shown context; the button names it. The form takes namespaces, namespace exclusions, a namespace
  selector, a label selector, image exclusions, the number of images scanned in parallel (1–32) and package types, each
  prefilled from your settings and labelled with the saved value. What you change applies to that scan only.
  The UI runs one scan at a time, across all contexts; a second start while one runs is refused, and the other
  contexts' Scans pages name the cluster being scanned. A scan from another `kubedelos ui` doesn't block it. Progress updates every 2 seconds without a reload: the phase (Trivy DB, inventory, scanning,
  saving), N of M images, scanned, cached and failed counts, the last finished image, and an estimate once 5 images
  have been scanned. When the scan ends, the page reloads once to show the finished run. Cancel stops the scan once the
  images in flight finish. The run history lists every run, newest first, 25 per page, with status, scope, packages,
  images, failures and duration; only `ok` and `partial` runs link to their results. Ctrl-C on `kubedelos ui` cancels
  a running scan, waits up to 10 seconds for the images in flight, then kills any Trivy process still running.
  Each finished run's duration links to its scan times.
- **Scan times (`/scans/<run>/times`)**: where a run's scanning time went. Each image's scan is timed, from start to
  result with downloads and a retry included, and stored with its result (schema migration 9). The page lists the 50
  slowest images with their result, and sums up: images timed, cached, the times added up, the longest, and the part
  the ten slowest took, which tells a few huge images from many ordinary ones. The failures page shows each failure's
  time too. Runs scanned before this have no times.
- **Settings (`/settings`)**: every setting this `kubedelos ui` started with, read-only, with its `KUBEDELOS_*`
  variable (or flag), its value and where the value came from (flag, environment or default), then the database file,
  the data and cache directories, the Trivy in use and the log level. No credentials are listed: kubedelos holds none,
  and registry logins stay in Docker's own config.

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
