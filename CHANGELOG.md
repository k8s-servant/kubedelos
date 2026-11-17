# Changelog

## Unreleased

### Features

- Rescan every image: a box on the Scans form skips the 24-hour result cache for one scan, so every image is matched against the current Trivy DB. Fresh results still go into the cache.
- A guide, [How a scan works](docs/how-scans-work.md), explains each step of a scan, the result cache, the Trivy DBs and the layer cache (what, where, why and how long), parallelism and time limits, failure kinds and retries, how to speed up a slow scan, and what is kept on disk.
- Package skeleton with the `kubedelos` entrypoint.
- An About page (last in the sidebar) says how fresh the data is: when Trivy built the vulnerability and Java DBs in use, whether a newer one is out (the next scan downloads it) and when the shown context was last scanned. It also names the kubedelos, Trivy and Python versions, the license, the project links with the security policy, and what kubedelos never does.
- Layer cache: each parallel scan keeps Trivy's layer cache on disk between runs, in a slot of its own (Trivy locks the cache for a whole scan), so a rescan only analyses layers it has not seen; a warm rescan of a JDK image took 1.8 s instead of 11 s. A slot another `kubedelos ui` is using is skipped, a scan with no free slot keeps its cache in memory as before, each repository goes back to its own slot (one of 32, at most 128 MB each, emptied when over), and `KUBEDELOS_LAYER_CACHE=false` turns it off.
- Retry by kind: the retry form ticks a box per kind of failure, with its count, so a retry can skip images that will fail again. Every kind but `not_found` is ticked at first (only the shown kind when the page is narrowed), and the note a retry leaves counts only the images it retried. The form's limits and button now line up on one row.
- Scans start from the web UI; there is no `kubedelos scan` command, since CI gating is left to plain Trivy.
- Scan times: each image's scan is timed and stored with its result (schema migration 9). A page per run lists the slowest images and how the time was spent, linked from each run's duration in the Scans history and from the failures page, which shows each failure's time.
- A Settings page lists every setting the UI started with, its value and where it came from (flag, environment or default), plus the database file, data and cache directories, the Trivy in use and the log level. It is read-only and lists no credentials.
- A Reports page in the sidebar picks a run and opens its print report, or picks a run and the findings filters and downloads the CSV.
- Reports: the findings page downloads its view as a formula-safe CSV (every row, streamed), and a print sheet of a run gives its numbers, fix-first list and failed images for printing or saving as PDF.
- Compare: a Compare page shows what changed between two runs of a cluster (new findings, fixed or gone, images added, gone and changed), matching images by repository so a tag bump does not read as everything fixed and everything new. It names scope differences, failed images and coverage gaps above the numbers.
- Retry failed images: the newest partial run of a cluster can scan its failed images again from the failures page, with a longer time limit and fewer parallel images, and the results go into the same run, which becomes `ok` once nothing fails. The cluster is not read, and each retry leaves a note on the run.
- Failed images read at a glance: the dashboard's card counts the failures by kind, one line each with what the kind means and a link to just those images, plus a Retry button where the run can be retried. The failures page names each image short (the full ref is folded away), gives the cause in a few words, and narrows to one kind with `?kind=`.
- Failed images: a page per run lists every image that failed to scan with its cause, linked from the Scans history, the dashboard and the progress readout, which also shows the newest failures while a scan runs. An image that fails with a passing network error (such as "unexpected EOF" mid-download) is retried once.
- Runs are numbered per cluster: each cluster's first run is Run 1, wherever the UI names a run. URLs keep the run id. Schema migration 8 numbers existing runs.
- Accepted risk: accept a CVE from any findings row (for one cluster or all, optionally narrowed to a namespace, an image repository or a package, with a reason, an owner and an expiry of at most a year). Accepted findings leave the fix-first list and the findings page until they expire or are revoked, and each list says how many it left out; counts never change. The Accepted page lists every entry with its state, days left and what it covers. Schema migration 7 adds the `acceptance` table.
- A Namespaces page lists each namespace of the dashboard's run, worst first, with owner, team, counts per severity and images; every column sorts, it filters by text and by severity, and each count links to exactly its findings.
- The UI shows every kube-context: the sidebar's context card opens a list of the kubeconfig's contexts (read on each page) and those in the scan history, with when each was last scanned. The shown context travels in the URL (`?context=`), and the Scans page scans it; one scan runs at a time across contexts.
- `kubedelos trivy install` downloads the pinned Trivy v0.76.1 release and checks it against an embedded, Sigstore-verified SHA-256. A scan runs one standalone Trivy per image and stops them when `kubedelos ui` exits on Ctrl-C or SIGTERM; `registry test` also stops on SIGHUP.
- A scan inventories a kube-context (running pods with their init and ephemeral containers, plus the templates of CronJobs and of workloads scaled to zero) and scans every unique image with Trivy.
- Digest cache so unchanged images are not rescanned.
- A namespace selector and a pod/workload label selector narrow a scan (kubectl syntax, applied by the API server), and image globs skip images before scanning. Each run records its scope.
- `KUBEDELOS_PKG_TYPES` (or the Scans form) chooses OS packages, application libraries or both (the default). Each finding records its package class, OS-only scans skip the Java DB, and cached results are kept per scan level.
- `kubedelos registry test <image>` checks that an image is readable with your current registry login, and the dashboard shows a login hint for registries that refuse access.
- Parallel scans, and scans from several `kubedelos ui` processes at once, share one Trivy DB cache safely; no local Trivy server or port is used.
- Owner attribution from the `kubedelos.io/owner-email` namespace annotation, recorded with every finding.
- RBAC-aware inventory: namespaces you may not list are skipped with a warning, and the run is marked incomplete.
- Images are shown as `repo:tag` plus a short digest.
- Environment variables are documented, including the JSON list format.
- `kubedelos ui` serves a local web UI (dashboard, findings and scans, with a sidebar layout, the radar logo, a light and dark theme, a Worst images panel and a sidebar footer naming the Trivy version of the shown run) on loopback only. The Scans page starts a scan of the UI's context, one at a time, with a form for the scope, the image exclusions, the parallel image count and the package types, with live progress (phase, image counts, the last finished image and an estimate), cancel, and a paged run history; Ctrl-C on `kubedelos ui` cancels a running UI scan and, after 10 seconds, kills any Trivy still running. The printed URL carries a token that is swapped for a session cookie and stays valid until the server stops (a restart prints a new one); `KUBEDELOS_LOG_LEVEL=info` prints an access line per request on stderr.
- The UI pages render in under 300 ms on a database of 1,000 images and 100,000 findings; schema migration 5 adds the indexes they need.
- Each scan run stores the namespaces and resources the inventory could not list, so the UI marks such runs incomplete.
- Each scan run holds an owner lock file while it runs. `kubedelos ui` closes runs left `running` with no live owner as `failed` at startup (printing, for example, `note: closed 2 interrupted runs`) and before each UI scan; a scan running in another process is never closed.

### Documentation

- The README leads with the web UI, explains why kubedelos exists next to plain Trivy, has a compatibility table (Python, operating systems, Trivy, Kubernetes, image platforms, registries) and credits Trivy.
- The README names the oldest Trivy a custom `KUBEDELOS_TRIVY_PATH` can be: v0.54.0, the first with `--pkg-types`.

### Bug Fixes

- The Scans form lines up: the parallel images box is styled like the other inputs (as are the retry form's number boxes), inputs, pills and the Scan button share one height and top edge, and the rescan hint fits on one line.
- Two kubedelos processes opening the same new or older database at once no longer fail with "duplicate column name" or "database is locked": each migration runs under the write lock and is skipped when the other process has already applied it.
- Image exclusions match images whose registry host is written in uppercase or as `index.docker.io`, the way image names are normalised.
- A run's scope ignores repeated namespaces and image exclusions, so such runs still compare with the same scope written once.
- `kubedelos registry test --platform` must be `os/arch[/variant]`; anything else is refused before Trivy runs.
- UI polish: the KPI tiles put the change line right under the number instead of at the tile bottom; the findings table names each image short (the full ref is its tooltip), so rows stay one line high; installed versions, with their "+N", never wrap; status chips use the mockup grey.
- The About and Settings pages give their label column one width on wide screens, so the values line up from card to card.
- The namespaces filter no longer answers 400 "invalid parameter: has" when "any severity" is selected, and a 400 page keeps the cluster it was shown for.
- Static files are served under a content-hashed URL, so a browser never pairs a new page with a stylesheet it cached from an older release.
- Images with no registry digest, such as kind's preloaded images, are now cached by their local image ID when Trivy scanned that exact image, so a repeat scan of a kind cluster takes seconds instead of rescanning every image.
- The local UI keeps at most 64 sessions, so repeated token visits no longer grow its memory.
- Restarting `kubedelos ui` on macOS no longer fails with 'port in use' while the previous run's connections close.
- Valid image refs with an uppercase or IPv6 registry host, repeated separators or a non-sha256 digest are no longer rejected.
- Locally loaded images (kind's `import-<date>` imageID) are scanned by their tag instead of a digest that no registry has.
- SIGTERM no longer leaves Trivy scans running and the run stuck in `running`.
- `--context` no longer falls back to the in-cluster config when the context does not exist.
- Kubernetes API calls time out instead of hanging.
- Pods on Windows nodes are scanned for `windows/<arch>` instead of `linux/<arch>`.
- A cached result that no longer validates is rescanned instead of failing the run.
- Results from a custom Trivy (`KUBEDELOS_TRIVY_PATH`) no longer enter the cache under the pinned Trivy version.
- Failed images, `registry test` and Trivy DB download errors show the cause Trivy reports (`MANIFEST_UNKNOWN`, `DENIED`, `no such host`) instead of the first 200 characters of its generic `FATAL` wrapper, and multi-line errors print on one line. Before Trivy errors are stored or printed, URL query strings and `user:password@`, bearer tokens and `token=`/`password=`-style values are redacted, so a signed storage URL doesn't leak its signature. This is best effort: other credential shapes aren't recognised.
- Error redaction also covers `Basic` and bare `Authorization` header values, JWT-shaped values, and colon forms such as `token: ...`, `password: ...`, `secret: ...` and `api-key: ...`, including JSON-quoted keys. Errors shown in the UI go through the same redaction.
