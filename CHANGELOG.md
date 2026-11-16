# Changelog

## Unreleased

### Features

- Package skeleton with the `kubedelos` entrypoint.
- Scans start from the web UI; there is no `kubedelos scan` command, since CI gating is left to plain Trivy.
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

### Bug Fixes

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
