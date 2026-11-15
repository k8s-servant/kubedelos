# Changelog

## Unreleased

### Features

- Package skeleton with the `kubedelos` entrypoint.
- `kubedelos trivy install` downloads the pinned Trivy v0.76.1 release and checks it against an embedded, Sigstore-verified SHA-256. `kubedelos scan` runs one standalone Trivy per image and stops them on exit, Ctrl-C, SIGTERM or SIGHUP.
- `kubedelos scan` inventories a kube-context and scans every unique image with Trivy.
- Output formats: table, JSON, CSV (formula-safe) and SARIF, with `--fail-on` exit codes and `--allow-partial`.
- Digest cache so unchanged images are not rescanned.
- `--namespace-selector` and `-l/--selector` narrow a scan by namespace or pod/workload labels (kubectl syntax, applied by the API server), and `--exclude-image` skips images by glob before scanning. Each run records its scope.
- `--pkg-types` (`KUBEDELOS_PKG_TYPES`) chooses OS packages, application libraries or both (the default). Each finding records its package class, the CSV output gains a `pkg_class` column, OS-only scans skip the Java DB, and cached results are kept per scan level.
- `kubedelos registry test <image>` checks that an image is readable with your current registry login, and scans print a login hint for registries that refuse access.
- Parallel scans and concurrent `kubedelos scan` runs share one Trivy DB cache safely; no local Trivy server or port is used.
- Owner attribution from the `kubedelos.io/owner-email` namespace annotation, shown on every finding.
- RBAC-aware inventory: namespaces you may not list are skipped with a warning, and `--fail-on` fails closed on partial inventory.
- Every failed image is listed on stderr with its ref, platform, error kind and error.
- The table shows `repo:tag` plus a short digest; JSON, CSV and SARIF keep the full ref.
- Environment variables are documented, including the JSON list format.
- `kubedelos ui` serves a local web UI (dashboard, findings and scans, with a sidebar layout, the radar logo, a light and dark theme, a Worst images panel and a sidebar footer naming the Trivy version of the shown run) on loopback only. The Scans page starts a scan of the UI's context, one at a time, with a form for the scope, the image exclusions, the parallel image count and the package types, with live progress (phase, image counts, the last finished image and an estimate), cancel, and a paged run history; Ctrl-C on `kubedelos ui` cancels a running UI scan and, after 10 seconds, kills any Trivy still running. The printed URL carries a token that is swapped for a session cookie and stays valid until the server stops (a restart prints a new one); `KUBEDELOS_LOG_LEVEL=info` prints an access line per request on stderr.
- The UI pages render in under 300 ms on a database of 1,000 images and 100,000 findings; schema migration 5 adds the indexes they need.
- Each scan run stores the namespaces and resources the inventory could not list, so the UI marks such runs incomplete.
- Each scan run, from the CLI or the UI, holds an owner lock file while it runs. `kubedelos ui` closes runs left `running` with no live owner as `failed` at startup (printing, for example, `note: closed 2 interrupted runs`) and before each UI scan; a scan running in another terminal is never closed.

### Documentation

- The README has a compatibility table (Python, operating systems, Trivy, Kubernetes, image platforms, registries) and credits Trivy.

### Bug Fixes

- Images with no registry digest, such as kind's preloaded images, are now cached by their local image ID when Trivy scanned that exact image, so a repeat scan of a kind cluster takes seconds instead of rescanning every image.
- The local UI keeps at most 64 sessions, so repeated token visits no longer grow its memory.
- Restarting `kubedelos ui` on macOS no longer fails with 'port in use' while the previous run's connections close.
- Valid image refs with an uppercase or IPv6 registry host, repeated separators or a non-sha256 digest are no longer rejected.
- Locally loaded images (kind's `import-<date>` imageID) are scanned by their tag instead of a digest that no registry has.
- SIGTERM and SIGHUP no longer leave Trivy scans running and the run stuck in `running`.
- A forbidden node list, or a forbidden namespace list with `--namespace`, no longer makes `--fail-on` exit 2; real coverage gaps still do, and now say why.
- `--context` no longer falls back to the in-cluster config when the context does not exist.
- Kubernetes API calls time out instead of hanging.
- Pods on Windows nodes are scanned for `windows/<arch>` instead of `linux/<arch>`.
- A cached result that no longer validates is rescanned instead of failing the run.
- Results from `--trivy-path` no longer enter the cache under the pinned Trivy version.
- When `--fail-on` fires on findings hidden by `--severity`, the count is printed.
- Failed images, `registry test` and Trivy DB download errors show the cause Trivy reports (`MANIFEST_UNKNOWN`, `DENIED`, `no such host`) instead of the first 200 characters of its generic `FATAL` wrapper, and multi-line errors print on one line. Before Trivy errors are stored or printed, URL query strings and `user:password@`, bearer tokens and `token=`/`password=`-style values are redacted, so a signed storage URL doesn't leak its signature. This is best effort: other credential shapes aren't recognised.
- Error redaction also covers `Basic` and bare `Authorization` header values, JWT-shaped values, and colon forms such as `token: ...`, `password: ...`, `secret: ...` and `api-key: ...`, including JSON-quoted keys. Errors shown in the UI go through the same redaction.
