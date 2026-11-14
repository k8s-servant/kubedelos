# Changelog

## 0.1.0 (2026-11-14)


### Features

* add --pkg-types to choose os packages, libraries or both ([#25](https://github.com/k8s-servant/kubedelos/issues/25)) ([18573d4](https://github.com/k8s-servant/kubedelos/commit/18573d4b06af17964077a136761c44a657e90d00))
* add kubedelos registry test and registry login hints ([#6](https://github.com/k8s-servant/kubedelos/issues/6)) ([818f93e](https://github.com/k8s-servant/kubedelos/commit/818f93edb65f1e89f63ef1a38b8a20f3477a88aa))
* add kubedelos ui with the dashboard and findings pages ([#29](https://github.com/k8s-servant/kubedelos/issues/29)) ([a84eb88](https://github.com/k8s-servant/kubedelos/commit/a84eb88f984bec6c2f8ab496bf564a08be161224))
* add label selectors and image exclusion to scan ([#26](https://github.com/k8s-servant/kubedelos/issues/26)) ([f3e92aa](https://github.com/k8s-servant/kubedelos/commit/f3e92aa6184253d531d9ca823914aa0e54b51a05))
* bootstrap repo and add kubedelos scan ([#1](https://github.com/k8s-servant/kubedelos/issues/1)) ([c5bc930](https://github.com/k8s-servant/kubedelos/commit/c5bc93096dfbb1e458f9735dba7acd35454bcf89))
* restyle kubedelos ui with a sidebar, radar logo and worst images panel ([#30](https://github.com/k8s-servant/kubedelos/issues/30)) ([38935df](https://github.com/k8s-servant/kubedelos/commit/38935df1c57ef04234db7d907160a4958427d49a))


### Bug fixes

* show the cause of trivy errors instead of their first 200 characters ([#27](https://github.com/k8s-servant/kubedelos/issues/27)) ([cf176f6](https://github.com/k8s-servant/kubedelos/commit/cf176f6632cef353acf3def2d55f4ba14ffdc645))

## Changelog

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
- `kubedelos ui` serves a local web UI (dashboard and findings, with a sidebar layout, the radar logo, a light and dark theme and a Worst images panel) on loopback only. The printed URL carries a token that is swapped for a session cookie and stays valid until the server stops (a restart prints a new one); `KUBEDELOS_LOG_LEVEL=info` prints an access line per request on stderr.
- The UI pages render in under 300 ms on a database of 1,000 images and 100,000 findings; schema migration 5 adds the indexes they need.
- Each scan run stores the namespaces and resources the inventory could not list, so the UI marks such runs incomplete.

### Bug Fixes

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
