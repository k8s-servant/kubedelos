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

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Scan finished and no `--fail-on` threshold was reached |
| 1 | A finding at or above the `--fail-on` severity was found |
| 2 | With `--fail-on`: an image failed to scan or inventory was incomplete (for example a namespace you may not list), or a fatal error |
| 130 | Cancelled |

With `--fail-on` unset, image scan errors are only reported on stderr and the exit code stays 0, so check stderr before treating 0 as fully scanned.

Pass `--allow-partial` to accept an incomplete scan instead of exiting 2.

## Trivy

kubedelos runs a pinned Trivy release (v0.76.1) in server mode. `kubedelos trivy install` downloads it
and checks it against an embedded SHA-256. It never resolves "latest". Use `--trivy-path` to bring your own binary.

## Coming soon

`delos`, a web UI on top of the same scan data, is not available yet.

## License

Apache-2.0
