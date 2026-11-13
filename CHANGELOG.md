# Changelog

## Unreleased

### Features

- Package skeleton with the `kubedelos` and `delos` entrypoints.
- `kubedelos trivy install` downloads the pinned Trivy v0.76.1 release and checks it against an embedded, Sigstore-verified SHA-256.
- `kubedelos scan` inventories a kube-context and scans every unique image with Trivy.
- Output formats: table, JSON, CSV (formula-safe) and SARIF, with `--fail-on` exit codes and `--allow-partial`.
- Pinned, checksum-verified Trivy v0.76.1 run in server mode and stopped on exit or cancel.
- Digest cache so unchanged images are not rescanned.
- Owner attribution from the `kubedelos.io/owner-email` namespace annotation, shown on every finding.
- RBAC-aware inventory: namespaces you may not list are skipped with a warning, and `--fail-on` fails closed on partial inventory.
