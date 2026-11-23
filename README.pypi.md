# kubedelos

<!-- mcp-name: io.github.k8s-servant/kubedelos -->

Scan the container images running in a Kubernetes cluster with Trivy, from a local web UI.

Status: pre-alpha. Interfaces and output may change.

```bash
pipx install kubedelos        # or: uv tool install kubedelos
kubedelos ui
```

`kubedelos ui` opens a local web UI against your current kube-context. Start a scan on the Scans page: kubedelos lists
the images running in the cluster (read-only, never reading Secrets), scans each unique image once with a pinned,
checksum-verified Trivy, and keeps every run in a local SQLite database. The dashboard shows:

- the Critical and High findings that have a fix, grouped by fix or by image;
- the images worst hit, and the images that failed to scan, with a registry login hint;
- the change since the last comparable run.

Trivy does the scanning and kubedelos doesn't replace it; kubedelos is for what comes after the report, across a whole
cluster and over time. An in-cluster mode with scheduled scans and reports to namespace owners is next on the roadmap.

Documentation, configuration and compatibility: <https://github.com/k8s-servant/kubedelos#readme>

kubedelos is built on [Trivy](https://github.com/aquasecurity/trivy), an open source scanner by Aqua Security, licensed
under Apache-2.0. kubedelos is an independent project, not affiliated with or endorsed by Aqua Security.

License: Apache-2.0
