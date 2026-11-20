# kubedelos documentation

Start with [Install](install.md), then read what fits how you run kubedelos. The [README](../README.md) gives the
overview.

## Getting started

- [Install](install.md): requirements, installing on your machine or in a cluster, cluster permissions, registry
  logins, where files are kept, upgrading and uninstalling.
- [Configuration](configuration.md): every `KUBEDELOS_*` setting and its default.

## Using kubedelos

- [The local web UI](ui.md): what each page shows, contexts, using it on a remote machine.
- [Risk score](risk-score.md): how the fix-first order is worked out, and the CISA KEV and EPSS feeds behind it.
- [Attack-surface facts](attack-surface.md): what each scan records about a workload's exposure, host access and RBAC
  rights, and what "unknown" means.
- [Ask your agent](mcp.md): `kubedelos mcp`, the read-only MCP server for Claude Code, VS Code Copilot and others.

## Running it in a cluster

- [Running kubedelos in a cluster](in-cluster.md): the Helm chart's values, storage, exposing the UI, the security
  model and verifying a release.
- [Example: oauth2-proxy behind Envoy Gateway](exposure-oauth2-proxy-envoy-gateway.md): a sign-in proxy in front of
  the UI.

## Private registries in a cluster

- [Azure Container Registry from AKS](registries/acr.md)
- [Amazon ECR from EKS](registries/ecr.md)
- [Google Artifact Registry from GKE](registries/gar.md)
- [Pull secrets and Docker configs](registries/pull-secrets.md)

On your machine, kubedelos uses your Docker logins; see [Install](install.md#private-registries).

## How it works

- [How a scan works](how-scans-work.md): the inventory, what a scan covers, the caches and DBs, parallelism, time
  limits, failures and tuning a slow scan.

## Project

- [Contributing](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)
