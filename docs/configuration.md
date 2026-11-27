# Configuration

Settings come from environment variables. `kubedelos ui --context` and `--kubeconfig` win over theirs, and the Scans
page can change the scope, parallelism and package types for one scan. `kubedelos serve` reads the same variables, and
the Helm chart sets them from its values (see [Running kubedelos in a cluster](in-cluster.md#values)). The UI's
Settings page shows every setting in use, its value and where the value came from.

## General

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
| `KUBEDELOS_LAYER_CACHE` | `true`: each parallel scan keeps Trivy's layer cache on disk (`<cache dir>/trivy-layers`, 32 slots of at most 128 MB) so a rescan skips layers it has seen; `false` keeps it in memory |
| `KUBEDELOS_TRIVY_PATH` | the pinned Trivy |
| `KUBEDELOS_CACHE_DIR` | the user cache dir (`~/.cache/kubedelos` on Linux, `~/Library/Caches/kubedelos` on macOS): Trivy binary, DB and layer caches |
| `KUBEDELOS_DATA_DIR` | the user data dir (`~/.local/share/kubedelos` on Linux, `~/Library/Application Support/kubedelos` on macOS): `kubedelos.db` |
| `KUBEDELOS_OWNER_ANNOTATION` | `kubedelos.io/owner-email` |
| `KUBEDELOS_TEAM_LABEL` | `kubedelos.io/team` |
| `KUBEDELOS_ATTACK_SURFACE` | `true`: record the [attack-surface facts](attack-surface.md) with each scan |
| `KUBEDELOS_THREAT_FEEDS` | `true`: download CISA KEV and EPSS at most once a day for the [risk score](risk-score.md) |
| `KUBEDELOS_RETENTION_DAYS` | `180`: runs older than this are deleted when `kubedelos ui` starts and after each `serve` sweep, except the newest run of each comparable scan; `0` keeps every run |

List variables take a JSON list, not a comma-separated string (`KUBEDELOS_PKG_TYPES` is the exception: `os,library`):

```bash
KUBEDELOS_NAMESPACES='["team-a","team-b"]' kubedelos ui
```

Inside a pod with no kubeconfig, kubedelos uses the in-cluster service account. It never does that when a context or kubeconfig is set.

## Logging

`KUBEDELOS_LOG_LEVEL=info` makes `kubedelos ui` print one access line (path only) per request on stderr.

## `kubedelos serve`

These only matter to the in-cluster mode.

| Variable | Default |
| -------- | ------- |
| `KUBEDELOS_CLUSTER_NAME` | required: the name runs are stored under |
| `KUBEDELOS_SWEEP_SCHEDULE` | `0 3 * * *` (5-field cron) |
| `KUBEDELOS_SWEEP_TIMEZONE` | `UTC` (an IANA name such as `Europe/Vilnius`) |
| `KUBEDELOS_SWEEP_ENABLED` | `true`; `false` turns the schedule off |
| `KUBEDELOS_READ_ONLY` | `false`; `true` refuses every write |
| `KUBEDELOS_TRUST_PROXY_HEADERS` | `false`; `true` reads the user's name from the identity header |
| `KUBEDELOS_IDENTITY_HEADER` | `X-Auth-Request-Email` |
| `KUBEDELOS_ALLOWED_HOSTS` | `localhost,127.0.0.1`: the `Host` header values the UI answers to (`/healthz` answers to any) |

Two more settings serve the container image: `KUBEDELOS_TRIVY_DIR` names a directory holding `<version>/trivy`, used
before the cache and never downloaded over (the image sets it to its bundled Trivy), and `KUBEDELOS_SECURE_COOKIES`
(default `false`; the chart sets `true`) marks the CSRF cookie `Secure`, for a UI reached over HTTPS.

## Registry credentials (set by the chart)

The chart sets these from its `registries` values; they are listed so the Settings page reads clearly.

| Variable | What it holds |
| -------- | ------------- |
| `KUBEDELOS_DOCKER_CONFIGS` | mounted Docker `config.json` files (JSON list of paths); see [Pull secrets and Docker configs](registries/pull-secrets.md) |
| `KUBEDELOS_POD_PULL_SECRET_NAMESPACES` | the namespaces whose pods' pull secrets kubedelos may read |
| `KUBEDELOS_SECRETS_DIR` | the memory-backed directory for each scan's Docker config, deleted when the scan ends |
| `KUBEDELOS_CLOUD_PROVIDER` | `azure`, `aws`, `gcp` or `none`: the workload identity Trivy uses for [ACR](registries/acr.md), [ECR](registries/ecr.md) or [GAR](registries/gar.md) |
| `KUBEDELOS_CLOUD_IDENTITY` | that identity's client id or role name, never a token |

## Related

- [Install](install.md): where kubedelos keeps its files, and how to bring your own Trivy.
- [How a scan works](how-scans-work.md): what the scan settings change.
- [All guides](README.md)
