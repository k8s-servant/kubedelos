# Install

kubedelos runs in two ways:

- **On your machine:** `kubedelos ui` serves a local web UI against your kubeconfig and scans from there. Nothing is
  installed in the cluster. Start here.
- **In the cluster:** the Helm chart runs `kubedelos serve`, which sweeps one cluster on a schedule and serves the same
  UI to your team. See [In a cluster](#in-a-cluster).

## What you need

| | |
|---|---|
| Python | 3.12, 3.13 or 3.14 |
| OS | Linux or macOS, amd64 or arm64; on Windows, inside [WSL2](#on-windows) |
| Disk | about 160 MB for Trivy, about 1.6 GB for its vulnerability DB, and 1.5 GB more for its Java DB when application libraries are scanned (the default) |
| Network | GitHub (the Trivy download), the registries Trivy fetches its DBs from, your image registries, and `www.cisa.gov` and `epss.empiricalsecurity.com` for the [threat feeds](risk-score.md#the-threat-feeds) |
| Cluster | a kubeconfig context that may `list` the resources below |

## Install on your machine

With [pipx](https://pipx.pypa.io) or [uv](https://docs.astral.sh/uv/):

```bash
pipx install kubedelos        # or: uv tool install kubedelos
kubedelos version
```

To run the latest `main` instead of a release: `pipx install git+https://github.com/k8s-servant/kubedelos`.

To upgrade, run `pipx upgrade kubedelos` (or `uv tool upgrade kubedelos`). The database schema is migrated on the next
start and is not migrated back, so keep a copy of `kubedelos.db` if you may want to downgrade.

### On Windows

kubedelos doesn't run natively on Windows yet ([#110](https://github.com/k8s-servant/kubedelos/issues/110)). Run it
inside [WSL2](https://learn.microsoft.com/windows/wsl/install) instead, where it sees an ordinary Linux machine:

1. Install a distribution with Python 3.12 or later, for example `wsl --install -d Ubuntu-24.04`.
2. In the WSL2 shell, install kubedelos as above (`pipx install kubedelos`).
3. Give WSL2 its own kubeconfig and logins. kubedelos reads `~/.kube/config` and `~/.docker/config.json` inside the
   distribution, not the Windows ones. Copy the kubeconfig over, or point `KUBECONFIG` at it:
   `export KUBECONFIG=/mnt/c/Users/<you>/.kube/config`. A context whose login runs a helper, such as `kubelogin`,
   `aws` or `gke-gcloud-auth-plugin`, needs that helper installed inside WSL2 too.
4. Run `kubedelos ui`. WSL2 forwards `localhost` to Windows, so the printed URL opens in your Windows browser. If no
   browser opens, copy the URL from the terminal.

Keep the data in the WSL2 file system (the default). A `KUBEDELOS_DATA_DIR` under `/mnt/c` is slow and SQLite's file
locks are unreliable there.

### Trivy

kubedelos runs a pinned Trivy (v0.76.1). The first scan downloads it from GitHub and checks it against a SHA-256 built
into kubedelos; it never resolves "latest". To download it ahead of time, for example before going offline:

```bash
kubedelos trivy install
```

To use a Trivy you already have, set `KUBEDELOS_TRIVY_PATH`. It must be v0.54.0 or later, and its results are not
cached. See [How a scan works](how-scans-work.md#3-trivy-the-pinned-binary).

## First scan

```bash
kubedelos ui
```

It opens the UI in your browser against your current kube-context (`--context` picks another one). Open the Scans page
and press Scan: kubedelos lists the workloads, scans each unique image once and shows the results on the dashboard.
A scan uses the context's own login, as kubectl does, so log in with kubectl first if the login opens a browser or asks
for a device code. [The local web UI](ui.md) describes each page.

### Cluster permissions

Every call is read-only; kubedelos never changes the cluster and reads no Secrets. Your identity needs `list` on:

- `namespaces`, `pods` and `nodes`;
- `deployments` and `statefulsets` (`apps`), and `cronjobs` (`batch`), for workloads scaled to zero and CronJobs;
- for the [attack-surface facts](attack-surface.md#what-is-recorded): `serviceaccounts`, `services`, `ingresses`,
  `httproutes`, `networkpolicies`, `roles`, `rolebindings`, `clusterroles` and `clusterrolebindings`.

What it may not list is skipped with a warning and the run is marked incomplete; it never reads as "no findings". The
Helm chart's ClusterRole grants the same lists to `kubedelos serve`.

### Private registries

Scans use the Docker credentials you already have: `DOCKER_CONFIG`, or `~/.docker/config.json`, including credential
helpers. Log in the way you normally would:

- any registry: `docker login registry.example`
- Azure Container Registry: `az acr login --name myregistry`
- Google Artifact Registry: `gcloud auth configure-docker europe-docker.pkg.dev`
- Amazon ECR: the [ECR credential helper](https://github.com/awslabs/amazon-ecr-credential-helper), or
  `aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com`

Check access to one image with:

```bash
kubedelos registry test registry.example/team/app:1.2.3
```

It exits 0 when the image is readable, 1 when the registry refuses access or the image is not found, and 2 for other
errors. When images fail registry auth in a scan, the dashboard lists them with the command to log in to each registry.

### Your agent

To ask your coding agent about the results, add the read-only MCP server:

```bash
claude mcp add kubedelos -- kubedelos mcp
```

[Ask your agent](mcp.md) covers VS Code Copilot and the other clients.

## In a cluster

The chart installs `kubedelos serve` with a read-only ClusterRole, a NetworkPolicy and a volume for the data. The image
bundles the pinned Trivy.

```bash
helm install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster
```

To run an unreleased `main`, build the image and install the chart from a clone. On a kind cluster:

```bash
git clone https://github.com/k8s-servant/kubedelos && cd kubedelos
docker build -t kubedelos:dev .
kind load docker-image kubedelos:dev --name my-cluster
helm install kubedelos ./charts/kubedelos --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster --set image.repository=kubedelos,image.tag=dev,image.pullPolicy=Never
```

For another cluster, push the image to a registry it can pull from and set `image.repository` and `image.tag` to it.

**Anyone who can reach the UI can read every finding and, by default, start scans and accept risks.** Read
[Running kubedelos in a cluster](in-cluster.md) before exposing it: it has every value, the security model, how to
put the UI behind a sign-in proxy, and how to verify a release with cosign. The registry guides cover
[ACR](registries/acr.md), [ECR](registries/ecr.md), [GAR](registries/gar.md) and
[pull secrets](registries/pull-secrets.md).

## Where kubedelos keeps its files

| | macOS | Linux | Override |
|---|---|---|---|
| Data: `kubedelos.db`, every run | `~/Library/Application Support/kubedelos` | `~/.local/share/kubedelos` | `KUBEDELOS_DATA_DIR` |
| Cache: Trivy, its DBs, layer caches | `~/Library/Caches/kubedelos` | `~/.cache/kubedelos` | `KUBEDELOS_CACHE_DIR` |

The Settings page shows the ones in use. Registry tokens are never written to either.

## Uninstall

```bash
pipx uninstall kubedelos       # or: uv tool uninstall kubedelos
```

Then delete the data and cache directories above to remove the scan history and the Trivy downloads. In a cluster,
`helm uninstall kubedelos -n kubedelos` removes the release, including the PVC and the database on it, unless you
set `persistence.existingClaim`.
