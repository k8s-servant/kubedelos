# kubedelos Helm chart

[kubedelos](https://github.com/k8s-servant/kubedelos) scans the container images running in a Kubernetes cluster with
a pinned Trivy, keeps every run in SQLite and shows what to fix first: each finding gets a risk score from its severity,
known exploitation (CISA KEV, EPSS), how exposed the workload is, whether it can reach the node and what its
ServiceAccount may do.

This chart runs `kubedelos serve`: the web UI for one cluster, a scheduled sweep (03:00 UTC by default) and retention
of old runs. It runs one hardened replica (non-root, read-only root filesystem) with a volume for the database, a
read-only ClusterRole that never reads Secrets, and a NetworkPolicy. The image bundles the pinned Trivy.

## Install

```bash
helm install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster
```

`clusterName` is required: it is the name the runs are stored under. Nothing is reachable from outside the cluster
after the install. To open the UI:

```bash
kubectl port-forward svc/kubedelos 8080:80 -n kubedelos
```

and open `http://localhost:8080`.

**Anyone who can reach the UI can read every finding and, by default, start scans and accept risks.** Set
`readOnly: true`, keep it cluster-internal, or put it behind a sign-in proxy before you expose it.

## Main values

| Value | Default | What it does |
|---|---|---|
| `clusterName` | `""` | Required. The name the runs are stored under. |
| `scope.namespaces`, `scope.excludeNamespaces` | `[]` | What a scan covers; empty means every namespace. |
| `sweep.schedule`, `sweep.timezone` | `0 3 * * *`, `UTC` | When the scheduled sweep runs. |
| `retentionDays` | `180` | How long runs are kept; `0` keeps every run. |
| `attackSurface.enabled` | `true` | Records exposure, host access and RBAC facts for the risk score (list calls only). |
| `threatFeeds.enabled` | `false` | Downloads CISA KEV and EPSS once a day; needs egress to `www.cisa.gov` and `epss.empiricalsecurity.com`. |
| `readOnly` | `false` | Makes the UI view-only. |
| `persistence.size` | `10Gi` | The volume for the SQLite database. |
| `cloud.provider` | `none` | `azure`, `aws` or `gcp`: workload identity for ACR, ECR or Artifact Registry. |
| `ingress.enabled`, `httpRoute.enabled` | `false` | Expose the UI through an Ingress or a Gateway API HTTPRoute. |

Every value, the security model and the registry guides are in
[Running kubedelos in a cluster](https://github.com/k8s-servant/kubedelos/blob/main/docs/in-cluster.md).

## Verify a release

The image and the chart are signed keylessly with cosign by the release workflow:

```bash
IDENTITY='^https://github.com/k8s-servant/kubedelos/\.github/workflows/release-please\.yml@refs/heads/main$'
ISSUER=https://token.actions.githubusercontent.com

cosign verify ghcr.io/k8s-servant/charts/kubedelos:<release> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
cosign verify ghcr.io/k8s-servant/kubedelos:<release> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```
