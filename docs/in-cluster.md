# Running kubedelos in a cluster

The Helm chart installs `kubedelos serve`: one pod that serves the UI of one cluster, sweeps it on a cron schedule and
keeps the results in SQLite on a volume. It reads the cluster through a read-only ClusterRole (`get` and `list` on
namespaces, pods and nodes, `list` on deployments, statefulsets and cronjobs) and nothing else. It reads no Secrets,
unless you turn on pod pull secrets, which adds a `get`-only Role in each namespace you list (see
[private registries](#private-registries)).
The chart turns the [attack-surface facts](attack-surface.md) off (`KUBEDELOS_ATTACK_SURFACE=false`) because it grants
no RBAC for their lists yet; that is a follow-up.
It also turns the [threat feeds](risk-score.md#the-threat-feeds) off (`KUBEDELOS_THREAT_FEEDS=false`), because many
clusters give pods no egress to the internet; see [Threat feeds](#threat-feeds) to turn them on.
The image bundles the pinned Trivy, so the pod downloads no scanner, only the vulnerability DBs.

Without any registry setting a scan reads public images, and whatever the node's own identity lets Trivy reach. For
private images see [Private registries](#private-registries).

## Install

```bash
helm install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster
```

`clusterName` is required: it is the name the runs are stored under. The chart names its objects (Service,
Deployment, PVC) `<release>-kubedelos`, or just the release name when that already contains `kubedelos`. The release is
called `kubedelos` here, so its Service is `kubedelos`; the examples below write `<release>-kubedelos` for the general
case, so use the name your release gets (`helm template` or `kubectl get svc -n kubedelos` shows it).
The chart always runs one replica with a `Recreate` strategy, because SQLite allows only one writer; the replica
count is not a value.

Nothing is reachable from outside the cluster after the install. To look at the UI from your machine:

```bash
kubectl port-forward svc/kubedelos 8080:80 -n kubedelos
```

and open `http://localhost:8080`. The first sweep runs at the next scheduled time (03:00 UTC by default). To scan
sooner, start a scan from the Scans page.

## Values

The chart rejects keys it does not know (`values.schema.json`).

| Key | Default | What it does |
| --- | ------- | ------------ |
| `image.repository` | `ghcr.io/k8s-servant/kubedelos` | The image. |
| `image.tag` | `""` | The image tag; empty means the chart's `appVersion`. |
| `image.digest` | `""` | `sha256:...`; wins over the tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | Pull secrets for the kubedelos image itself, if you mirror it. |
| `clusterName` | `""` | Required. The name runs are stored under. |
| `scope.namespaces` | `[]` | Namespaces to scan; empty means every namespace. A scan started from the UI can only narrow this. |
| `scope.excludeNamespaces` | `[]` | Namespaces to skip. |
| `scope.namespaceSelector` | `""` | Label selector on namespaces, for example `team=a`. |
| `scope.selector` | `""` | Label selector on pods and workloads. |
| `scope.excludeImages` | `[]` | Globs on the normalised image name. |
| `sweep.enabled` | `true` | Run the scheduled sweep. |
| `sweep.schedule` | `0 3 * * *` | Five-field cron. A sweep skips the 24-hour result cache. |
| `sweep.timezone` | `UTC` | An IANA name such as `Europe/Vilnius`. |
| `retentionDays` | `180` | Runs older than this are deleted; `0` keeps every run. |
| `scan.parallelism` | `4` | Images scanned at once. |
| `scan.timeoutSeconds` | `600` | Time limit for one image. |
| `readOnly` | `false` | `true` makes the UI view-only: every write gets a 403 and the pages hide their forms. Sweeps still run. |
| `auth.trustProxyHeaders` | `false` | Read the user's name from `auth.identityHeader`. Only behind a sign-in proxy; see [the security model](#security-model). |
| `auth.identityHeader` | `X-Auth-Request-Email` | The header that carries the name. |
| `secureCookies` | `true` | Mark the CSRF cookie `Secure`; see [Secure cookies](#secure-cookies). |
| `extraAllowedHosts` | `[]` | Host header values to answer to, besides the ones the chart adds (see [Hosts](#hosts)). |
| `clusterDomain` | `cluster.local` | Used for the Service's fully qualified DNS name. |
| `logLevel` | `info` | `info` prints an access line per request. |
| `persistence.size` | `10Gi` | Size of the volume (ReadWriteOnce). |
| `persistence.storageClassName` | `""` | Empty uses the cluster default class. |
| `persistence.existingClaim` | `""` | Use this claim instead of creating one. |
| `resources` | 100m CPU and 512Mi memory requested, 2Gi memory limit | With `scan.parallelism` 4, the 2Gi limit can be tight for large or Java images (several Trivy processes plus the Java DB). If scans are OOM-killed, raise `resources.limits.memory` or lower `scan.parallelism`. |
| `serviceAccount.annotations` | `{}` | The cloud preset's annotation is merged over these. |
| `cloud.provider` | `none` | `azure`, `aws`, `gcp` or `none`. Annotates the ServiceAccount for that cloud's workload identity (and labels the pod on Azure). Needs the matching id below. |
| `cloud.azure.clientId` | `""` | Client id of the managed identity. Required with `azure`. |
| `cloud.aws.roleArn` | `""` | IAM role ARN. Required with `aws`. |
| `cloud.gcp.serviceAccount` | `""` | Google service account email. Required with `gcp`. |
| `registries.dockerConfigSecrets` | `[]` | Names of `kubernetes.io/dockerconfigjson` Secrets in the release namespace, mounted in order; the first match for a host wins. |
| `registries.podPullSecrets` | `false` | Read the `imagePullSecrets` of scanned pods, in the namespaces below. |
| `registries.podPullSecretNamespaces` | `[]` | Required when `podPullSecrets` is on, and refused when it is off. Each namespace gets a Role with `get` on `secrets`. |
| `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity` | empty | Passed to the pod. |
| `networkPolicy.enabled` | `true` | Render the NetworkPolicy. |
| `networkPolicy.ingressFrom` | `[]` | Raw NetworkPolicy `from` entries that may reach the pod. Empty admits nothing. |
| `networkPolicy.egress` | `[]` | Raw egress rules. Empty leaves egress open, because registries and the Trivy DB mirror can be anywhere. |
| `ingress.enabled` | `false` | Render an Ingress. |
| `ingress.className`, `ingress.annotations` | empty | |
| `ingress.hosts` | `[]` | `networking.k8s.io/v1` host entries (`host` only; the chart routes `/`). At least one when enabled. |
| `ingress.tls` | `[]` | |
| `httpRoute.enabled` | `false` | Render a Gateway API HTTPRoute. |
| `httpRoute.parentRefs` | `[]` | The Gateway to attach to. At least one when enabled. |
| `httpRoute.hostnames` | `[]` | Exact hostnames. |
| `httpRoute.annotations` | `{}` | |

The pod runs as user 65532 on a read-only root filesystem, with all capabilities dropped and the `RuntimeDefault`
seccomp profile. Only `/data` (the volume), `/tmp` (an `emptyDir`) and `/run/kubedelos` (a memory-backed `emptyDir` of
16Mi, see below) are written.

## Private registries

Each registry setting has its own page:

- [Azure Container Registry from AKS](registries/acr.md): `cloud.provider: azure` with workload identity.
- [Amazon ECR from EKS](registries/ecr.md): `cloud.provider: aws` with IAM roles for service accounts.
- [Artifact Registry from GKE](registries/gar.md): `cloud.provider: gcp` with Workload Identity Federation.
- [Pull secrets and Docker configs](registries/pull-secrets.md): `registries.dockerConfigSecrets` and
  `registries.podPullSecrets`, for any other registry.

The cloud preset only wires the identity into the pod; the cloud-side role (`AcrPull`, an ECR read policy,
`roles/artifactregistry.reader`) is yours to create, and it decides which registries kubedelos can read. The Settings
page
has a Registries card that shows what is configured and, in `serve`, a "Test an image" box.

Per-scan Docker configs are written to `/run/kubedelos` (`KUBEDELOS_SECRETS_DIR`), a memory-backed volume, so a
credential never reaches node disk. Turning on pod pull secrets gives kubedelos `get` on every Secret in the namespaces
you list; read the [security note](registries/pull-secrets.md#security-note) first.

## Threat feeds

The [risk score](risk-score.md) uses two public feeds for known exploitation: CISA KEV from `www.cisa.gov` and EPSS
from `epss.empiricalsecurity.com`. Each is a plain HTTPS `GET` of a fixed URL, at most once a day per feed, before a
scan; it carries nothing about the cluster. The chart sets `KUBEDELOS_THREAT_FEEDS=false`, so without them the score
counts known exploitation as nothing and the rest of it still works.

Turn them on only when the pod can reach both hosts on port 443. If `networkPolicy.egress` restricts egress, a plain
NetworkPolicy cannot allow them by name: it matches IP blocks, not hostnames, and both hosts sit behind CDNs whose
addresses change. Use an `ipBlock` rule for port 443 wide enough to cover them, or a CNI policy that matches FQDNs
(such as Cilium's `toFQDNs`).

The chart has no value for this switch yet (one is the planned follow-up); set the variable on the container, which
takes precedence over the chart's ConfigMap. The Deployment is named after the release (see [Install](#install)), so
select it by the release label:

```bash
kubectl set env deployment -l app.kubernetes.io/instance=<release> KUBEDELOS_THREAT_FEEDS=true -n kubedelos
```

The edit survives `helm upgrade`, because the chart never sets an `env` entry on the container, but a GitOps
controller (Argo CD, Flux) reverts it and a reinstall drops it.

The feeds are fetched before the next scan. Without egress each try times out (10 s to connect), logs
`threat feed <name> not updated: ...` and lets the scan go on. The Settings page shows when each feed was last fetched.

## Storage

Everything kubedelos keeps lives under `/data`: the SQLite database, the Trivy vulnerability DB, the Java DB (about 1 GB
by itself) and the layer cache (up to 32 slots of at most 128 MB each, 4 GB at the most). The default `10Gi` leaves room
for all of that and a long history. Resize the volume only if your storage class allows expansion; otherwise pick the
size at install time. Losing the volume loses the history and the risk acceptances, so use a storage class you back up
if they matter to you. [How a scan works](how-scans-work.md) explains what is kept and for how long.

## Exposing the UI

The chart forces no proxy, gateway or Ingress controller. Choose one:

- **Port-forward.** Nothing to configure; good for a look and for a first install. It needs RBAC to `pods/portforward`
  in the namespace, and it skips the NetworkPolicy (see [the two bypasses](#what-the-guard-does-not-cover)).
- **Ingress.** Set `ingress.enabled`, `ingress.className`, `ingress.hosts` (and `ingress.tls`). Controller-specific
  settings, such as external-auth annotations, go in `ingress.annotations`.
- **HTTPRoute.** Set `httpRoute.enabled`, `httpRoute.parentRefs` (the Gateway) and `httpRoute.hostnames`. Anything the
  Gateway implementation needs beyond that, an Envoy Gateway `SecurityPolicy` for example, you deploy yourself.

Wildcard hosts (`*.example.com`) are refused, because kubedelos compares the Host header exactly: list each host. An
enabled Ingress needs at least one host and an enabled HTTPRoute at least one `parentRefs` entry.

Whichever you pick, also fill `networkPolicy.ingressFrom` with the pods that carry the traffic (the Ingress controller or
the gateway's proxy pods). With the NetworkPolicy on and `ingressFrom` empty, typically only the kubelet's probes reach the pod (node and
`hostNetwork` traffic depend on your CNI).

A worked example with a sign-in proxy: [oauth2-proxy behind Envoy Gateway](exposure-oauth2-proxy-envoy-gateway.md).

### Hosts

`KUBEDELOS_ALLOWED_HOSTS` lists the Host header values the UI answers to, and the CSRF check on writes compares the
`Origin` against it. The chart sets it, in this order, to: the Service's DNS names (`<release>-kubedelos`,
`<release>-kubedelos.<namespace>`, `.svc` and `.svc.<clusterDomain>`), `localhost` and `127.0.0.1` (so `kubectl
port-forward svc/<release>-kubedelos 8080:80` works), the Ingress hosts, the HTTPRoute hostnames, and
`extraAllowedHosts`. Use `extraAllowedHosts` for a host that reaches the pod some other way, for example a load balancer
you deploy yourself. `/healthz` answers to any host, for the probes.

## Security model

### Writes are open by default

Without a proxy that signs users in, anyone who can reach the UI can read the whole vulnerability inventory and also
write: start scans within the configured scope, retry failed images, cancel queued or running scans, and accept or
revoke risks. Accepting a risk hides its findings from the dashboard and the reports, and every user is `anonymous`.

Set `readOnly: true` for an instance meant only for looking. Otherwise put a sign-in proxy in front and turn on
`auth.trustProxyHeaders`, or keep the Service cluster-internal. `NOTES.txt` warns when writes are open with no header
trust, and when the UI is exposed with no sign-in.

### The trust boundary

With `auth.trustProxyHeaders: true`, kubedelos takes the user's name from `auth.identityHeader` and uses it as the
requester of a scan and the owner of a risk acceptance. It believes the header of every request that reaches it, so two
things must hold, and kubedelos can check neither:

1. **The proxy must overwrite the header on every request**, replacing any copy a client sent. Check this for your
   proxy and test it: send a request with a forged header through the proxy and see that kubedelos shows the proxy's
   value.
2. **Only the proxy may reach the pod.** Any other pod that can connect could send the header and claim to be anyone.

The chart helps with the second point: the NetworkPolicy admits only `networkPolicy.ingressFrom`.

### The guard

With `auth.trustProxyHeaders` on, `helm install` and `helm upgrade` fail to render when the NetworkPolicy cannot
enforce that. The guard refuses:

- `networkPolicy.enabled: false`;
- an empty `networkPolicy.ingressFrom`;
- an entry that admits every pod: `{}`, or an entry with none of `podSelector`, `namespaceSelector` and `ipBlock` (a
  `null` `namespaceSelector` counts as absent);
- a selector with no non-empty `matchLabels` and no `In` expression, so a selector made only of `Exists`,
  `DoesNotExist` or `NotIn` counts as empty, because it can match every object;
- an empty `namespaceSelector` (every namespace);
- a `namespaceSelector` that names only the release namespace, with an empty or absent `podSelector` (every pod of the
  release namespace, kubedelos itself included);
- an `ipBlock` whose prefix length is 0, such as `0.0.0.0/0`, `::/0` or `0.0.0.0/00`.

Wildcard Ingress hosts and HTTPRoute hostnames, and an enabled Ingress with no host or an enabled HTTPRoute with no
`parentRefs`, are refused whether or not trust is on.

### What the guard does not cover

The guard catches common mistakes. It is not a proof that only the proxy can reach the pod.

- **`ipBlock` entries are yours to get right.** The guard refuses `/0`, not a range that happens to cover the pod
  network. Name the proxy by selector where you can.
- **NetworkPolicies are additive.** Another policy in the namespace that selects the kubedelos pod and allows more
  ingress defeats this one.
- **`kubectl port-forward` bypasses the NetworkPolicy.** Anyone allowed to port-forward to the pod or Service in this
  namespace can send any header. Limit `pods/portforward` RBAC there.
- **A CNI that does not enforce NetworkPolicy** makes the whole policy void. Check that yours does.
- **Traffic from `hostNetwork` pods and from the node** is not matched by pod selectors on many CNIs, and may reach the
  pod regardless.

`NOTES.txt` repeats these when trust is on.

### Secure cookies

`secureCookies` defaults to `true`: the CSRF cookie that protects writes carries the `Secure` attribute, so a browser
sends it only over HTTPS. Chrome, Edge and Firefox also accept it on `http://localhost`, so `kubectl port-forward` keeps
working there. Safari drops it on `http://localhost`, so forms fail as expired; use another browser, or set
`secureCookies: false` if you only reach the UI over plain HTTP.

If your browser reaches the UI over plain HTTP on any other host (a cluster-internal name through a VPN, an Ingress with
no TLS), the browser drops the cookie and every write fails its CSRF check. Terminate TLS in front of the UI, which is the
better fix, or set `secureCookies: false`.

## Verifying a release

The release signs the image and the chart in separate jobs, keylessly with cosign, using the workflow identity of
`release-please.yml` on `main`. Verify before you install:

```bash
IDENTITY='^https://github.com/k8s-servant/kubedelos/\.github/workflows/release-please\.yml@refs/heads/main$'
ISSUER=https://token.actions.githubusercontent.com

cosign verify ghcr.io/k8s-servant/kubedelos:<release> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"

cosign verify ghcr.io/k8s-servant/charts/kubedelos:<release> \
  --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

The image also carries an SBOM and provenance attestations from the build. The workflows install their tools with the
SHA-256 digests pinned in the workflow files.
