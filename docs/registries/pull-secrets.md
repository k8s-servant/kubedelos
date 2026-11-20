# Pull secrets and Docker configs

For a registry that the cloud identity does not cover (Docker Hub, GitLab, Harbor, a registry behind a custom domain),
give kubedelos a Docker config. There are two ways, and you can use both:

1. **Mounted Docker config Secrets.** You create the Secret, list it in the chart, and the kubelet mounts it. No Secret
   RBAC is needed.
2. **Pod pull secrets (opt-in).** kubedelos reads the `imagePullSecrets` that the scanned pods name, in namespaces you
   list. This needs a Role with `get` on Secrets in each of those namespaces.

For ACR, ECR and Artifact Registry through a workload identity, see [ACR](acr.md), [ECR](ecr.md) and [GAR](gar.md).

## Mounted Docker config Secrets

Create a `kubernetes.io/dockerconfigjson` Secret in the release namespace:

```bash
kubectl create secret docker-registry my-registry \
  --namespace kubedelos \
  --docker-server=registry.example.com \
  --docker-username=my-user \
  --docker-password='...'
```

Then list it:

```bash
helm upgrade kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --reuse-values \
  --set 'registries.dockerConfigSecrets={my-registry}'
```

The chart mounts each Secret's `.dockerconfigjson` read-only (mode 0400) at
`/etc/kubedelos/docker-configs/<name>/.dockerconfigjson` and lists the paths, in order, in
`KUBEDELOS_DOCKER_CONFIGS`. The Secret must be in the release namespace, because a pod can only mount Secrets from its
own namespace. The pod does not start until every listed Secret exists.

kubedelos reads only the `auths` entries. Credential helpers (`credsStore`, `credHelpers`) are dropped, since the image
has none. A mounted file that is missing, empty or not JSON is skipped with a warning that names the path, and the
others still apply.

## Pod pull secrets

Turn it on and list the namespaces whose pull secrets kubedelos may read:

```bash
helm upgrade kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --reuse-values \
  --set registries.podPullSecrets=true \
  --set 'registries.podPullSecretNamespaces={team-a,team-b}'
```

The chart then creates, in each listed namespace, a Role named `<fullname>-pull-secrets` (with the install above,
`kubedelos-pull-secrets`) with the single rule `get` on `secrets` (never `list` or `watch`) and a RoleBinding to
kubedelos's ServiceAccount. Nothing is granted
cluster-wide. The list is required when the option is on, and listing namespaces without turning the option on fails
the render, so no access is granted by accident. The chart also sets `KUBEDELOS_POD_PULL_SECRET_NAMESPACES`.

For each image that runs in a listed namespace, kubedelos reads the `imagePullSecrets` of the pod (a pod's list
includes the ones the ServiceAccount admission controller copied from the pod's ServiceAccount, so kubedelos needs no
access to ServiceAccounts). It then reads those Secrets by name:

- kubedelos gets each Secret a pod names. The type is only known after the get, so the whole object, `data` included,
  reaches the process. A Secret whose `type` is not `kubernetes.io/dockerconfigjson` is then discarded without its data
  being decoded, used or logged, and its name is not logged either.
- From the rest, kubedelos keeps only the `auths` entries for the image's registry host. Entries for other hosts are
  never used, so the credentials are sent only to the registry they are for.
- A Secret that does not exist, or that kubedelos may not get, is skipped. The scan goes on with what remains, and the
  Secret's name (never its content) is logged at debug level.
- A Secret is read at most once per run, a failed read included: it counts as empty until the next run, so a slow API
  server is asked once, not once per image. A retry starts a new read.
- The "Test an image" box on the Settings page has no pod, so it never uses pod pull secrets: an image only a pull
  secret can open fails there (with a note) and still works in a scan.
- Pods in other namespaces get no pull secrets; their images use the mounted configs.

The Secret names an image's pods used are stored with the image's result (schema migration 11), so a retry of an
auth failure reads the same Secrets again. The contents are read again at that time and never stored.

Docker Hub entries keyed `https://index.docker.io/v1/`, `index.docker.io`, `registry-1.docker.io` or `docker.io` all
apply to `docker.io` images.

## Which credentials a scan uses

For one image, in this order:

1. The mounted Docker configs, in the order listed in `registries.dockerConfigSecrets`. The first one with an entry for
   the image's host wins.
2. Pod pull secrets override that for the image's host. When several pull secrets have an entry for the host, the first
   in inventory order wins: namespaces in the order the API lists them, then the pods in each, then the scaled-to-zero
   templates and CronJobs. It is not a sorted order.
3. kubedelos writes the entries for that host, and only that host, to a temporary Docker config for this one scan, and
   points Trivy at it.
4. Trivy then picks between the cloud identity and that Docker config. For a host the identity covers, **the cloud
   identity is tried first and the Docker config is the fallback**. Trivy tries each option in turn and uses the first
   that works. Source (Trivy v0.76.1):
   - `pkg/remote/remote.go`, `authOptions`: credentials passed on the command line (kubedelos passes none), then the
     provider's token, then the Docker config through the default keychain (it reads `DOCKER_CONFIG`).
   - `pkg/fanal/image/registry/token.go`: a provider that fails to get a token is logged at debug level only and
     contributes nothing, so the Docker config is tried next.
   - The hosts each provider covers: `.azurecr.io` and `.azurecr.cn` (`azure/azure.go`); `gcr.io`, `.gcr.io` and
     `-docker.pkg.dev`, not `mirror.gcr.io` (`google/google.go`); ECR endpoints (`ecr/ecr.go`).

So a pull secret for `myregistry.azurecr.io` does not stop the cloud identity being tried. It is used when the identity
gets no token or the registry rejects it, for example an ACR in another tenant. For every other host the Docker config
is the only option.

With no `KUBEDELOS_SECRETS_DIR` (a laptop), no file is written and Trivy uses your own Docker login, as before.

## Where the credentials live

The chart mounts an in-memory `emptyDir` (`medium: Memory`, 16Mi) at `/run/kubedelos`
(`KUBEDELOS_SECRETS_DIR`). For each Trivy process kubedelos creates a directory there (mode 0700) holding a
`config.json` (mode 0600) with the entries for that image's host. It is deleted when the process ends, also on error or
cancel. A kill that skips the cleanup leaves the file only until `serve` starts again, which removes leftover per-scan
configs (`kubedelos-docker-*`) from the directory, and the volume goes with the pod. So credentials are never written to
node disk, SQLite or logs. This is the one place
kubedelos puts a credential in a file, and the memory volume is why that is acceptable. `KUBEDELOS_SECRETS_DIR` must
be a different directory from the data and cache directories.

## Security note

Read this before you turn pod pull secrets on.

- The Role lets kubedelos get **every** Secret in each listed namespace, not only pull secrets. It gets one only when a
  pod there names it under `imagePullSecrets`. If its type is not `kubernetes.io/dockerconfigjson`, the data is
  discarded undecoded, unused and unlogged, but it has been fetched into the process. `NOTES.txt` says the same.
- Anyone who can create pods in a listed namespace can name any `dockerconfigjson` Secret of that namespace in a pod,
  and kubedelos will then read it and use its credentials, for the registry host they are for. List only namespaces
  whose Secrets you accept sharing with this deployment.
- The UI has no per-namespace access control. An image shared by pods in several namespaces is scanned once, and may
  be scanned with any listed namespace's pull secret. Its findings show for every workload that runs it. This exposes
  nothing new: everyone who can open the UI already sees every namespace's findings.
- Without a sign-in proxy, anyone who can reach the UI can start scans (see [the security
  model](../in-cluster.md#security-model)).
  A scan uses the credentials above, but a scan cannot name an image that no pod runs, and "Test an image" refuses a
  host that is not configured, used in the cluster or covered by the identity.

## Troubleshooting

| What you see | Usual cause |
| --- | --- |
| The pod is stuck in `ContainerCreating` after listing a Secret | The Secret does not exist in the release namespace, or has no `.dockerconfigjson` key (wrong type). |
| `unauthorized` for an image in a listed namespace | The pod names no pull secret (check `kubectl get pod -o yaml`), the Secret has no entry for the image's registry host, or the credentials expired. Settings, Registries shows the namespaces and Secret names. |
| `unauthorized` for an image in another namespace | That namespace is not in `registries.podPullSecretNamespaces`. |
| `pull secret team-a/my-pull skipped: HTTP 403` in the debug log | The Role is missing, usually because the namespace was added after install and the chart was not upgraded. |
| Docker Hub rate limit (`toomanyrequests`) | Anonymous pulls are limited. Add a Docker Hub account as a mounted Docker config. |

## Related

- Cloud identities: [ACR](acr.md), [ECR](ecr.md), [GAR](gar.md).
- [Running kubedelos in a cluster](../in-cluster.md#private-registries).
- [All guides](../README.md)
