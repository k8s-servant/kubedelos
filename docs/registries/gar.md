# Google Artifact Registry and Container Registry from GKE

This page sets up kubedelos in a GKE cluster to read images from Artifact Registry (and the older Container Registry
domains) with Workload Identity Federation for GKE. kubedelos runs no Google code of its own: it starts Trivy, and
Trivy takes an access token from the GKE metadata server for the Google service account the pod is linked to. See
[Running kubedelos in a cluster](../in-cluster.md) for the install itself.

The names below are placeholders: project `my-project`, cluster `my-cluster`, location `europe-west1`, release
`kubedelos` in namespace `kubedelos`. The chart names its ServiceAccount `<release>-kubedelos`, or just the release name
when it already contains `kubedelos`, in the release namespace. With the names above it is `kubedelos` in `kubedelos`.

## What you need

- Workload Identity Federation for GKE on the cluster (always on in Autopilot) and on the node pool:

  ```bash
  gcloud container clusters update my-cluster \
    --location=europe-west1 \
    --workload-pool=my-project.svc.id.goog

  gcloud container node-pools update my-pool \
    --cluster=my-cluster \
    --location=europe-west1 \
    --workload-metadata=GKE_METADATA
  ```

  Updating a node pool affects the workloads running in it.
- Permission to create a service account and change IAM policy.

Flags checked against [Use Workload Identity Federation for
GKE](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).

## 1. Create the identity

```bash
gcloud iam service-accounts create kubedelos --project=my-project
```

The service account's email is `kubedelos@my-project.iam.gserviceaccount.com`. It goes into the chart values in step 4.

## 2. Let it read the registry

```bash
gcloud projects add-iam-policy-binding my-project \
  --member "serviceAccount:kubedelos@my-project.iam.gserviceaccount.com" \
  --role "roles/artifactregistry.reader"
```

Grant it on the project, or on a single repository to read less. Images in the legacy `gcr.io` domains are stored in
Cloud Storage buckets, so for those also grant `roles/storage.objectViewer` on the bucket (or the project).

This binding decides which registries kubedelos can read. The chart gives it the identity and nothing more. For
repositories in other projects, grant the role there.

## 3. Link it to the kubedelos ServiceAccount

Allow the Kubernetes ServiceAccount to act as the Google service account:

```bash
gcloud iam service-accounts add-iam-policy-binding kubedelos@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[kubedelos/kubedelos]"
```

The member is `serviceAccount:<project>.svc.id.goog[<namespace>/<serviceaccount>]`. The chart adds the other half, the
ServiceAccount annotation `iam.gke.io/gcp-service-account`, in step 4.

## 4. Install or upgrade the chart

```bash
helm upgrade --install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster \
  --set cloud.provider=gcp \
  --set cloud.gcp.serviceAccount=kubedelos@my-project.iam.gserviceaccount.com
```

`cloud.provider: gcp` annotates the ServiceAccount with `iam.gke.io/gcp-service-account: <serviceAccount>`. The render
fails when `cloud.gcp.serviceAccount` is empty.

## 5. Check it

1. Open the Settings page (`kubectl port-forward svc/kubedelos 8080:80 -n kubedelos`). The Registries card shows the
   cloud identity (`gcp` and the service account email, never a token) and the hosts it is used for.
2. Type an image into "Test an image", for example `europe-west1-docker.pkg.dev/my-project/my-repo/app:1.0`, and press
   Test. It scans that one image once, with the cloud identity and the mounted Docker configs (pod pull secrets are not
   used: there is no pod). The box exists only in `kubedelos serve` with writes on, and refuses a host that is not in a
   mounted Docker config, not covered by the cloud identity and not used by an image in the cluster's newest run.
3. Start a scan from the Scans page, or wait for the sweep. Images that fail with the kind `auth` are listed on the
   run's failures page.

## Which hosts use the identity, and what wins

Trivy v0.76.1 uses the Google identity only for `gcr.io`, hosts ending in `.gcr.io`, and hosts ending in
`-docker.pkg.dev` (`pkg/fanal/image/registry/google/google.go`). `mirror.gcr.io` is skipped on purpose. Nothing else
gets the token.

The token comes from `docker-credential-gcr` v2.2.1 (the version in Trivy's `go.mod`). Its `env` token source uses
Application Default Credentials, which on GKE means the metadata server and so the linked service account
(`credhelper/helper.go` in that release).

For such a host Trivy tries the cloud identity first, then the Docker config (`pkg/remote/remote.go`, `authOptions`).
If getting the token fails, Trivy logs it at debug level only (`pkg/fanal/image/registry/token.go`) and goes on to the
Docker config, so a mounted Docker config or pull secret for the same host is the fallback, not an override. See
[Pull secrets](pull-secrets.md). If both fail you see the registry's ordinary auth error.

## Troubleshooting

| What you see | Usual cause |
| --- | --- |
| `denied` or `unauthorized` for a `-docker.pkg.dev` host | The service account lacks `roles/artifactregistry.reader` on the repository (step 2), or the binding has not propagated yet. |
| Same, and the node pool has no `GKE_METADATA` | The node pool does not use the GKE metadata server (step "What you need"), so the pod gets the node's identity instead. |
| Same, role is in place | The `workloadIdentityUser` member names another namespace or ServiceAccount, or the annotation is missing. Check `kubectl get sa kubedelos -n kubedelos -o yaml`. |
| A legacy `gcr.io` image fails, Artifact Registry ones work | Missing `roles/storage.objectViewer` for the bucket behind `gcr.io`. |
| A host like `mirror.gcr.io` or a custom domain | Not covered by the identity. Use a [pull secret](pull-secrets.md) if it needs login. |

Trivy logs the cause of a failed cloud login at debug level only. To see it, run `trivy image` by hand in a pod with the
same ServiceAccount.

## Limits

- One identity per install. Registries the service account cannot read need a pull secret or a second install.
- The GCP path is not run in this project's CI (no GCP project). The Trivy behaviour above comes from reading its
  v0.76.1 source.
