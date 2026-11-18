# Azure Container Registry from AKS

This page sets up kubedelos in an AKS cluster to read images from Azure Container Registry (ACR) with Microsoft Entra
Workload ID. kubedelos runs no Azure code of its own: it starts Trivy, and Trivy logs in to the registry with the
identity the chart gives the pod. See [Running kubedelos in a cluster](../in-cluster.md) for the install itself.

The names below are placeholders: `my-rg`, `my-cluster`, `myregistry`, release `kubedelos` in namespace `kubedelos`.
The chart names its ServiceAccount `<release>-kubedelos`, or just the release name when it already contains
`kubedelos`, in the release namespace. With the names above it is `kubedelos` in `kubedelos`. Check yours with
`helm template` or `kubectl get sa -n kubedelos`.

## What you need

- An AKS cluster with the OIDC issuer and workload identity turned on:

  ```bash
  az aks update --resource-group my-rg --name my-cluster --enable-oidc-issuer --enable-workload-identity
  ```

  (`az aks create` takes the same two flags.) Azure CLI 2.47.0 or later.
- Permission to create a managed identity, a federated credential and a role assignment on the registry.

Flags checked against Microsoft Learn: [Deploy and configure workload identity on AKS](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster).

## 1. Create the identity

```bash
az identity create --name kubedelos --resource-group my-rg

CLIENT_ID=$(az identity show --resource-group my-rg --name kubedelos --query clientId --output tsv)
PRINCIPAL_ID=$(az identity show --resource-group my-rg --name kubedelos --query principalId --output tsv)
```

`CLIENT_ID` goes into the chart values in step 4.

## 2. Let it read the registry

```bash
ACR_ID=$(az acr show --name myregistry --query id --output tsv)

az role assignment create \
  --assignee-object-id "$PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role AcrPull \
  --scope "$ACR_ID"
```

This assignment is what decides which registries kubedelos can read. The chart gives kubedelos the identity and nothing
more; assign `AcrPull` on each registry you want scanned, and no other.

If the registry uses ABAC repository permissions ("RBAC Registry + ABAC Repository Permissions"), `AcrPull` does not
apply. Assign `Container Registry Repository Reader` instead. See
[Authenticate with ACR from AKS](https://learn.microsoft.com/en-us/azure/aks/cluster-container-registry-integration).

A role assignment can take a few minutes to take effect.

## 3. Link it to the kubedelos ServiceAccount

A federated credential tells Entra to trust tokens that your cluster issues for this ServiceAccount.

```bash
AKS_OIDC_ISSUER=$(az aks show --name my-cluster --resource-group my-rg --query oidcIssuerProfile.issuerUrl --output tsv)

az identity federated-credential create \
  --name kubedelos \
  --identity-name kubedelos \
  --resource-group my-rg \
  --issuer "$AKS_OIDC_ISSUER" \
  --subject system:serviceaccount:kubedelos:kubedelos \
  --audience api://AzureADTokenExchange
```

The subject is `system:serviceaccount:<namespace>:<serviceaccount>`. If it does not match the ServiceAccount the chart
creates, Entra refuses the token exchange. A new credential can take a few seconds to propagate.

## 4. Install or upgrade the chart

```bash
helm upgrade --install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster \
  --set cloud.provider=azure \
  --set cloud.azure.clientId="$CLIENT_ID"
```

`cloud.provider: azure` makes the chart:

- annotate the ServiceAccount with `azure.workload.identity/client-id: <clientId>`;
- label the pod `azure.workload.identity/use: "true"`, which makes the workload identity webhook inject
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and the federated token file into it.

The render fails when `cloud.azure.clientId` is empty.

## 5. Check it

1. Open the Settings page (`kubectl port-forward svc/kubedelos 8080:80 -n kubedelos`). The Registries card shows the
   cloud identity (`azure` and the client id, never a token) and the hosts it is used for.
2. Type an image from the registry into "Test an image", for example `myregistry.azurecr.io/team/app:1.0`, and press
   Test. It scans that one image once, with the access a scan would use. The box is there only in `kubedelos serve`
   with writes on (not in read-only mode), and refuses a host that is not in a mounted Docker config, not covered by
   the cloud identity and not used by an image in the cluster's newest run.
3. Start a scan from the Scans page, or wait for the sweep. Images that fail with the kind `auth` are listed on the
   run's failures page.

## Which hosts use the identity, and what wins

Trivy v0.76.1 uses the Azure identity only for hosts ending in `.azurecr.io` or `.azurecr.cn`
(`pkg/fanal/image/registry/azure/azure.go`). Nothing else gets it, so a pod that names some other registry never sees
the token. It sends it to the ACR service for the registry in the image name, and that service refuses a registry
outside the identity's tenant.

For such a host Trivy tries the cloud identity first, then the Docker config
(`pkg/remote/remote.go`, `authOptions`). If the identity gives no token, or the registry rejects it, Trivy tries the
Docker config next. A failure to get the token is logged by Trivy at debug level only
(`pkg/fanal/image/registry/token.go`), so kubedelos sees the registry's ordinary auth error if both fail. This means a
mounted Docker config or pull secret for the same host does not override the identity; it is the fallback. See
[Pull secrets](pull-secrets.md).

Trivy also needs `AZURE_TENANT_ID` (the webhook sets it) for the exchange of the Entra token for an ACR token.

## Troubleshooting

| What you see | Usual cause |
| --- | --- |
| `unauthorized` or `authentication required` for `myregistry.azurecr.io`, and the pod has no `AZURE_*` variables (`kubectl exec` and `env`) | `cloud.provider` is not `azure`, or the pod was not restarted after the upgrade. |
| Same error, the variables are there | No `AcrPull` assignment for the managed identity on this registry (or, with ABAC, the wrong role), or it has not propagated yet. Check `az role assignment list --assignee "$PRINCIPAL_ID" --scope "$ACR_ID"`. |
| Auth errors, the variables are there, and the role assignment is in place | The federated credential's issuer or subject does not match: wrong namespace or ServiceAccount name, or the issuer URL of another cluster. Entra then answers "no matching federated identity record", which only Trivy's debug log shows. |
| `missing environment variable AZURE_TENANT_ID` (in Trivy's debug log, not the UI) | The pod label is missing. Use the chart's preset rather than annotating by hand. |

Trivy logs the cause of a failed cloud login at debug level only, so the registry's refusal is often all the UI
shows. To see the cause, run `trivy image` by hand in a pod with the same ServiceAccount and label.

## Limits

- A registry behind a custom domain (a CNAME to `myregistry.azurecr.io`) is not recognised, because Trivy matches the
  host name. Use a [pull secret](pull-secrets.md) for it.
- `az aks update --attach-acr` grants `AcrPull` to the cluster's kubelet identity, which is what pulls images for pods.
  kubedelos does not use that identity, so attaching the registry is not enough on its own. Do step 2.
- One identity per install. Registries the identity cannot read need a pull secret or a second install.
- No Azure ACR is available to this project's CI. The tests cover the chart rendering (annotation, pod label, required
  client id) and the host matching on the Settings page. The Azure login itself is Trivy's, and it was not run end to end
  for this project. What this page says about it comes from reading Trivy's v0.76.1 source.
