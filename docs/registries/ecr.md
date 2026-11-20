# Amazon ECR from EKS

This page sets up kubedelos in an EKS cluster to read images from Amazon ECR with IAM roles for service accounts
(IRSA). kubedelos runs no AWS code of its own: it starts Trivy, and Trivy asks ECR for a token with the role the chart
gives the pod. See [Running kubedelos in a cluster](../in-cluster.md) for the install itself.

The names below are placeholders: `my-cluster`, account `123456789012`, region `eu-west-1`, release `kubedelos` in
namespace `kubedelos`. The chart names its ServiceAccount `<release>-kubedelos`, or just the release name when it
already contains `kubedelos`, in the release namespace. With the names above it is `kubedelos` in `kubedelos`.

## What you need

- An EKS cluster with an IAM OIDC provider associated:

  ```bash
  eksctl utils associate-iam-oidc-provider --cluster my-cluster --approve
  ```

- Permission to create an IAM role and attach a policy to it.

Flags checked against the eksctl docs ([IAM roles for service
accounts](https://docs.aws.amazon.com/eks/latest/eksctl/iamserviceaccounts.html))
and the eksctl source for `create iamserviceaccount` (`pkg/ctl/create/iamserviceaccount.go`, which defines
`--role-only`,
`--attach-policy-arn`, `--role-name` and `--approve`).

## 1. Create the identity

One command creates the IAM role and its trust policy, which names the ServiceAccount. `--role-only` stops eksctl from
creating the ServiceAccount, because the chart does that.

```bash
eksctl create iamserviceaccount \
  --cluster my-cluster \
  --namespace kubedelos \
  --name kubedelos \
  --role-name kubedelos-ecr-read \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly \
  --approve
```

## 2. Let it read the registry

The command above already attached `AmazonEC2ContainerRegistryReadOnly`. That managed policy reads every repository in
the account. To limit kubedelos, attach your own policy instead, with these actions, and `Resource` set to the
repositories you want scanned (`ecr:GetAuthorizationToken` only works with `Resource: "*"`):

- `ecr:GetAuthorizationToken`
- `ecr:BatchGetImage`
- `ecr:GetDownloadUrlForLayer`

The role's permissions decide which registries kubedelos can read. The chart gives it the role and nothing more. For
images in another AWS account, the repository's policy there must allow this role as well.

Get the role ARN for the chart:

```bash
ROLE_ARN=$(aws iam get-role --role-name kubedelos-ecr-read --query Role.Arn --output text)
```

It looks like `arn:aws:iam::123456789012:role/kubedelos-ecr-read`.

## 3. Link it to the kubedelos ServiceAccount

`eksctl create iamserviceaccount` did this: the role's trust policy lets the cluster's OIDC provider assume it for
`system:serviceaccount:kubedelos:kubedelos`. If you made the role another way, its trust policy needs that subject
(the `sub` condition) and the audience `sts.amazonaws.com`. The chart adds the other half, the ServiceAccount
annotation `eks.amazonaws.com/role-arn`, in step 4.

## 4. Install or upgrade the chart

```bash
helm upgrade --install kubedelos oci://ghcr.io/k8s-servant/charts/kubedelos \
  --version <release> --namespace kubedelos --create-namespace \
  --set clusterName=my-cluster \
  --set cloud.provider=aws \
  --set cloud.aws.roleArn="$ROLE_ARN"
```

`cloud.provider: aws` annotates the ServiceAccount with `eks.amazonaws.com/role-arn: <roleArn>`. EKS's webhook then
injects `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` into the pod. The render fails when `cloud.aws.roleArn` is
empty.

## 5. Check it

1. Open the Settings page (`kubectl port-forward svc/kubedelos 8080:80 -n kubedelos`). The Registries card shows the
   cloud identity (`aws` and the role ARN, never a token) and the hosts it is used for.
2. Type an ECR image into "Test an image", for example `123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/app:1.0`,
   and press Test. It scans that one image once, with the cloud identity and the mounted Docker configs (pod pull
   secrets are not
   used: there is no pod). The box exists only in
   `kubedelos serve` with writes on, and refuses a host that is not in a mounted Docker config, not covered by the cloud
   identity and not used by an image in the cluster's newest run.
3. Start a scan from the Scans page, or wait for the sweep. Images that fail with the kind `auth` are listed on the
   run's failures page.

## Which hosts use the identity, and what wins

Trivy v0.76.1 uses the AWS identity only for hosts that match, in full, the ECR endpoint pattern in
`pkg/fanal/image/registry/ecr/ecr.go`:

```
^[^.]+\.dkr[.-]ecr(?:-fips)?\.([^.]+)\.(?:amazonaws\.com(?:\.cn)?|sc2s\.sgov\.gov|c2s\.ic\.gov|on\.aws)$
```

That is `<account>.dkr.ecr.<region>.amazonaws.com`, the `.amazonaws.com.cn` and FIPS forms, the isolated-region
domains and `<account>.dkr-ecr.<region>.on.aws`. Nothing else gets the token. The region comes from the host name.

For such a host Trivy tries the cloud identity first, then the Docker config (`pkg/remote/remote.go`, `authOptions`).
If `GetAuthorizationToken` fails, Trivy logs it at debug level only (`pkg/fanal/image/registry/token.go`) and goes on to
the Docker config, so a mounted Docker config or pull secret for the same host is the fallback, not an override. See
[Pull secrets](pull-secrets.md). If both fail you see the registry's ordinary auth error.

The AWS SDK looks for credentials in its usual order. Without the IRSA variables it falls back to the node's instance
role through the EC2 metadata service, so a node role with ECR read access also works, and the IRSA role is not
required for that case. The SDK's role is still only used against the ECR hosts above.

## EKS Pod Identity

Pod Identity is the other way to give a pod an IAM role. Trivy v0.76.1's `go.mod` pins
`aws-sdk-go-v2/config v1.33.9` and `credentials v1.20.9`. In that `config` release
`resolve_credentials.go` reads `AWS_CONTAINER_CREDENTIALS_FULL_URI` and the container authorization token, and
accepts the EKS agent's link-local addresses (`169.254.170.23`, `fd00:ec2::23`) as hosts. AWS lists Go v2 release
2023-11-14 as the first version with Pod Identity support
([Use pod identity with the AWS SDK](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-minimum-sdk.html)).
So the SDK Trivy uses can read Pod Identity credentials.

What is not covered:

- The chart has no Pod Identity preset. The association is made in EKS (`aws eks create-pod-identity-association
  --cluster-name my-cluster --role-arn <role> --namespace kubedelos --service-account kubedelos`), not with a
  ServiceAccount annotation, and the role's trust policy names `pods.eks.amazonaws.com`.
- `cloud.provider: aws` requires `cloud.aws.roleArn` and adds the IRSA annotation. With Pod Identity leave
  `cloud.provider` at `none`. Then the Settings page shows no cloud identity, and "Test an image" refuses ECR hosts
  that no running image uses, because it only trusts hosts of the configured provider.
- If both an IRSA annotation and a Pod Identity association exist, the SDK uses the web identity token first.
- This path has not been run end to end for this project. Use IRSA unless you need Pod Identity.

## Troubleshooting

| What you see | Usual cause |
| --- | --- |
| `denied` or `unauthorized`, and the pod has no `AWS_ROLE_ARN` variable | `cloud.provider` is not `aws`, the role ARN is empty or wrong, or the pod was not restarted after the upgrade. |
| Same error, `AWS_ROLE_ARN` is set | The role lacks the ECR actions or the repository (step 2), or its trust policy names another namespace, ServiceAccount or OIDC provider (step 3). |
| An image in another account fails | The repository policy in that account does not allow the role. |
| A host like `myregistry.example.com` fails | Not an ECR endpoint, so Trivy does not use the identity. A pull-through cache repository is on the normal ECR host, so the identity covers it. A custom domain in front of ECR needs a [pull secret](pull-secrets.md), which is only good for 12 hours unless you refresh it. |

Trivy logs the cause of a failed cloud login at debug level only. To see it, run `trivy image` by hand in a pod with the
same ServiceAccount.

## Limits

- One identity per install. Registries the role cannot read need a pull secret or a second install.
- The AWS path is not run in this project's CI (no AWS account). The Trivy behaviour above comes from reading its
  v0.76.1 source.

## Related

- [Pull secrets and Docker configs](pull-secrets.md): for registries the role cannot read.
- [Running kubedelos in a cluster](../in-cluster.md#private-registries).
- [All guides](../README.md)
