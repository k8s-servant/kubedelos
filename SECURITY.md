# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's
[private vulnerability reporting](https://github.com/k8s-servant/kubedelos/security/advisories/new)
on this repository. Do not open a public issue for them.

Examples that count as security problems:

- A code path that writes to the cluster, reads a Secret, or otherwise goes beyond the
  read-only access kubedelos needs to list pods.
- A registry credential or token that ends up in SQLite, logs or reports.
- A flaw in how the pinned Trivy binary is downloaded or verified.
- The local web UI exposing data or accepting requests it should not.
- A leaked credential or personal data in the repository.
- A weakness in the release or CI workflows.

## What to expect

We aim to acknowledge a report within a week and to tell you what we decide. Fixes are
released as a patch version.

## Scope

kubedelos runs [Trivy](https://github.com/aquasecurity/trivy) against the images your
cluster runs. Vulnerabilities in Trivy itself belong to the Trivy project. kubedelos
uses your kubeconfig, so its real limit is that identity's RBAC: give it read-only
credentials.
