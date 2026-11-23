#!/usr/bin/env bash
# Push the Artifact Hub repository metadata (artifacthub-repo.yml) next to the chart on GHCR, under the special
# `artifacthub.io` tag. Artifact Hub reads it to mark the repository as a verified publisher. Run it once after adding
# the repository on artifacthub.io, with the repository ID that Artifact Hub shows; re-run it only if the ID changes.
#
#   scripts/artifacthub-metadata.sh REPOSITORY_ID
#
# It needs oras and a GHCR login that may write the package (`oras login ghcr.io` or `docker login ghcr.io` with a token
# that has write:packages). Nothing else is pushed: the chart versions and their signatures stay as the release made them.
set -euo pipefail

repository_id="${1:?usage: scripts/artifacthub-metadata.sh REPOSITORY_ID}"
case "${repository_id}" in
  *[!0-9a-f-]*) echo "the repository ID is a UUID (hex digits and dashes)" >&2; exit 2 ;;
esac
ref="${CHART_REF:-ghcr.io/k8s-servant/charts/kubedelos}:artifacthub.io"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
printf 'repositoryID: %s\n' "${repository_id}" > "${work}/artifacthub-repo.yml"

cd "${work}"
oras push "${ref}" \
  --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
  artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
