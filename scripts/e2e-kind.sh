#!/usr/bin/env bash
# End-to-end check: scan a throwaway kind cluster and write the JSON result to $1.
# Only ever touches the cluster "kubedelos-e2e" and a temporary kubeconfig.
set -euo pipefail

OUT="${1:?usage: e2e-kind.sh <out.json>}"
NAME="kubedelos-e2e"

if kind get clusters 2>/dev/null | grep -qx "$NAME"; then
  echo "kind cluster $NAME already exists; refusing to reuse or delete it" >&2
  exit 3
fi

KCFG="$(mktemp)"
CACHE_DIR="${KUBEDELOS_CACHE_DIR:-$(mktemp -d)}"
DATA_DIR="${KUBEDELOS_DATA_DIR:-$(mktemp -d)}"
CREATED=0

cleanup() {
  if [ "$CREATED" = 1 ]; then
    kind delete cluster --name "$NAME" --kubeconfig "$KCFG" || true
  fi
  rm -f "$KCFG"
  if [ -z "${KUBEDELOS_CACHE_DIR:-}" ]; then
    rm -rf "$CACHE_DIR"
  fi
  if [ -z "${KUBEDELOS_DATA_DIR:-}" ]; then
    rm -rf "$DATA_DIR"
  fi
}
trap cleanup EXIT

CREATED=1
kind create cluster --name "$NAME" --kubeconfig "$KCFG" --wait 120s

kc() { kubectl --kubeconfig "$KCFG" --context "kind-$NAME" "$@"; }

kc create namespace web
kc create namespace jobs
kc -n web create deployment web --image=nginx:1.19
kc annotate namespace web kubedelos.io/owner-email=web@example.com
kc -n web rollout status deployment/web --timeout=300s
kc -n web wait --for=condition=Ready pod -l app=web --timeout=300s
kc -n jobs create cronjob cleanup --image=busybox:1.36 --schedule "0 0 1 1 *" -- true

set +e
# kube-system is left out: kind's control-plane pods report an imageID ("import-<date>@sha256:...")
# that does not exist in any registry, so those images cannot be scanned remotely.
KUBEDELOS_CACHE_DIR="$CACHE_DIR" KUBEDELOS_DATA_DIR="$DATA_DIR" kubedelos scan --kubeconfig "$KCFG" \
  --context "kind-$NAME" --namespace web --namespace jobs \
  -o json --output-file "$OUT" --fail-on critical
RC=$?
set -e

if [ "$RC" -ne 1 ]; then
  echo "expected kubedelos exit code 1 (critical findings), got $RC" >&2
  exit 1
fi
echo "kubedelos exited 1 as expected"
