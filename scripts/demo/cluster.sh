#!/usr/bin/env bash
# Create (or delete with --delete) the throwaway kind cluster the README pictures are taken from: kubedelos-demo,
# running the old public images in scripts/demo/workloads.yaml. It writes its kubeconfig to $DEMO_DIR/kubeconfig
# (default: a directory under $TMPDIR), never to ~/.kube/config. Needs kind, kubectl and docker.
set -euo pipefail

NAME="kubedelos-demo"
DEMO_DIR="${DEMO_DIR:-${TMPDIR:-/tmp}/kubedelos-demo}"
KCFG="$DEMO_DIR/kubeconfig"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = --delete ]; then
  kind delete cluster --name "$NAME" --kubeconfig "$KCFG"
  exit 0
fi

mkdir -p "$DEMO_DIR"
if ! kind get clusters | grep -qx "$NAME"; then
  kind create cluster --name "$NAME" --kubeconfig "$KCFG" --wait 120s
fi
kind get kubeconfig --name "$NAME" >"$KCFG"
kubectl --kubeconfig "$KCFG" apply -f "$HERE/workloads.yaml"
for ns in shop data ops; do
  kubectl --kubeconfig "$KCFG" -n "$ns" wait --for=condition=Available deployment --all --timeout=300s 2>/dev/null || true
done
kubectl --kubeconfig "$KCFG" -n ops rollout status daemonset/node-agent --timeout=300s
echo "kubeconfig: $KCFG (context kind-$NAME)"
