#!/usr/bin/env bash
# End-to-end check: scan a throwaway kind cluster through the scan service the UI uses, into the database under
# $KUBEDELOS_DATA_DIR (a temporary one when unset). Only ever touches the cluster "kubedelos-e2e" and a temporary
# kubeconfig.
set -euo pipefail

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
trap 'exit 130' INT
trap 'exit 143' TERM

# Set before create so a half-created cluster is still deleted by the EXIT trap.
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

# Attack-surface facts: web is exposed by a NodePort Service and isolated for ingress by a policy that allows
# nothing in; the jobs default ServiceAccount is bound to the view ClusterRole.
kc -n web expose deployment web --type=NodePort --port=80
kc apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-ingress
  namespace: web
spec:
  podSelector:
    matchLabels:
      app: web
  policyTypes: [Ingress]
EOF
kc -n jobs create rolebinding cleanup-view --clusterrole=view --serviceaccount=jobs:default

# kube-system is left out. kind preloads its control-plane images into the node image, and whether every one of
# those tags (kind builds some of them itself) exists in a public registry is not guaranteed, so a single not_found
# would make the run partial.
KUBEDELOS_CACHE_DIR="$CACHE_DIR" KUBEDELOS_DATA_DIR="$DATA_DIR" python -I -c '
import sys

from kubedelos.config import Settings
from kubedelos.scan.service import run_scan

settings = Settings(kubeconfig=sys.argv[1], context=sys.argv[2], namespaces=["web", "jobs"])
outcome = run_scan(settings, trigger="e2e")
print(f"run {outcome.run_id}: {outcome.status}")
sys.exit(0 if outcome.status == "ok" else 1)
' "$KCFG" "kind-$NAME"
