#!/usr/bin/env bash
# End-to-end check of the Helm chart and image: build the image, install the chart on a throwaway kind cluster
# and wait for the first scheduled sweep to finish. Only ever touches the cluster "kubedelos-e2e-chart" and a
# temporary kubeconfig.
set -euo pipefail

NAME="kubedelos-e2e-chart"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLL_SECONDS="${E2E_POLL_SECONDS:-900}"

if kind get clusters 2>/dev/null | grep -qx "$NAME"; then
  echo "kind cluster $NAME already exists; refusing to reuse or delete it" >&2
  exit 3
fi

KCFG="$(mktemp)"
CREATED=0

cleanup() {
  if [ "$CREATED" = 1 ]; then
    kind delete cluster --name "$NAME" --kubeconfig "$KCFG" || true
  fi
  rm -f "$KCFG"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

kc() { kubectl --kubeconfig "$KCFG" --context "kind-$NAME" "$@"; }

dump_state() {
  echo "--- kubectl logs" >&2
  kc -n kubedelos logs deploy/kd-kubedelos --tail=200 >&2 || true
  echo "--- kubectl describe pod" >&2
  kc -n kubedelos describe pod -l app.kubernetes.io/instance=kd >&2 || true
}

docker build -t kubedelos:e2e "$ROOT"

# Set before create so a half-created cluster is still deleted by the EXIT trap.
CREATED=1
kind create cluster --name "$NAME" --kubeconfig "$KCFG" --wait 120s
kind load docker-image kubedelos:e2e --name "$NAME"

kc create namespace web
kc -n web create deployment web --image=nginx:1.19
kc -n web rollout status deployment/web --timeout=300s

if ! helm install kd "$ROOT/charts/kubedelos" -n kubedelos --create-namespace \
  -f "$ROOT/charts/kubedelos/ci/e2e-values.yaml" \
  --set image.repository=kubedelos,image.tag=e2e,image.pullPolicy=Never \
  --kubeconfig "$KCFG" --kube-context "kind-$NAME" --wait --timeout 5m; then
  dump_state
  exit 1
fi

# Newest scheduled run as "<id> <status> <nginx rows>"; empty until the first sweep has started. The last field counts
# the run's successfully scanned nginx rows (stored as the digest-pinned ref, docker.io/library/nginx@sha256:...,
# of the only image in the web namespace), so a sweep where every image errored cannot pass. The database is
# opened read-only, and the pod has no curl or sqlite3 CLI, so python does the query.
QUERY='
import sqlite3
db = sqlite3.connect("file:/data/kubedelos.db?mode=ro", uri=True)
row = db.execute("SELECT id, status FROM scan_run WHERE trigger = ? ORDER BY id DESC LIMIT 1", ("schedule",)).fetchone()
if row:
    ok = db.execute(
        "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status != ? AND ref LIKE ?", (row[0], "error", "%/nginx@%")
    ).fetchone()[0]
    print(*row, ok)
'

deadline=$((SECONDS + POLL_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  run="$(kc -n kubedelos exec deploy/kd-kubedelos -- python -c "$QUERY" 2>/dev/null || true)"
  read -r id status scanned <<<"$run"
  case "${status:-}" in
    ok | partial)
      if [ "${scanned:-0}" -ge 1 ]; then
        echo "sweep run $id: $status, nginx:1.19 scanned"
        exit 0
      fi
      echo "sweep run $id: $status, but nginx:1.19 was not scanned successfully"
      dump_state
      exit 1
      ;;
    failed | cancelled)
      echo "sweep run $id: $status"
      dump_state
      exit 1
      ;;
  esac
  sleep 10
done

echo "no sweep finished within ${POLL_SECONDS}s (last seen: ${run:-none})" >&2
dump_state
exit 1
