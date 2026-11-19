#!/usr/bin/env bash
# End-to-end check of the Helm chart and image: build the image, install the chart on a throwaway kind cluster
# and wait for the first scheduled sweep to finish. A private registry:2 (htpasswd, random per-run credentials that are
# never printed) holds a copy of nginx:1.19, and pods in four namespaces name it to cover the registry credential
# paths of the chart. Only ever touches the cluster "kubedelos-e2e-chart", a temporary kubeconfig and a temporary
# directory for the credentials.
set -euo pipefail

NAME="kubedelos-e2e-chart"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLL_SECONDS="${E2E_POLL_SECONDS:-1200}"

if kind get clusters 2>/dev/null | grep -qx "$NAME"; then
  echo "kind cluster $NAME already exists; refusing to reuse or delete it" >&2
  exit 3
fi

KCFG="$(mktemp)"
WORK="$(mktemp -d)" # the generated registry credentials; removed on exit
CREATED=0

# The private registry answers as two hosts (two Services with fixed ClusterIPs inside kind's default service CIDR).
# The chart's mounted docker config covers only the first, so the pull-secret cases name the second.
REG_MOUNTED_HOST="10.96.200.50:5000"
REG_OTHER_HOST="10.96.200.51:5000"

cleanup() {
  if [ "$CREATED" = 1 ]; then
    kind delete cluster --name "$NAME" --kubeconfig "$KCFG" || true
  fi
  rm -f "$KCFG"
  rm -rf "$WORK"
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

# --- private registry: htpasswd with a random user and password, kept in $WORK and never echoed.
REG_USER="e2e$(openssl rand -hex 4)"
REG_PASS="$(openssl rand -hex 16)"
docker pull httpd:2.4-alpine >/dev/null
printf '%s' "$REG_PASS" | docker run --rm -i httpd:2.4-alpine htpasswd -Bin "$REG_USER" >"$WORK/htpasswd"

kc apply -f "$ROOT/tests/e2e/registry/registry.yaml"
kc -n e2e-registry create secret generic registry-htpasswd --from-file=htpasswd="$WORK/htpasswd"
kc -n e2e-registry rollout status deployment/registry --timeout=300s

# Copy nginx:1.19 into the registry under four repos (one per scenario: pods sharing an image ref share one scan, so
# each scenario needs its own ref) from inside the cluster (skopeo), so no host port or insecure-registry setting of
# the docker daemon is needed. The credentials reach the pod through a Secret and env vars, not its arguments.
printf '%s' "$REG_USER" >"$WORK/user"
printf '%s' "$REG_PASS" >"$WORK/pass"
kc -n e2e-registry create secret generic registry-admin --from-file=user="$WORK/user" --from-file=pass="$WORK/pass"
kc apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: push
  namespace: e2e-registry
spec:
  restartPolicy: Never
  containers:
    - name: skopeo
      image: quay.io/skopeo/stable:v1.20.0
      env:
        - name: REG_USER
          valueFrom: {secretKeyRef: {name: registry-admin, key: user}}
        - name: REG_PASS
          valueFrom: {secretKeyRef: {name: registry-admin, key: pass}}
      command: ["/bin/sh", "-c"]
      args:
        - |
          for repo in nginx pull unlisted opaque; do
            skopeo copy --dest-tls-verify=false --dest-creds "\$REG_USER:\$REG_PASS" \\
              docker://docker.io/library/nginx:1.19 "docker://registry.e2e-registry:5000/e2e/\$repo:1.19"
          done
EOF
if ! kc -n e2e-registry wait --for=jsonpath='{.status.phase}'=Succeeded pod/push --timeout=300s; then
  kc -n e2e-registry logs pod/push >&2 || true
  exit 1
fi

# A dockerconfigjson file per registry host, built from the generated credentials.
AUTH="$(printf '%s:%s' "$REG_USER" "$REG_PASS" | base64 | tr -d '\n')"
for pair in "mounted:$REG_MOUNTED_HOST" "other:$REG_OTHER_HOST"; do
  printf '{"auths":{"%s":{"auth":"%s"}}}' "${pair#*:}" "$AUTH" >"$WORK/${pair%%:*}.json"
done

# The mounted config covers the first host only (release namespace Secret, named in the values file).
kc create namespace kubedelos
kc -n kubedelos create secret generic e2e-regcred --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson="$WORK/mounted.json"

# One pod per scenario. They only need to name the image: the inventory reads the pod spec, so ImagePullBackOff is fine.
# e2e-mounted: first host, no pull secret. The others name the second host, which the mounted config does not cover.
#   e2e-pull: a pull secret in a listed namespace; e2e-unlisted: a valid one in an unlisted namespace;
#   e2e-opaque: an Opaque Secret (not a dockerconfigjson type) in a listed namespace.
scenario_pod() { # namespace image [pull secret name]
  kc create namespace "$1"
  if [ -n "${3:-}" ]; then
    kc -n "$1" run app --image="$2" --overrides="{\"spec\":{\"imagePullSecrets\":[{\"name\":\"$3\"}]}}"
  else
    kc -n "$1" run app --image="$2"
  fi
}
scenario_pod e2e-mounted "$REG_MOUNTED_HOST/e2e/nginx:1.19"
scenario_pod e2e-pull "$REG_OTHER_HOST/e2e/pull:1.19" e2e-pull-cred
scenario_pod e2e-unlisted "$REG_OTHER_HOST/e2e/unlisted:1.19" e2e-unlisted-cred
scenario_pod e2e-opaque "$REG_OTHER_HOST/e2e/opaque:1.19" e2e-opaque-cred
for ns in e2e-pull e2e-unlisted; do
  kc -n "$ns" create secret generic "$ns-cred" --type=kubernetes.io/dockerconfigjson \
    --from-file=.dockerconfigjson="$WORK/other.json"
done
kc -n e2e-opaque create secret generic e2e-opaque-cred --from-file=.dockerconfigjson="$WORK/other.json"

if ! helm install kd "$ROOT/charts/kubedelos" -n kubedelos --create-namespace \
  -f "$ROOT/charts/kubedelos/ci/e2e-values.yaml" \
  --set image.repository=kubedelos,image.tag=e2e,image.pullPolicy=Never \
  --kubeconfig "$KCFG" --kube-context "kind-$NAME" --wait --timeout 5m; then
  dump_state
  exit 1
fi

# Newest scheduled run as "<id> <status> <nginx rows> <ns>=<status>/<error kind> ...": empty until the first sweep has
# started. The third field counts the run's successfully scanned nginx rows (stored as the digest-pinned ref,
# docker.io/library/nginx@sha256:..., of the only image in the web namespace), so a sweep where every image errored
# cannot pass; the rest give each e2e-* namespace's registry image outcome. The database is opened read-only, and the
# pod has no curl or sqlite3 CLI, so python does the query.
QUERY='
import sqlite3
db = sqlite3.connect("file:/data/kubedelos.db?mode=ro", uri=True)
row = db.execute("SELECT id, status FROM scan_run WHERE trigger = ? ORDER BY id DESC LIMIT 1", ("schedule",)).fetchone()
if row:
    ok = db.execute(
        "SELECT COUNT(*) FROM image_result WHERE run_id = ? AND status != ? AND ref LIKE ?", (row[0], "error", "%/nginx@%")
    ).fetchone()[0]
    reg = db.execute(
        "SELECT w.namespace, r.status, r.error_kind FROM image_result r JOIN workload w ON w.image_result_id = r.id"
        " WHERE r.run_id = ? AND w.namespace LIKE ? ORDER BY w.namespace", (row[0], "e2e-%")
    ).fetchall()
    print(*row, ok, *(f"{ns}={st}/{kind or chr(45)}" for ns, st, kind in reg))
'

# Compares one namespace's "<status>/<error kind>" with the expectation: "scanned" is any status but error.
expect_registry() { # namespace outcome ("scanned" or "error auth"), then the run's ns=outcome fields
  local ns="$1" want="$2" got="" f
  shift 2
  for f in "$@"; do
    case "$f" in "$ns="*) got="${f#*=}" ;; esac
  done
  if [ "$want" = scanned ] && [ -n "$got" ] && [ "${got%%/*}" != error ]; then
    echo "registry $ns: scanned"
  elif [ "$want" = "error auth" ] && [ "$got" = error/auth ]; then
    echo "registry $ns: error auth"
  else
    echo "registry $ns: expected $want, got '${got:-no row}'"
    return 1
  fi
}

# The per-scan docker configs live in /run/kubedelos only while a scan runs, and a new sweep may start at any minute, so
# the directory is only judged while no scan_run is running (checked right before and right after listing it). Prints
# the entry count seen in such a quiet moment; a directory that never reads empty within the window (a temp dir left
# behind for good) prints its last count. Python is the only tool in the image.
SECRETS_QUERY='
import os, sqlite3, time

def running():
    db = sqlite3.connect("file:/data/kubedelos.db?mode=ro", uri=True)
    try:
        return db.execute("SELECT COUNT(*) FROM scan_run WHERE status = ?", ("running",)).fetchone()[0] > 0
    finally:
        db.close()

left = -1
for _ in range(90):
    if not running():
        names = os.listdir("/run/kubedelos")
        if not running():
            left = len(names)
            if left == 0:
                break
    time.sleep(2)
print(left)
'

deadline=$((SECONDS + POLL_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
  run="$(kc -n kubedelos exec deploy/kd-kubedelos -- python -c "$QUERY" 2>/dev/null || true)"
  read -r id status scanned registry <<<"$run"
  case "${status:-}" in
    ok | partial)
      if [ "${scanned:-0}" -lt 1 ]; then
        echo "sweep run $id: $status, but nginx:1.19 was not scanned successfully"
        dump_state
        exit 1
      fi
      echo "sweep run $id: $status, nginx:1.19 scanned"
      # A sweep that started before every namespace was seen has fewer rows: wait for the next one.
      if [ "$(wc -w <<<"$registry")" -lt 4 ]; then
        echo "sweep run $id saw only: ${registry:-nothing}" >&2
      else
        # shellcheck disable=SC2086 # the fields are words on purpose
        if expect_registry e2e-mounted scanned $registry && expect_registry e2e-pull scanned $registry &&
          expect_registry e2e-unlisted "error auth" $registry && expect_registry e2e-opaque "error auth" $registry; then
          left="$(kc -n kubedelos exec deploy/kd-kubedelos -- python -c "$SECRETS_QUERY")" || {
            echo "secrets dir check failed" >&2
            dump_state
            exit 1
          }
          if [ "$left" = 0 ]; then
            echo "secrets dir empty"
            exit 0
          fi
          echo "/run/kubedelos was never empty while no scan ran" \
            "(last count: $left, -1 means a scan was always running)"
        fi
        dump_state
        exit 1
      fi
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
