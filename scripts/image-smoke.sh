#!/usr/bin/env bash
# Smoke test for the container image: scripts/image-smoke.sh IMAGE. Checks the CLI, the bundled Trivy pin, that
# `kubedelos serve` answers /healthz as the non-root user on a read-only root filesystem, and that the logs are clean.
# It needs no cluster: the kubeconfig points at an unreachable address and the sweep is off. Fails on the first problem.
set -euo pipefail

IMAGE="${1:?usage: image-smoke.sh IMAGE}"
SUFFIX="$$"
VOLUME="kubedelos-smoke-data-$SUFFIX"
CONTAINER="kubedelos-smoke-$SUFFIX"
WORKDIR="$(mktemp -d)"
TRIVY_DIR=/usr/local/lib/kubedelos/trivy
RUN_OPTS=(--read-only --tmpfs /tmp --tmpfs /run/kubedelos:uid=65532,mode=0700 --user 65532:65532 -v "$VOLUME:/data")

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
  echo "image-smoke: FAIL: $*" >&2
  exit 1
}

# 1. The CLI starts.
out="$(docker run --rm --entrypoint kubedelos "${RUN_OPTS[@]}" "$IMAGE" version)" || fail "'version' exited non-zero"
case "$out" in kubedelos\ *) ;; *) fail "unexpected 'version' output: $out" ;; esac

# 2. The bundled Trivy is the pinned one, and ensure_trivy resolves to it without downloading.
pin="$(docker run --rm --entrypoint python "$IMAGE" -c 'from kubedelos.trivy.pins import TRIVY_VERSION; print(TRIVY_VERSION)')"
tv="$(docker run --rm --entrypoint "$TRIVY_DIR/$pin/trivy" "${RUN_OPTS[@]}" "$IMAGE" --version)" || fail "bundled trivy does not run"
case "$tv" in *"Version: $pin"*) ;; *) fail "bundled trivy is not $pin: $tv" ;; esac
resolved="$(docker run --rm --entrypoint python "${RUN_OPTS[@]}" "$IMAGE" -c \
  'from kubedelos.config import Settings; from kubedelos.trivy.binary import ensure_trivy; print(ensure_trivy(Settings(), download=False))')"
[ "$resolved" = "$TRIVY_DIR/$pin/trivy" ] || fail "ensure_trivy resolved to $resolved"

# 3. `serve` starts against an unreachable kubeconfig and answers /healthz.
cat >"$WORKDIR/kubeconfig" <<'KC'
apiVersion: v1
kind: Config
clusters:
  - name: unreachable
    cluster: {server: "https://127.0.0.1:1"}
users:
  - name: nobody
    user: {token: unused}
contexts:
  - name: smoke
    context: {cluster: unreachable, user: nobody}
current-context: smoke
KC
chmod 644 "$WORKDIR/kubeconfig"
docker run -d --name "$CONTAINER" "${RUN_OPTS[@]}" \
  -e KUBEDELOS_CLUSTER_NAME=my-cluster -e KUBEDELOS_SWEEP_ENABLED=false -e KUBEDELOS_KUBECONFIG=/kc \
  -v "$WORKDIR/kubeconfig:/kc:ro" "$IMAGE" >/dev/null
healthy=0
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" python -c \
    'import urllib.request, sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=2).status == 200 else 1)' \
    >/dev/null 2>&1; then
    healthy=1
    break
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = true ] || break
  sleep 1
done
[ "$healthy" = 1 ] || { docker logs "$CONTAINER" >&2 || true; fail "/healthz did not answer 200 within 30s"; }

# 4. The container runs as the non-root user.
uid="$(docker exec "$CONTAINER" id -u)"
[ "$uid" = 65532 ] || fail "container runs as uid $uid, want 65532"

# 5. After 10 s the logs hold no traceback and the container is still up.
sleep 10
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = true ] || fail "container exited"
if docker logs "$CONTAINER" 2>&1 | grep -q 'Traceback'; then
  docker logs "$CONTAINER" >&2
  fail "traceback in the container logs"
fi

echo "image-smoke: OK ($IMAGE)"
