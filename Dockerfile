# Container image for `kubedelos serve`: the wheel in a virtualenv plus the pinned Trivy, checksum-verified at build
# time, so the running pod downloads nothing and writes only to /data and /tmp.
# Literal digest (not an ARG) so Dependabot can bump it.
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS base

FROM base AS builder
WORKDIR /build
COPY pyproject.toml LICENSE NOTICE README.pypi.md ./
COPY kubedelos ./kubedelos
RUN pip install --no-cache-dir build \
    && python -m build --wheel --outdir dist \
    && python -m venv /opt/kubedelos \
    && /opt/kubedelos/bin/pip install --no-cache-dir dist/*.whl
# `trivy install` downloads the pinned release and verifies its SHA-256 for this platform.
RUN KUBEDELOS_CACHE_DIR=/build/cache /opt/kubedelos/bin/kubedelos trivy install \
    && version="$(/opt/kubedelos/bin/python -c 'from kubedelos.trivy.pins import TRIVY_VERSION; print(TRIVY_VERSION)')" \
    && mkdir -p "/usr/local/lib/kubedelos/trivy/${version}" \
    && cp "/build/cache/trivy/${version}/trivy" "/usr/local/lib/kubedelos/trivy/${version}/trivy"

FROM base
LABEL org.opencontainers.image.source="https://github.com/k8s-servant/kubedelos" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /opt/kubedelos /opt/kubedelos
COPY --from=builder /usr/local/lib/kubedelos/trivy /usr/local/lib/kubedelos/trivy
# /data is owned by the runtime user so a fresh volume inherits it (a Kubernetes PVC gets fsGroup instead).
# /run/kubedelos is where serve writes the per-scan docker configs; the chart mounts a memory volume over it.
RUN mkdir /data /run/kubedelos && chown 65532:65532 /data /run/kubedelos && chmod 0700 /run/kubedelos
ENV PATH="/opt/kubedelos/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    KUBEDELOS_DATA_DIR=/data \
    KUBEDELOS_CACHE_DIR=/data/cache \
    KUBEDELOS_SECRETS_DIR=/run/kubedelos \
    KUBEDELOS_TRIVY_DIR=/usr/local/lib/kubedelos/trivy \
    TMPDIR=/tmp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["kubedelos", "serve"]
