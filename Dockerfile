# Container image for `kubedelos serve`: the wheel in a virtualenv plus the pinned Trivy, checksum-verified at build
# time, so the running pod downloads nothing and writes only to /data and /tmp.
# Literal digest (not an ARG) so Dependabot can bump it.
FROM python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd AS base

FROM base AS builder
WORKDIR /build
# Every Python package comes from the hashed locks in requirements/ (scripts/lock-image.sh writes them), so two builds
# of one commit install the same files and a changed hash fails the build. pip is the base image's, pinned by its digest.
COPY requirements ./requirements
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements/build.txt \
    && python -m venv /opt/kubedelos \
    && /opt/kubedelos/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements/image.txt
COPY pyproject.toml LICENSE NOTICE README.pypi.md ./
COPY kubedelos ./kubedelos
# The wheel is built with the locked setuptools (no isolated build env that would fetch its own) and installed without
# its dependencies, which the lock already put in place; pip check fails the build if the lock misses one.
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir dist . \
    && /opt/kubedelos/bin/pip install --no-cache-dir --no-deps dist/*.whl \
    && /opt/kubedelos/bin/pip check
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
