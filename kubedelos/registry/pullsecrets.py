"""Read the docker credentials of the pull secrets a pod names, at scan time, for the image being scanned.

The inventory only records ``(namespace, name)`` of each ``imagePullSecrets`` entry, and only in namespaces the
operator opted in. Here the one API call kubedelos makes for them happens: a read of a single named Secret (never a
list). A Secret that is not a ``kubernetes.io/dockerconfigjson`` one is dropped before its ``data`` is touched, a
Secret is read at most once per run, and contents never reach logs: a skipped secret is logged by name only.
"""

import base64
import binascii
import logging
from collections.abc import Collection

from kubernetes.client.rest import ApiException

from kubedelos.kube.client import KubeApi
from kubedelos.registry import dockerconfig
from kubedelos.registry.dockerconfig import Auths

logger = logging.getLogger(__name__)

SECRET_TYPE = "kubernetes.io/dockerconfigjson"  # noqa: S105 - a Kubernetes type name, not a password
DATA_KEY = ".dockerconfigjson"


class PullSecrets:
    """Pull-secret credentials read from the cluster; one instance per run, so its cache dies with the run."""

    def __init__(self, api: KubeApi, namespaces: Collection[str]) -> None:
        self._api = api
        self._namespaces = frozenset(namespaces)
        self._cache: dict[tuple[str, str], Auths] = {}

    def auths_for(self, refs: list[tuple[str, str]], host: str) -> Auths:
        """The credentials for ``host`` from the first of ``refs`` that has any."""
        for ns, name in refs:
            found = dockerconfig.for_host(self._read(ns, name), host)
            if found:
                return found
        return {}

    def _read(self, ns: str, name: str) -> Auths:
        if ns not in self._namespaces:
            return {}
        if (ns, name) not in self._cache:
            self._cache[(ns, name)] = self._fetch(ns, name)
        return self._cache[(ns, name)]

    def _fetch(self, ns: str, name: str) -> Auths:
        try:
            secret = self._api.read_secret(ns, name)
        except ApiException as exc:
            if exc.status in (403, 404):
                logger.debug("pull secret %s/%s skipped: HTTP %s", ns, name, exc.status)
                return {}
            raise
        if secret.type != SECRET_TYPE:
            logger.debug("pull secret %s/%s skipped: not a %s secret", ns, name, SECRET_TYPE)
            return {}
        encoded = (secret.data or {}).get(DATA_KEY)
        if not encoded:
            logger.debug("pull secret %s/%s skipped: no %s", ns, name, DATA_KEY)
            return {}
        try:
            return dockerconfig.parse(base64.b64decode(encoded, validate=True))
        except (ValueError, binascii.Error) as exc:  # a bad config's message names no content
            logger.debug("pull secret %s/%s skipped: %s", ns, name, type(exc).__name__)
            return {}
