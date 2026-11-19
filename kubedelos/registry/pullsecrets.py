"""Read the docker credentials of the pull secrets a pod names, at scan time, for the image being scanned.

The inventory only records ``(namespace, name)`` of each ``imagePullSecrets`` entry, and only in namespaces the
operator opted in. Here the one API call kubedelos makes for them happens: a read of a single named Secret (never a
list). A Secret that is not a ``kubernetes.io/dockerconfigjson`` one is dropped before its ``data`` is touched, and
contents never reach logs: a skipped secret is logged by name only. A Secret is read at most once per run, a failed
read included (it counts as holding nothing, so a slow API server is asked once, not once per image); a retry builds
a new instance and so gets another chance. Each Secret has its own lock, so a slow read blocks only its own waiters.
"""

import base64
import binascii
import logging
import threading
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
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._guard = threading.Lock()  # protects only the two dicts, never held across an API call

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
        key = (ns, name)
        with self._guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:  # scan workers share one instance: a Secret is read once, not once per worker
            if key not in self._cache:
                self._cache[key] = self._fetch(ns, name) or {}  # a failed read stands as empty for the run
            return self._cache[key]

    def _fetch(self, ns: str, name: str) -> Auths | None:
        """The Secret's credentials, ``{}`` when it holds none, or ``None`` when it could not be read."""
        try:
            secret = self._api.read_secret(ns, name)
        except ApiException as exc:
            logger.debug("pull secret %s/%s skipped: HTTP %s", ns, name, exc.status)
            return None
        except Exception as exc:  # transport errors (timeouts, resets): one unreadable Secret must not fail a scan
            logger.debug("pull secret %s/%s skipped: %s", ns, name, type(exc).__name__)
            return None
        if secret.type != SECRET_TYPE:  # not ours: dropped before its data is touched, and not even named in a log
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
