"""A small read-only wrapper over the Kubernetes API groups the inventory needs."""

import os
from typing import Protocol

from kubernetes import client, config
from kubernetes.client import V1Namespace

from kubedelos.config import Settings

IN_CLUSTER = "in-cluster"
REQUEST_TIMEOUT = (10, 120)  # (connect, read) seconds, so a hung API server cannot hang a scan forever


class KubeApi(Protocol):
    def list_namespaces(self) -> list[V1Namespace]: ...
    def list_pods(self, ns: str) -> list: ...
    def list_deployments(self, ns: str) -> list: ...
    def list_statefulsets(self, ns: str) -> list: ...
    def list_cronjobs(self, ns: str) -> list: ...
    def list_nodes(self) -> list: ...
    def current_context(self) -> str: ...


class _RealKubeApi:
    def __init__(self, context_name: str) -> None:
        self._core = client.CoreV1Api()
        self._apps = client.AppsV1Api()
        self._batch = client.BatchV1Api()
        self._context = context_name

    def list_namespaces(self) -> list[V1Namespace]:
        return self._core.list_namespace(_request_timeout=REQUEST_TIMEOUT).items

    def list_pods(self, ns: str) -> list:
        return self._core.list_namespaced_pod(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_deployments(self, ns: str) -> list:
        return self._apps.list_namespaced_deployment(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_statefulsets(self, ns: str) -> list:
        return self._apps.list_namespaced_stateful_set(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_cronjobs(self, ns: str) -> list:
        return self._batch.list_namespaced_cron_job(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_nodes(self) -> list:
        return self._core.list_node(_request_timeout=REQUEST_TIMEOUT).items

    def current_context(self) -> str:
        return self._context


def load(settings: Settings) -> KubeApi:
    """Load kubeconfig (or the in-cluster config when there is none) and return the API wrapper.

    The in-cluster fallback is only taken when no kubeconfig or context was asked for: a typo in ``--context``
    inside a pod must fail, not silently scan the pod's own cluster.
    """
    kubeconfig = str(settings.kubeconfig) if settings.kubeconfig else None
    try:
        config.load_kube_config(config_file=kubeconfig, context=settings.context)
    except config.ConfigException:
        if kubeconfig or settings.context or "KUBERNETES_SERVICE_HOST" not in os.environ:
            raise
        config.load_incluster_config()
        return _RealKubeApi(IN_CLUSTER)
    _, active = config.list_kube_config_contexts(config_file=kubeconfig)
    return _RealKubeApi(settings.context or active["name"])
