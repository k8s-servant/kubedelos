"""A small read-only wrapper over the Kubernetes API groups the inventory needs.

The attack-surface lists (services, ingresses, network policies, RBAC) are reads too, and no Secret is listed.
"""

import os
from collections.abc import Iterator
from typing import Protocol
from urllib.parse import urlsplit

import yaml
from kubernetes import client, config
from kubernetes.client import V1Namespace, V1Secret
from kubernetes.config import kube_config

from kubedelos.config import Settings

IN_CLUSTER = "in-cluster"
REQUEST_TIMEOUT = (10, 120)  # (connect, read) seconds, so a hung API server cannot hang a scan forever


class KubeApi(Protocol):
    def list_namespaces(self, label_selector: str | None = None) -> list[V1Namespace]:
        """Namespaces, optionally filtered by a label selector."""

    def list_pods(self, ns: str, label_selector: str | None = None) -> list:
        """Pods in ``ns``, optionally filtered by a label selector."""

    def list_deployments(self, ns: str, label_selector: str | None = None) -> list:
        """Deployments in ``ns``, optionally filtered by a label selector."""

    def list_statefulsets(self, ns: str, label_selector: str | None = None) -> list:
        """StatefulSets in ``ns``, optionally filtered by a label selector."""

    def list_cronjobs(self, ns: str, label_selector: str | None = None) -> list:
        """CronJobs in ``ns``, optionally filtered by a label selector."""

    def list_nodes(self) -> list:
        """Cluster nodes, for each pod's platform."""

    def list_services(self, ns: str) -> list:
        """Services in ``ns``."""

    def list_service_accounts(self, ns: str) -> list:
        """ServiceAccounts in ``ns``."""

    def list_ingresses(self, ns: str) -> list:
        """Ingresses in ``ns``."""

    def list_network_policies(self, ns: str) -> list:
        """NetworkPolicies in ``ns``."""

    def list_httproutes(self, ns: str) -> list[dict]:
        """Gateway API HTTPRoutes in ``ns``, as the plain dicts the custom-objects API returns."""

    def list_roles(self, ns: str | None) -> list:
        """Roles in ``ns``, or in every namespace when ``ns`` is None."""

    def list_role_bindings(self, ns: str | None) -> list:
        """RoleBindings in ``ns``, or in every namespace when ``ns`` is None."""

    def list_cluster_roles(self) -> list:
        """ClusterRoles."""

    def list_cluster_role_bindings(self) -> list:
        """ClusterRoleBindings."""

    def read_secret(self, ns: str, name: str) -> V1Secret:
        """One Secret by name: only ever a Secret a pod names as an imagePullSecret, never a list."""

    def current_context(self) -> str:
        """The kube-context name, or ``in-cluster``."""


def _list_kwargs(label_selector: str | None) -> dict[str, object]:
    """Every list call gets the timeout; a label selector only when one was asked for."""
    kwargs: dict[str, object] = {"_request_timeout": REQUEST_TIMEOUT}
    if label_selector is not None:
        kwargs["label_selector"] = label_selector
    return kwargs


class _RealKubeApi:
    def __init__(self, context_name: str) -> None:
        self._core = client.CoreV1Api()
        self._apps = client.AppsV1Api()
        self._batch = client.BatchV1Api()
        self._networking = client.NetworkingV1Api()
        self._rbac = client.RbacAuthorizationV1Api()
        self._custom = client.CustomObjectsApi()
        self._context = context_name

    def list_namespaces(self, label_selector: str | None = None) -> list[V1Namespace]:
        return self._core.list_namespace(**_list_kwargs(label_selector)).items

    def list_pods(self, ns: str, label_selector: str | None = None) -> list:
        return self._core.list_namespaced_pod(ns, **_list_kwargs(label_selector)).items

    def list_deployments(self, ns: str, label_selector: str | None = None) -> list:
        return self._apps.list_namespaced_deployment(ns, **_list_kwargs(label_selector)).items

    def list_statefulsets(self, ns: str, label_selector: str | None = None) -> list:
        return self._apps.list_namespaced_stateful_set(ns, **_list_kwargs(label_selector)).items

    def list_cronjobs(self, ns: str, label_selector: str | None = None) -> list:
        return self._batch.list_namespaced_cron_job(ns, **_list_kwargs(label_selector)).items

    def list_nodes(self) -> list:
        return self._core.list_node(_request_timeout=REQUEST_TIMEOUT).items

    def list_services(self, ns: str) -> list:
        return self._core.list_namespaced_service(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_service_accounts(self, ns: str) -> list:
        return self._core.list_namespaced_service_account(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_ingresses(self, ns: str) -> list:
        return self._networking.list_namespaced_ingress(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_network_policies(self, ns: str) -> list:
        return self._networking.list_namespaced_network_policy(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_httproutes(self, ns: str) -> list[dict]:
        return self._custom.list_namespaced_custom_object(
            "gateway.networking.k8s.io", "v1", ns, "httproutes", _request_timeout=REQUEST_TIMEOUT
        )["items"]

    def list_roles(self, ns: str | None) -> list:
        if ns is None:
            return self._rbac.list_role_for_all_namespaces(_request_timeout=REQUEST_TIMEOUT).items
        return self._rbac.list_namespaced_role(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_role_bindings(self, ns: str | None) -> list:
        if ns is None:
            return self._rbac.list_role_binding_for_all_namespaces(_request_timeout=REQUEST_TIMEOUT).items
        return self._rbac.list_namespaced_role_binding(ns, _request_timeout=REQUEST_TIMEOUT).items

    def list_cluster_roles(self) -> list:
        return self._rbac.list_cluster_role(_request_timeout=REQUEST_TIMEOUT).items

    def list_cluster_role_bindings(self) -> list:
        return self._rbac.list_cluster_role_binding(_request_timeout=REQUEST_TIMEOUT).items

    def read_secret(self, ns: str, name: str) -> V1Secret:
        return self._core.read_namespaced_secret(name, ns, _request_timeout=REQUEST_TIMEOUT)

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


def _kubeconfig_docs(settings: Settings) -> Iterator[dict]:
    """The parsed YAML of every kubeconfig path (as kubectl reads ``KUBECONFIG``), in order. Data only: nothing is
    loaded, so no login plugin runs. A file that is missing, half-written or not a mapping is skipped."""
    paths = str(settings.kubeconfig) if settings.kubeconfig else kube_config.KUBE_CONFIG_DEFAULT_LOCATION
    for path in filter(None, paths.split(kube_config.ENV_KUBECONFIG_PATH_SEPARATOR)):
        try:
            with open(os.path.expanduser(path)) as f:
                data = yaml.safe_load(f)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if isinstance(data, dict):
            yield data


def _named_entries(doc: dict, key: str) -> Iterator[tuple[str, dict]]:
    """The ``(name, entry)`` pairs of a kubeconfig list such as ``contexts``, skipping malformed ones."""
    entries = doc.get(key)
    for entry in entries if isinstance(entries, list) else []:
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, str) and name:
            yield name, entry


def list_contexts(settings: Settings) -> list[str]:
    """The context names in the kubeconfig (every ``KUBECONFIG`` path), sorted, or none when it can't be read.
    Parsing only: no context is loaded, so no login plugin runs, and no current context is needed."""
    names = {name for doc in _kubeconfig_docs(settings) for name, _ in _named_entries(doc, "contexts")}
    return sorted(names, key=str.casefold)


def normalise_server(url: str) -> str:
    """An API server URL folded so equal servers compare equal: lower-case scheme and host, no default port
    (``:443`` for https, ``:80`` for http) and no trailing slash."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and port != {"https": 443, "http": 80}.get(scheme):
        host = f"{host}:{port}"
    return f"{scheme}://{host}{parts.path.rstrip('/')}"


def cluster_keys(settings: Settings) -> dict[str, str]:
    """Each kubeconfig context name mapped to its cluster key: the normalised API server of the cluster it names, so
    two logins to one server (a user and an ``--admin`` context) share a key. A context whose cluster entry is
    missing or has no server is keyed by its own name. As in kubectl, the first definition of a name wins."""
    servers: dict[str, str] = {}
    cluster_of: dict[str, str | None] = {}
    for doc in _kubeconfig_docs(settings):
        for name, entry in _named_entries(doc, "clusters"):
            server = (entry.get("cluster") or {}).get("server") if isinstance(entry.get("cluster"), dict) else None
            if isinstance(server, str) and server.strip():
                servers.setdefault(name, server)
        for name, entry in _named_entries(doc, "contexts"):
            ctx = entry.get("context")
            cluster = ctx.get("cluster") if isinstance(ctx, dict) else None
            cluster_of.setdefault(name, cluster if isinstance(cluster, str) else None)
    return {
        name: normalise_server(servers[cluster]) if cluster in servers else name for name, cluster in cluster_of.items()
    }
