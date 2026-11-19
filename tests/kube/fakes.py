"""Hand-built Kubernetes objects and an in-memory KubeApi, so tests never touch a cluster."""

import base64

from kubernetes.client import (
    RbacV1Subject,
    V1ClusterRole,
    V1ClusterRoleBinding,
    V1Container,
    V1ContainerStatus,
    V1CronJob,
    V1CronJobSpec,
    V1Deployment,
    V1DeploymentSpec,
    V1EphemeralContainer,
    V1HTTPIngressPath,
    V1HTTPIngressRuleValue,
    V1Ingress,
    V1IngressBackend,
    V1IngressRule,
    V1IngressServiceBackend,
    V1IngressSpec,
    V1JobSpec,
    V1JobTemplateSpec,
    V1LabelSelector,
    V1LabelSelectorRequirement,
    V1LocalObjectReference,
    V1Namespace,
    V1NetworkPolicy,
    V1NetworkPolicySpec,
    V1Node,
    V1NodeStatus,
    V1NodeSystemInfo,
    V1ObjectMeta,
    V1OwnerReference,
    V1Pod,
    V1PodSpec,
    V1PodStatus,
    V1PodTemplateSpec,
    V1PolicyRule,
    V1Role,
    V1RoleBinding,
    V1RoleRef,
    V1Secret,
    V1Service,
    V1ServiceAccount,
    V1ServiceBackendPort,
    V1ServiceSpec,
)
from kubernetes.client.rest import ApiException


def namespace(name: str, annotations: dict | None = None, labels: dict | None = None) -> V1Namespace:
    return V1Namespace(metadata=V1ObjectMeta(name=name, annotations=annotations, labels=labels))


def node(name: str, arch: str = "amd64", os: str = "linux") -> V1Node:
    return V1Node(
        metadata=V1ObjectMeta(name=name),
        status=V1NodeStatus(
            node_info=V1NodeSystemInfo(
                architecture=arch,
                boot_id="b",
                container_runtime_version="c",
                kernel_version="k",
                kube_proxy_version="p",
                kubelet_version="v",
                machine_id="m",
                operating_system=os,
                os_image="o",
                system_uuid="u",
            )
        ),
    )


def pod(
    name: str,
    ns: str = "default",
    image: str = "nginx:1.25",
    image_id: str = "",
    container: str = "app",
    node_name: str | None = None,
    owner: tuple[str, str] | None = None,
    init: tuple[str, str, str] | None = None,  # (container name, image, imageID)
    ephemeral: tuple[str, str, str] | None = None,
    labels: dict | None = None,
    pull_secrets: list[str] | None = None,
) -> V1Pod:
    refs = [V1OwnerReference(api_version="v1", kind=owner[0], name=owner[1], uid="u")] if owner else None
    spec = V1PodSpec(containers=[V1Container(name=container, image=image)], node_name=node_name)
    if pull_secrets:
        spec.image_pull_secrets = [V1LocalObjectReference(name=n) for n in pull_secrets]
    status = V1PodStatus(container_statuses=[_status(container, image, image_id)])
    if init:
        spec.init_containers = [V1Container(name=init[0], image=init[1])]
        status.init_container_statuses = [_status(*init)]
    if ephemeral:
        spec.ephemeral_containers = [_ephemeral(ephemeral[0], ephemeral[1])]
        status.ephemeral_container_statuses = [_status(*ephemeral)]
    return V1Pod(
        metadata=V1ObjectMeta(name=name, namespace=ns, owner_references=refs, labels=labels), spec=spec, status=status
    )


def _ephemeral(name: str, image: str):
    return V1EphemeralContainer(name=name, image=image)


def _status(name: str, image: str, image_id: str) -> V1ContainerStatus:
    return V1ContainerStatus(name=name, image=image, image_id=image_id, ready=True, restart_count=0)


def _template(image: str, container: str = "app", pull_secrets: list[str] | None = None) -> V1PodTemplateSpec:
    refs = [V1LocalObjectReference(name=n) for n in pull_secrets] if pull_secrets else None
    return V1PodTemplateSpec(
        spec=V1PodSpec(containers=[V1Container(name=container, image=image)], image_pull_secrets=refs)
    )


def deployment(name: str, ns: str, image: str, replicas: int, pull_secrets: list[str] | None = None) -> V1Deployment:
    return V1Deployment(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1DeploymentSpec(replicas=replicas, selector={}, template=_template(image, pull_secrets=pull_secrets)),
    )


def cronjob(name: str, ns: str, image: str, pull_secrets: list[str] | None = None) -> V1CronJob:
    return V1CronJob(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1CronJobSpec(
            schedule="* * * * *",
            job_template=V1JobTemplateSpec(spec=V1JobSpec(template=_template(image, pull_secrets=pull_secrets))),
        ),
    )


def secret(name: str, ns: str, data: dict[str, bytes] | None = None, type: str = "kubernetes.io/dockerconfigjson"):
    """A Secret; ``data`` values are given raw and stored base64, as the client library returns them."""
    encoded = {k: base64.b64encode(v).decode() for k, v in data.items()} if data is not None else None
    return V1Secret(metadata=V1ObjectMeta(name=name, namespace=ns), type=type, data=encoded)


def service(
    name: str,
    ns: str,
    selector: dict | None,
    type: str = "ClusterIP",
    annotations: dict | None = None,
    external_ips: list[str] | None = None,
) -> V1Service:
    return V1Service(
        metadata=V1ObjectMeta(name=name, namespace=ns, annotations=annotations),
        spec=V1ServiceSpec(selector=selector, type=type, external_ips=external_ips),
    )


def ingress(
    name: str,
    ns: str,
    rules: list[tuple[str, str]] | None = None,  # (host, service name)
    default_backend: str | None = None,  # service name
) -> V1Ingress:
    def backend(svc: str) -> V1IngressBackend:
        return V1IngressBackend(service=V1IngressServiceBackend(name=svc, port=V1ServiceBackendPort(number=80)))

    ing_rules = [
        V1IngressRule(
            host=host,
            http=V1HTTPIngressRuleValue(paths=[V1HTTPIngressPath(path="/", path_type="Prefix", backend=backend(svc))]),
        )
        for host, svc in rules or []
    ]
    return V1Ingress(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1IngressSpec(
            rules=ing_rules or None, default_backend=backend(default_backend) if default_backend else None
        ),
    )


def httproute(
    name: str,
    ns: str,
    hostnames: list[str] | None = None,
    backends: list[tuple] | None = None,  # (name, kind="Service", group="")
) -> dict:
    """An HTTPRoute as the CustomObjectsApi returns it: a plain dict."""
    refs = [
        {"name": b[0], "kind": b[1] if len(b) > 1 else "Service", "group": b[2] if len(b) > 2 else ""}
        for b in backends or []
    ]
    return {
        "metadata": {"name": name, "namespace": ns},
        "spec": {"hostnames": hostnames or [], "rules": [{"backendRefs": refs}]},
    }


def network_policy(
    name: str,
    ns: str,
    match_labels: dict | None = None,
    match_expressions: list[tuple[str, str, list[str]]] | None = None,  # (key, operator, values)
    policy_types: list[str] | None = None,
    egress: bool = False,
) -> V1NetworkPolicy:
    """A policy selecting pods by labels; ``egress`` adds the Egress type to ``policy_types``."""
    expressions = [V1LabelSelectorRequirement(key=k, operator=op, values=v) for k, op, v in match_expressions or []]
    types = list(policy_types) if policy_types else ["Ingress"]
    if egress and "Egress" not in types:
        types.append("Egress")
    return V1NetworkPolicy(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1NetworkPolicySpec(
            pod_selector=V1LabelSelector(match_labels=match_labels, match_expressions=expressions or None),
            policy_types=types,
        ),
    )


def _rules(rules: list[tuple] | None) -> list[V1PolicyRule]:
    return [
        V1PolicyRule(api_groups=groups, resources=resources, verbs=verbs, resource_names=names)
        for groups, resources, verbs, names in rules or []
    ]


def role(name: str, ns: str, rules: list[tuple] | None = None) -> V1Role:
    """``rules`` are (api groups, resources, verbs, resource names) tuples."""
    return V1Role(metadata=V1ObjectMeta(name=name, namespace=ns), rules=_rules(rules))


def cluster_role(name: str, rules: list[tuple] | None = None) -> V1ClusterRole:
    return V1ClusterRole(metadata=V1ObjectMeta(name=name), rules=_rules(rules))


def _subjects(subjects: list[tuple[str, str, str | None]] | None) -> list[RbacV1Subject]:
    return [RbacV1Subject(kind=kind, name=name, namespace=ns) for kind, name, ns in subjects or []]


def role_binding(
    name: str, ns: str, role_kind: str, role_name: str, subjects: list[tuple[str, str, str | None]] | None = None
) -> V1RoleBinding:
    """``subjects`` are (kind, name, namespace) tuples; ``role_kind`` is Role or ClusterRole."""
    return V1RoleBinding(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        role_ref=V1RoleRef(api_group="rbac.authorization.k8s.io", kind=role_kind, name=role_name),
        subjects=_subjects(subjects),
    )


def cluster_role_binding(
    name: str, role_name: str, subjects: list[tuple[str, str, str | None]] | None = None
) -> V1ClusterRoleBinding:
    return V1ClusterRoleBinding(
        metadata=V1ObjectMeta(name=name),
        role_ref=V1RoleRef(api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=role_name),
        subjects=_subjects(subjects),
    )


def service_account(name: str, ns: str, automount: bool | None = None) -> V1ServiceAccount:
    return V1ServiceAccount(metadata=V1ObjectMeta(name=name, namespace=ns), automount_service_account_token=automount)


class FakeKubeApi:
    def __init__(
        self,
        namespaces: list[V1Namespace] | None = None,
        pods: dict[str, list] | None = None,
        deployments: dict[str, list] | None = None,
        statefulsets: dict[str, list] | None = None,
        cronjobs: dict[str, list] | None = None,
        nodes: list | None = None,
        forbidden: set[str] | None = None,
        namespaces_forbidden: bool = False,
        forbidden_resources: set[tuple[str, str]] | None = None,  # (resource, namespace)
        nodes_forbidden: bool = False,
        bad_request: set[str] | None = None,  # list methods that answer HTTP 400, as for a selector they reject
        secrets: dict[tuple[str, str], V1Secret] | None = None,  # (namespace, name) -> Secret
        secret_status: dict[tuple[str, str], int] | None = None,  # (namespace, name) -> HTTP status to answer
        secret_errors: dict[tuple[str, str], Exception] | None = None,  # (namespace, name) -> error to raise
        services: dict[str, list] | None = None,
        service_accounts: dict[str, list] | None = None,
        ingresses: dict[str, list] | None = None,
        network_policies: dict[str, list] | None = None,
        httproutes: dict[str, list] | None = None,
        roles: dict[str, list] | None = None,
        role_bindings: dict[str, list] | None = None,
        cluster_roles: list | None = None,
        cluster_role_bindings: list | None = None,
        missing: set[str] | None = None,  # list methods that answer HTTP 404, as for a CRD that is not installed
    ) -> None:
        self.namespaces = namespaces or []
        self.pods = pods or {}
        self.deployments = deployments or {}
        self.statefulsets = statefulsets or {}
        self.cronjobs = cronjobs or {}
        self.nodes = nodes or []
        self.forbidden = forbidden or set()
        self.namespaces_forbidden = namespaces_forbidden
        self.forbidden_resources = forbidden_resources or set()
        self.nodes_forbidden = nodes_forbidden
        self.bad_request = bad_request or set()
        self.secrets = secrets or {}
        self.secret_status = secret_status or {}
        self.secret_errors = secret_errors or {}
        self.services = services or {}
        self.service_accounts = service_accounts or {}
        self.ingresses = ingresses or {}
        self.network_policies = network_policies or {}
        self.httproutes = httproutes or {}
        self.roles = roles or {}
        self.role_bindings = role_bindings or {}
        self.cluster_roles = cluster_roles or []
        self.cluster_role_bindings = cluster_role_bindings or []
        self.missing = missing or set()
        self.calls: list[str] = []  # the name of every list method called
        self.secret_reads: list[tuple[str, str]] = []
        self.selectors: list[tuple[str, str | None]] = []

    def _check(self, ns: str, resource: str) -> None:
        if ns in self.forbidden or (resource, ns) in self.forbidden_resources:
            raise ApiException(status=403, reason="Forbidden")

    def _match(self, method: str, objs: list, label_selector: str | None) -> list:
        """Record the selector and filter by comma-ANDed ``k=v`` equality; the real API server parses the rest."""
        self.selectors.append((method, label_selector))
        if method in self.bad_request:
            raise ApiException(status=400, reason="Bad Request")
        if not label_selector:
            return objs
        if "(" in label_selector and ")" not in label_selector:
            raise ApiException(status=400, reason="unable to parse requirement")
        wanted = dict(part.split("=", 1) for part in label_selector.split(","))
        return [o for o in objs if all((o.metadata.labels or {}).get(k) == v for k, v in wanted.items())]

    def list_namespaces(self, label_selector=None):
        self.calls.append("list_namespaces")
        if self.namespaces_forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return self._match("list_namespaces", self.namespaces, label_selector)

    def list_pods(self, ns, label_selector=None):
        self.calls.append("list_pods")
        self._check(ns, "pods")
        return self._match("list_pods", self.pods.get(ns, []), label_selector)

    def list_deployments(self, ns, label_selector=None):
        self.calls.append("list_deployments")
        self._check(ns, "deployments")
        return self._match("list_deployments", self.deployments.get(ns, []), label_selector)

    def list_statefulsets(self, ns, label_selector=None):
        self.calls.append("list_statefulsets")
        self._check(ns, "statefulsets")
        return self._match("list_statefulsets", self.statefulsets.get(ns, []), label_selector)

    def list_cronjobs(self, ns, label_selector=None):
        self.calls.append("list_cronjobs")
        self._check(ns, "cronjobs")
        return self._match("list_cronjobs", self.cronjobs.get(ns, []), label_selector)

    def list_nodes(self):
        self.calls.append("list_nodes")
        if self.nodes_forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return self.nodes

    def _list(self, method: str, ns: str | None, resource: str, store: dict[str, list]) -> list:
        """A namespaced list; ``ns=None`` is the all-namespaces call, answering every namespace's entries."""
        self.calls.append(method)
        if method in self.missing:
            raise ApiException(status=404, reason="Not Found")
        if ns is None:
            self._check("*", resource)
            return [o for objs in store.values() for o in objs]
        self._check(ns, resource)
        return store.get(ns, [])

    def _cluster_list(self, method: str, resource: str, objs: list) -> list:
        self.calls.append(method)
        if method in self.missing:
            raise ApiException(status=404, reason="Not Found")
        self._check("*", resource)
        return objs

    def list_services(self, ns):
        return self._list("list_services", ns, "services", self.services)

    def list_service_accounts(self, ns):
        return self._list("list_service_accounts", ns, "serviceaccounts", self.service_accounts)

    def list_ingresses(self, ns):
        return self._list("list_ingresses", ns, "ingresses", self.ingresses)

    def list_network_policies(self, ns):
        return self._list("list_network_policies", ns, "networkpolicies", self.network_policies)

    def list_httproutes(self, ns):
        return self._list("list_httproutes", ns, "httproutes", self.httproutes)

    def list_roles(self, ns):
        return self._list("list_roles", ns, "roles", self.roles)

    def list_role_bindings(self, ns):
        return self._list("list_role_bindings", ns, "rolebindings", self.role_bindings)

    def list_cluster_roles(self):
        return self._cluster_list("list_cluster_roles", "clusterroles", self.cluster_roles)

    def list_cluster_role_bindings(self):
        return self._cluster_list("list_cluster_role_bindings", "clusterrolebindings", self.cluster_role_bindings)

    def read_secret(self, ns, name):
        self.secret_reads.append((ns, name))
        if (ns, name) in self.secret_errors:
            raise self.secret_errors[(ns, name)]
        if (ns, name) in self.secret_status:
            raise ApiException(status=self.secret_status[(ns, name)], reason="x")
        if (ns, name) not in self.secrets:
            raise ApiException(status=404, reason="Not Found")
        return self.secrets[(ns, name)]

    def current_context(self) -> str:
        return "fake"
