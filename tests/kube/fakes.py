"""Hand-built Kubernetes objects and an in-memory KubeApi, so tests never touch a cluster."""

from kubernetes.client import (
    V1Container,
    V1ContainerStatus,
    V1CronJob,
    V1CronJobSpec,
    V1Deployment,
    V1DeploymentSpec,
    V1EphemeralContainer,
    V1JobSpec,
    V1JobTemplateSpec,
    V1Namespace,
    V1Node,
    V1NodeStatus,
    V1NodeSystemInfo,
    V1ObjectMeta,
    V1OwnerReference,
    V1Pod,
    V1PodSpec,
    V1PodStatus,
    V1PodTemplateSpec,
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
) -> V1Pod:
    refs = [V1OwnerReference(api_version="v1", kind=owner[0], name=owner[1], uid="u")] if owner else None
    spec = V1PodSpec(containers=[V1Container(name=container, image=image)], node_name=node_name)
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


def _template(image: str, container: str = "app") -> V1PodTemplateSpec:
    return V1PodTemplateSpec(spec=V1PodSpec(containers=[V1Container(name=container, image=image)]))


def deployment(name: str, ns: str, image: str, replicas: int) -> V1Deployment:
    return V1Deployment(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1DeploymentSpec(replicas=replicas, selector={}, template=_template(image)),
    )


def cronjob(name: str, ns: str, image: str) -> V1CronJob:
    return V1CronJob(
        metadata=V1ObjectMeta(name=name, namespace=ns),
        spec=V1CronJobSpec(
            schedule="* * * * *", job_template=V1JobTemplateSpec(spec=V1JobSpec(template=_template(image)))
        ),
    )


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
        self.selectors: list[tuple[str, str | None]] = []

    def _check(self, ns: str, resource: str) -> None:
        if ns in self.forbidden or (resource, ns) in self.forbidden_resources:
            raise ApiException(status=403, reason="Forbidden")

    def _match(self, method: str, objs: list, label_selector: str | None) -> list:
        """Record the selector and filter by comma-ANDed ``k=v`` equality; the real API server parses the rest."""
        self.selectors.append((method, label_selector))
        if not label_selector:
            return objs
        if "(" in label_selector and ")" not in label_selector:
            raise ApiException(status=400, reason="unable to parse requirement")
        wanted = dict(part.split("=", 1) for part in label_selector.split(","))
        return [o for o in objs if all((o.metadata.labels or {}).get(k) == v for k, v in wanted.items())]

    def list_namespaces(self, label_selector=None):
        if self.namespaces_forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return self._match("list_namespaces", self.namespaces, label_selector)

    def list_pods(self, ns, label_selector=None):
        self._check(ns, "pods")
        return self._match("list_pods", self.pods.get(ns, []), label_selector)

    def list_deployments(self, ns, label_selector=None):
        self._check(ns, "deployments")
        return self._match("list_deployments", self.deployments.get(ns, []), label_selector)

    def list_statefulsets(self, ns, label_selector=None):
        self._check(ns, "statefulsets")
        return self._match("list_statefulsets", self.statefulsets.get(ns, []), label_selector)

    def list_cronjobs(self, ns, label_selector=None):
        self._check(ns, "cronjobs")
        return self._match("list_cronjobs", self.cronjobs.get(ns, []), label_selector)

    def list_nodes(self):
        if self.nodes_forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return self.nodes

    def current_context(self) -> str:
        return "fake"
