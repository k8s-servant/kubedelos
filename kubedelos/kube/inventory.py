"""Collect the container images running in a cluster, with their workloads and owners."""

from collections import Counter
from dataclasses import dataclass

from kubernetes.client import V1Namespace, V1ObjectMeta
from kubernetes.client.rest import ApiException

from kubedelos.config import Settings
from kubedelos.kube import owners
from kubedelos.kube.client import KubeApi
from kubedelos.models import ImageRef, InventoryItem, Workload, is_digest

DEFAULT_PLATFORM = "linux/amd64"
_PREFIXES = ("docker-pullable://", "docker://")


@dataclass(frozen=True)
class InventoryWarning:
    """Something the inventory could not see.

    ``coverage`` is True when images may be missing from the scan (a skipped namespace or resource). It is False when
    every image is still found and only extra detail is lost (owner info, the node platform), so that a namespace-scoped
    identity without cluster-wide list rights can still pass ``--fail-on``.
    """

    text: str
    coverage: bool

    def __str__(self) -> str:
        return self.text


def _normalise(name: str) -> str:
    """Return ``name`` (no tag or digest) with an explicit registry host, adding ``library/`` on Docker Hub."""
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        host, path = first.lower(), rest  # registry hosts are case-insensitive
    else:
        host, path = "docker.io", name
    if host in ("docker.io", "index.docker.io"):
        host = "docker.io"
        if "/" not in path:
            path = f"library/{path}"
    return f"{host}/{path}"


def _split(image: str) -> tuple[str, str | None, str | None]:
    """Split ``image`` into (normalised repo, tag, digest)."""
    name, _, digest = image.partition("@")
    tag = None
    head, sep, last = name.rpartition(":")
    if sep and "/" not in last:
        name, tag = head, last
    return _normalise(name), tag, digest or None


def parse_image_id(image: str, image_id: str) -> ImageRef:
    """Build an ``ImageRef`` from a container's spec image and its status ``imageID``."""
    for prefix in _PREFIXES:
        image_id = image_id.removeprefix(prefix)
    spec_repo, spec_tag, spec_digest = _split(image)
    repo, digest = "", None
    if "@sha256:" in image_id:
        repo, _, digest = _split(image_id)
        if repo != spec_repo:  # e.g. kind's "import-<date>" repo for a locally loaded image: not this image's digest
            repo, digest = "", None
    if digest and is_digest(digest):
        return ImageRef(ref=f"{repo}@{digest}", repo=repo, tag=spec_tag, digest=digest)
    if spec_digest and is_digest(spec_digest):
        return ImageRef(ref=f"{spec_repo}@{spec_digest}", repo=spec_repo, tag=spec_tag, digest=spec_digest)
    tag = spec_tag or "latest"
    return ImageRef(ref=f"{spec_repo}:{tag}", repo=spec_repo, tag=tag)


def _status_ids(pod) -> dict[str, str]:
    status = pod.status
    if not status:
        return {}
    statuses = [*(status.container_statuses or []), *(status.init_container_statuses or [])]
    statuses += status.ephemeral_container_statuses or []
    return {s.name: s.image_id or "" for s in statuses}


def _spec_containers(spec) -> list:
    if not spec:
        return []
    return [
        *(spec.containers or []),
        *(spec.init_containers or []),
        *(getattr(spec, "ephemeral_containers", None) or []),
    ]


def _pod_owner(pod) -> tuple[str, str]:
    refs = pod.metadata.owner_references or []
    if not refs:
        return "Pod", pod.metadata.name
    ref = refs[0]
    if ref.kind == "ReplicaSet":
        rs_name = ref.name
        hash_ = (pod.metadata.labels or {}).get("pod-template-hash")
        if hash_ and rs_name.endswith(f"-{hash_}"):
            return "Deployment", rs_name.removesuffix(f"-{hash_}")
        return "Deployment", rs_name.rsplit("-", 1)[0]
    return ref.kind, ref.name


def _is_forbidden(exc: ApiException) -> bool:
    return exc.status == 403


def _list_or_warn(list_fn, resource: str, ns: str, warnings: list[InventoryWarning]) -> list:
    try:
        return list_fn(ns)
    except ApiException as exc:
        if not _is_forbidden(exc):
            raise
        warnings.append(InventoryWarning(f"skipped {resource} in namespace {ns}: forbidden", coverage=True))
        return []


def _select_namespaces(api: KubeApi, settings: Settings, warnings: list[InventoryWarning]) -> list[V1Namespace]:
    wanted = set(settings.namespaces)
    try:
        found = api.list_namespaces()
    except ApiException as exc:
        if not (_is_forbidden(exc) and wanted):
            raise
        warnings.append(
            InventoryWarning(
                "cannot list namespaces: forbidden; owner info unavailable for the selected namespaces", coverage=False
            )
        )
        found = [V1Namespace(metadata=V1ObjectMeta(name=name)) for name in settings.namespaces]
    for missing in sorted(wanted - {ns.metadata.name for ns in found}):
        warnings.append(InventoryWarning(f"namespace {missing} not found", coverage=True))
    excluded = set(settings.exclude_namespaces)
    return [ns for ns in found if (not wanted or ns.metadata.name in wanted) and ns.metadata.name not in excluded]


def collect(api: KubeApi, settings: Settings) -> tuple[list[InventoryItem], list[InventoryWarning]]:
    """Return the inventory (grouped by image key and platform) and any warnings."""
    warnings: list[InventoryWarning] = []
    namespaces = _select_namespaces(api, settings, warnings)

    node_platform: dict[str, str] = {}
    try:
        for node in api.list_nodes():
            info = node.status.node_info if node.status else None
            if info and info.architecture:
                # windows/<arch> nodes are kept: their images are scanned for their own platform
                node_platform[node.metadata.name] = f"{info.operating_system or 'linux'}/{info.architecture}"
    except ApiException as exc:
        warnings.append(
            InventoryWarning(f"cannot list nodes: HTTP {exc.status}; assuming a default platform", coverage=False)
        )
    common = Counter(node_platform.values()).most_common(1)
    fallback = common[0][0] if common else DEFAULT_PLATFORM

    items: dict[tuple[str, str], InventoryItem] = {}

    def add(image: ImageRef, platform: str, workload: Workload) -> None:
        item = items.setdefault((image.key, platform), InventoryItem(image=image, platform=platform))
        if workload not in item.workloads:
            item.workloads.append(workload)

    for ns in namespaces:
        name = ns.metadata.name
        owner, team = owners.resolve(ns, settings)
        try:
            pods = api.list_pods(name)
        except ApiException as exc:
            if not _is_forbidden(exc):
                raise
            warnings.append(InventoryWarning(f"skipped namespace {name}: forbidden", coverage=True))
            continue
        deployments = _list_or_warn(api.list_deployments, "deployments", name, warnings)
        statefulsets = _list_or_warn(api.list_statefulsets, "statefulsets", name, warnings)
        cronjobs = _list_or_warn(api.list_cronjobs, "cronjobs", name, warnings)

        for pod in pods:
            ids = _status_ids(pod)
            kind, workload_name = _pod_owner(pod)
            platform = (node_platform.get(pod.spec.node_name) if pod.spec else None) or fallback
            for c in _spec_containers(pod.spec):
                image = parse_image_id(c.image, ids.get(c.name, ""))
                add(
                    image,
                    platform,
                    Workload(namespace=name, kind=kind, name=workload_name, container=c.name, owner=owner, team=team),
                )

        templates = [("Deployment", d) for d in deployments if d.spec and d.spec.replicas == 0]
        templates += [("StatefulSet", s) for s in statefulsets if s.spec and s.spec.replicas == 0]
        for kind, obj in templates:
            _add_template(add, name, kind, obj.metadata.name, obj.spec.template.spec, owner, team, fallback)
        for cj in cronjobs:
            _add_template(
                add, name, "CronJob", cj.metadata.name, cj.spec.job_template.spec.template.spec, owner, team, fallback
            )

    return list(items.values()), warnings


def _add_template(add, ns: str, kind: str, name: str, pod_spec, owner, team, platform: str) -> None:
    for c in _spec_containers(pod_spec):
        add(
            parse_image_id(c.image, ""),
            platform,
            Workload(namespace=ns, kind=kind, name=name, container=c.name, owner=owner, team=team),
        )
