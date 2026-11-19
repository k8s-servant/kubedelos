"""Collect the container images running in a cluster, with their workloads and owners."""

import logging
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatchcase

from kubernetes.client import V1Namespace, V1ObjectMeta
from kubernetes.client.rest import ApiException
from urllib3.exceptions import HTTPError

from kubedelos.config import Settings
from kubedelos.kube import facts as fact_builders
from kubedelos.kube import owners
from kubedelos.kube.client import KubeApi
from kubedelos.kube.rbac import RbacIndex
from kubedelos.models import (
    FactSources,
    ImageRef,
    InventoryItem,
    Workload,
    WorkloadFacts,
    is_digest,
    is_valid_ref,
)

logger = logging.getLogger(__name__)

DEFAULT_PLATFORM = "linux/amd64"
_PREFIXES = ("docker-pullable://", "docker://")


@dataclass(frozen=True)
class InventoryWarning:
    """Something the inventory could not see.

    ``coverage`` is True when images may be missing from the scan (a skipped namespace or resource). It is False when
    every image is still found and only extra detail is lost (owner info, the node platform), so that a run by a
    namespace-scoped identity without cluster-wide list rights is not marked incomplete.
    """

    text: str
    coverage: bool

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class Inventory:
    """What ``collect_inventory`` found: the items (with each workload's facts), the warnings and the status of every
    fact source for the run."""

    items: list[InventoryItem]
    warnings: list[InventoryWarning]
    fact_sources: FactSources


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
        # An untagged spec image was pulled as :latest; record that, as the template path does, so tag patterns match.
        tag = spec_tag or (None if spec_digest else "latest")
        return ImageRef(ref=f"{repo}@{digest}", repo=repo, tag=tag, digest=digest)
    if spec_digest and is_digest(spec_digest):
        return ImageRef(ref=f"{spec_repo}@{spec_digest}", repo=spec_repo, tag=spec_tag, digest=spec_digest)
    tag = spec_tag or "latest"
    local_id = image_id if is_digest(image_id) else None  # a bare "sha256:..." is the node's local image ID
    return ImageRef(ref=f"{spec_repo}:{tag}", repo=spec_repo, tag=tag, image_id=local_id)


def parse_user_ref(image: str) -> ImageRef | None:
    """The ``ImageRef`` of an image a user typed, or None when it is not a plausible ref.

    ``parse_image_id`` falls back to ``:latest`` for a malformed digest; for a typed ref that would check another image.
    """
    ref = parse_image_id(image, "")
    if not is_valid_ref(ref.ref) or ("@" in image and ref.digest is None):
        return None
    return ref


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


def image_names(image: ImageRef) -> set[str]:
    """Every name an image exclusion pattern may match for ``image``, whatever spelling the pod spec used.

    ``repo``, ``repo:tag`` and ``repo@digest`` on the normalised repo, plus the short Docker Hub forms people type
    (``nginx:1.19`` and ``library/nginx:1.19`` for ``docker.io/library/nginx:1.19``).
    """
    repos = {image.repo}
    host, _, path = image.repo.partition("/")  # the repo is normalised, so the first segment is always the host
    if host == "docker.io":
        repos.add(path)
        if path.startswith("library/"):
            repos.add(path.removeprefix("library/"))
    names = set(repos)
    for repo in repos:
        if image.tag:
            names.add(f"{repo}:{image.tag}")
        if image.digest:
            names.add(f"{repo}@{image.digest}")
    return names


def is_excluded(image: ImageRef, patterns: list[str]) -> bool:
    return any(fnmatchcase(name, pattern) for name in image_names(image) for pattern in patterns)


def _with_selector(list_fn, selector: str | None, *args: str) -> list:
    """Call ``list_fn`` with ``selector``; a selector the API server cannot parse (HTTP 400) is a clear error."""
    try:
        return list_fn(*args, label_selector=selector)
    except ApiException as exc:
        if selector is not None and exc.status == 400:
            raise ValueError(f"invalid label selector {selector!r}: {exc.reason}") from None
        raise


def _list_or_warn(list_fn, resource: str, ns: str, warnings: list[InventoryWarning], selector: str | None) -> list:
    try:
        return _with_selector(list_fn, selector, ns)
    except ApiException as exc:
        if not _is_forbidden(exc):
            raise
        warnings.append(InventoryWarning(f"skipped {resource} in namespace {ns}: forbidden", coverage=True))
        return []


def _list_fact(list_fn, ns: str, may_be_absent: bool = False) -> tuple[list | None, str]:
    """List one namespace's ``list_fn`` for the attack-surface facts. Returns ``(result, outcome)``: ``ok``; ``absent``
    (HTTP 404 from a kind that ``may_be_absent``, a CRD that is not installed, so ``[]``); or ``forbidden`` or ``error``
    with a result of None. A 404 from a built-in kind is an ``error``: it says nothing about what is there. A failed
    list only makes facts unknown, so no API or transport error escapes."""
    try:
        return list_fn(ns), "ok"
    except ApiException as exc:
        if exc.status == 404 and may_be_absent:
            return [], "absent"
        return None, "forbidden" if _is_forbidden(exc) else "error"
    except HTTPError:
        return None, "error"


class _Tally:
    """The per-namespace outcomes of one fact source, and the status and warning they add up to."""

    def __init__(self, resource: str) -> None:
        self.resource = resource
        self.outcomes: list[str] = []

    def record(self, outcome: str) -> None:
        self.outcomes.append(outcome)

    @property
    def failures(self) -> list[str]:
        return [o for o in self.outcomes if o in ("forbidden", "error")]

    @property
    def status(self) -> str:
        failed = self.failures
        if not failed:
            return "absent" if self.outcomes and set(self.outcomes) == {"absent"} else "ok"
        if "ok" in self.outcomes:
            return "partial"
        return "forbidden" if set(failed) == {"forbidden"} else "error"

    def warning(self) -> InventoryWarning | None:
        failed = self.failures
        if not failed:
            return None
        why = "forbidden" if set(failed) == {"forbidden"} else "error"
        count = len(failed)
        return InventoryWarning(
            f"attack-surface: cannot list {self.resource} in {count} namespace{'s' if count != 1 else ''} ({why}); "
            "their facts are unknown",
            coverage=False,
        )


@dataclass
class _NamespaceLists:
    """One namespace's lists for the facts; None is a list that failed or was not made."""

    services: list | None = None
    ingresses: list | None = None
    network_policies: list | None = None
    sa_automount: dict[str, bool | None] | None = None


def _select_namespaces(api: KubeApi, settings: Settings, warnings: list[InventoryWarning]) -> list[V1Namespace]:
    wanted = set(settings.namespaces)
    selector = settings.namespace_selector
    try:
        found = _with_selector(api.list_namespaces, selector)
    except ApiException as exc:
        if _is_forbidden(exc) and selector is not None:
            # The labels cannot be read, so the selector cannot be applied: never guess which namespaces it means.
            raise RuntimeError(
                "cannot list namespaces: forbidden; the namespace selector needs list rights on namespaces"
            ) from None
        if not (_is_forbidden(exc) and wanted):
            raise
        warnings.append(
            InventoryWarning(
                "cannot list namespaces: forbidden; owner info unavailable for the selected namespaces", coverage=False
            )
        )
        found = [V1Namespace(metadata=V1ObjectMeta(name=name)) for name in settings.namespaces]
    unmatched: set[str] = set()
    if selector is not None and wanted - {ns.metadata.name for ns in found}:
        # A named namespace the selector dropped is not missing: say so instead of reporting it as not found. The
        # unfiltered list needs no handling of its own: the filtered list above just succeeded with the same rights.
        unmatched = (wanted & {ns.metadata.name for ns in api.list_namespaces()}) - {ns.metadata.name for ns in found}
        for name in sorted(unmatched):
            warnings.append(
                InventoryWarning(f"namespace {name} does not match the namespace selector; not scanned", coverage=False)
            )
    for missing in sorted(wanted - unmatched - {ns.metadata.name for ns in found}):
        warnings.append(InventoryWarning(f"namespace {missing} not found", coverage=True))
    excluded = set(settings.exclude_namespaces)
    return [ns for ns in found if (not wanted or ns.metadata.name in wanted) and ns.metadata.name not in excluded]


def collect(api: KubeApi, settings: Settings) -> tuple[list[InventoryItem], list[InventoryWarning]]:
    """Return the inventory (grouped by image key and platform) and any warnings."""
    inventory = collect_inventory(api, settings)
    return inventory.items, inventory.warnings


def collect_inventory(api: KubeApi, settings: Settings) -> Inventory:
    """Return the inventory (grouped by image key and platform), any warnings, and each workload's facts."""
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

    pull_namespaces = set(settings.pod_pull_secret_namespaces)

    scanned: list[tuple[V1Namespace, list]] = []
    for ns in namespaces:
        try:
            scanned.append((ns, _with_selector(api.list_pods, settings.selector, ns.metadata.name)))
        except ApiException as exc:
            if not _is_forbidden(exc):
                raise
            warnings.append(InventoryWarning(f"skipped namespace {ns.metadata.name}: forbidden", coverage=True))
    scanned_names = [ns.metadata.name for ns, _ in scanned]

    attack_surface = settings.attack_surface
    tallies = {
        name: _Tally(resource)
        for name, resource in (
            ("services", "services"),
            ("ingresses", "ingresses"),
            ("httproutes", "httproutes"),
            ("network_policies", "networkpolicies"),
            ("service_accounts", "serviceaccounts"),
        )
    }
    httproutes: list[dict] | None = None
    rbac, rbac_status = RbacIndex.off(), "off"
    if attack_surface:
        # A route may point at a Service in another namespace, so every namespace's routes come first.
        routes: list[dict] = []
        route_lists = [_list_fact(api.list_httproutes, name, may_be_absent=True) for name in scanned_names]
        for found, outcome in route_lists:
            tallies["httproutes"].record(outcome)
            routes += found or []
        # One unread namespace could hold a route that exposes anything: unknown, not "no routes".
        httproutes = None if tallies["httproutes"].failures else routes
        rbac, rbac_status = RbacIndex.load(api, scanned_names)

    failed: set[tuple[str, str, str]] = set()  # (namespace, kind, name) of the workloads whose facts failed

    def add(
        image: ImageRef,
        platform: str,
        workload: Workload,
        pull_secrets: list[str] | None = None,
        facts: WorkloadFacts | None = None,
    ) -> None:
        item = items.setdefault((image.key, platform), InventoryItem(image=image, platform=platform))
        if workload not in item.workloads:
            item.workloads.append(workload)
        if facts is not None:
            known = item.facts.get(workload)
            item.facts[workload] = fact_builders.merge(known, facts) if known else facts
        if workload.namespace in pull_namespaces:
            for secret_name in pull_secrets or []:
                ref = (workload.namespace, secret_name)
                if ref not in item.pull_secrets:
                    item.pull_secrets.append(ref)

    for ns, pods in scanned:
        name = ns.metadata.name
        owner, team = owners.resolve(ns, settings)
        lists = _NamespaceLists()
        if attack_surface:
            lists.services = _record(tallies["services"], _list_fact(api.list_services, name))
            lists.ingresses = _record(tallies["ingresses"], _list_fact(api.list_ingresses, name))
            lists.network_policies = _record(tallies["network_policies"], _list_fact(api.list_network_policies, name))
            accounts = _record(tallies["service_accounts"], _list_fact(api.list_service_accounts, name))
            if accounts is not None:
                lists.sa_automount = {a.metadata.name: a.automount_service_account_token for a in accounts}

        def facts_for(workload, spec, container, labels, name=name, lists=lists) -> WorkloadFacts:
            # Facts never fail a scan: whatever goes wrong deriving them, the workload gets unknown facts instead.
            service_account = getattr(spec, "service_account_name", None) or "default"
            try:
                return WorkloadFacts(
                    pod=fact_builders.pod_security(spec, container, lists.sa_automount),
                    exposure=fact_builders.exposure(
                        labels, name, lists.services, lists.ingresses, httproutes, container
                    ),
                    network=fact_builders.network(labels, lists.network_policies),
                    rights=rbac.rights(name, service_account),
                )
            except Exception as exc:  # any failure only makes these facts unknown
                failed.add((workload.namespace, workload.kind, workload.name))
                logger.debug(
                    "attack-surface: facts for %s/%s/%s container %s failed: %s",
                    workload.namespace,
                    workload.kind,
                    workload.name,
                    workload.container,
                    type(exc).__name__,
                )
                return fact_builders.unknown(service_account)

        deployments = _list_or_warn(api.list_deployments, "deployments", name, warnings, settings.selector)
        statefulsets = _list_or_warn(api.list_statefulsets, "statefulsets", name, warnings, settings.selector)
        cronjobs = _list_or_warn(api.list_cronjobs, "cronjobs", name, warnings, settings.selector)

        for pod in pods:
            ids = _status_ids(pod)
            kind, workload_name = _pod_owner(pod)
            platform = (node_platform.get(pod.spec.node_name) if pod.spec else None) or fallback
            for c in _spec_containers(pod.spec):
                image = parse_image_id(c.image, ids.get(c.name, ""))
                workload = Workload(
                    namespace=name, kind=kind, name=workload_name, container=c.name, owner=owner, team=team
                )
                facts = facts_for(workload, pod.spec, c, pod.metadata.labels or {})
                add(image, platform, workload, _pull_secret_names(pod.spec), facts)

        templates = [("Deployment", d) for d in deployments if d.spec and d.spec.replicas == 0]
        templates += [("StatefulSet", s) for s in statefulsets if s.spec and s.spec.replicas == 0]
        for kind, obj in templates:
            template = obj.spec.template
            _add_template(add, facts_for, name, kind, obj.metadata.name, template, owner, team, fallback)
        for cj in cronjobs:
            template = cj.spec.job_template.spec.template
            _add_template(add, facts_for, name, "CronJob", cj.metadata.name, template, owner, team, fallback)

    fact_sources = {"pod_security": "ok"}
    for source, tally in tallies.items():
        fact_sources[source] = tally.status if attack_surface else "off"
        if warning := tally.warning():
            warnings.append(warning)
    fact_sources["rbac"] = rbac_status
    if failed:
        warnings.append(
            InventoryWarning(
                f"attack-surface: could not derive facts for {len(failed)} workload(s); their facts are unknown",
                coverage=False,
            )
        )
    if rbac_status in ("partial", "forbidden", "error"):
        outcome = "partial" if rbac_status == "partial" else "unknown"
        warnings.append(
            InventoryWarning(
                f"attack-surface: cannot fully list roles and bindings ({rbac_status}); "
                f"service account rights are {outcome}",
                coverage=False,
            )
        )

    kept = [item for item in items.values() if not is_excluded(item.image, settings.exclude_images)]
    if excluded := len(items) - len(kept):
        warnings.append(InventoryWarning(f"excluded {excluded} image(s) matching the image exclusions", coverage=False))
    return Inventory(kept, warnings, fact_sources)


def _record(tally: _Tally, listed: tuple[list | None, str]) -> list | None:
    """Count one namespace's outcome in ``tally`` and return the list."""
    result, outcome = listed
    tally.record(outcome)
    return result


def _pull_secret_names(spec) -> list[str]:
    """The names in a pod spec's ``imagePullSecrets``; the Secrets themselves are not read here."""
    return [ref.name for ref in (spec.image_pull_secrets if spec else None) or [] if ref.name]


def _add_template(add, facts_for, ns: str, kind: str, name: str, template, owner, team, platform: str) -> None:
    """Add a workload that has no pod right now (scaled to zero, or a CronJob) from its pod template."""
    pod_spec = template.spec
    labels = (template.metadata.labels if template.metadata else None) or {}
    pull_secrets = _pull_secret_names(pod_spec)
    for c in _spec_containers(pod_spec):
        workload = Workload(namespace=ns, kind=kind, name=name, container=c.name, owner=owner, team=team)
        add(parse_image_id(c.image, ""), platform, workload, pull_secrets, facts_for(workload, pod_spec, c, labels))
