"""Attack-surface facts derived from Kubernetes objects the inventory has already listed.

The facts say what a workload's pod spec lets it do on the node (``pod_security``), how far it is reachable
(``exposure``) and whether NetworkPolicies isolate it (``network``), and ``merge`` folds the facts of several pods
of one workload container into the riskiest view. Everything here is a pure function of
objects already in hand: nothing calls the cluster, and no Secret is ever read (only the names that specs refer to).
"""

from kubedelos.models import (
    ExposedService,
    Exposure,
    HostPath,
    Network,
    PodSecurity,
    Rights,
    Tri,
    WorkloadFacts,
)

# Service annotations that make a LoadBalancer internal (key -> value, compared without regard to case). Checked
# against the vendors' docs:
#   AKS:  https://learn.microsoft.com/en-us/azure/aks/internal-lb
#   AWS:  https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/service/annotations/
#         (aws-load-balancer-internal is deprecated there but still honoured; the in-tree AWS cloud provider uses it)
#   GKE:  https://docs.cloud.google.com/kubernetes-engine/docs/how-to/internal-load-balancing
#         (networking.gke.io/load-balancer-type is current; cloud.google.com/load-balancer-type is the legacy key)
INTERNAL_LB_ANNOTATIONS = {
    "service.beta.kubernetes.io/azure-load-balancer-internal": "true",
    "service.beta.kubernetes.io/aws-load-balancer-internal": "true",
    "service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
    "networking.gke.io/load-balancer-type": "internal",
    "cloud.google.com/load-balancer-type": "internal",
}
_SERVICE_RISK = {"LoadBalancer": 2, "NodePort": 2, "ExternalName": 1}
_EXPOSURE_RANK = {"external": 3, "unknown": 2, "cluster": 1, "none": 0}
_STATUS_RANK = {"unknown": 3, "partial": 2, "ok": 1, "off": 0}


def pod_security(pod_spec, container, sa_automount: dict[str, bool | None] | None) -> PodSecurity:
    """What ``container`` of ``pod_spec`` may do on the node; ``sa_automount`` maps ServiceAccount names to their
    ``automountServiceAccountToken`` (None when ServiceAccounts were not listed)."""
    pod_ctx = pod_spec.security_context
    ctx = container.security_context
    privileged = bool(ctx and ctx.privileged)
    escalation = ctx.allow_privilege_escalation if ctx else None
    caps = ctx.capabilities if ctx else None
    service_account = pod_spec.service_account_name or "default"
    return PodSecurity(
        privileged=privileged,
        allow_privilege_escalation=privileged or escalation is None or escalation,
        runs_as_root=_runs_as_root(pod_ctx, ctx),
        read_only_root_fs=bool(ctx and ctx.read_only_root_filesystem),
        added_capabilities=tuple(sorted(set((caps.add or []) if caps else []))),
        host_network=bool(pod_spec.host_network),
        host_pid=bool(pod_spec.host_pid),
        host_ipc=bool(pod_spec.host_ipc),
        host_path_volumes=_host_paths(pod_spec, container),
        service_account=service_account,
        automount_token=_automount(pod_spec.automount_service_account_token, service_account, sa_automount),
        secret_refs=_secret_refs(pod_spec, container),
    )


def _effective(field: str, pod_ctx, ctx):
    """The container's value of a security-context field, else the pod's."""
    value = getattr(ctx, field, None) if ctx else None
    return value if value is not None else getattr(pod_ctx, field, None) if pod_ctx else None


def _runs_as_root(pod_ctx, ctx) -> Tri:
    user = _effective("run_as_user", pod_ctx, ctx)
    if user == 0:
        return True
    if (user is not None and user > 0) or _effective("run_as_non_root", pod_ctx, ctx):
        return False
    return None


def _mounted_volumes(pod_spec, container) -> list:
    mounted = {m.name for m in container.volume_mounts or []}
    return [v for v in pod_spec.volumes or [] if v.name in mounted]


def _host_paths(pod_spec, container) -> tuple[HostPath, ...]:
    read_only = {m.name: bool(m.read_only) for m in container.volume_mounts or []}
    paths = [
        HostPath(path=v.host_path.path, read_only=read_only[v.name])
        for v in _mounted_volumes(pod_spec, container)
        if v.host_path
    ]
    return tuple(sorted(paths, key=lambda h: h.path))


def _secret_refs(pod_spec, container) -> tuple[str, ...]:
    names: set[str] = set()
    for v in _mounted_volumes(pod_spec, container):
        if v.secret and v.secret.secret_name:
            names.add(v.secret.secret_name)
        for source in (v.projected.sources or []) if v.projected else []:
            if source.secret and source.secret.name:
                names.add(source.secret.name)
    for env in container.env or []:
        ref = env.value_from.secret_key_ref if env.value_from else None
        if ref and ref.name:
            names.add(ref.name)
    for env_from in container.env_from or []:
        if env_from.secret_ref and env_from.secret_ref.name:
            names.add(env_from.secret_ref.name)
    return tuple(sorted(names))


def _automount(pod_value: bool | None, service_account: str, sa_automount: dict[str, bool | None] | None) -> Tri:
    if pod_value is not None:
        return pod_value
    if sa_automount is None:
        return None
    value = sa_automount.get(service_account)
    return True if value is None else value


def selector_matches(selector, labels: dict[str, str]) -> bool:
    """Whether a ``V1LabelSelector`` selects ``labels``; an empty (or missing) selector selects everything."""
    if selector is None:
        return True
    if any(labels.get(k) != v for k, v in (selector.match_labels or {}).items()):
        return False
    return all(_expression_matches(e, labels) for e in selector.match_expressions or [])


def _expression_matches(expression, labels: dict[str, str]) -> bool:
    present = expression.key in labels
    match expression.operator:
        case "In":
            return present and labels[expression.key] in (expression.values or [])
        case "NotIn":
            return not present or labels[expression.key] not in (expression.values or [])
        case "Exists":
            return present
        case "DoesNotExist":
            return not present
    return False  # an operator Kubernetes would have rejected


def exposure(
    labels: dict[str, str],
    namespace: str,
    services: list | None,
    ingresses: list | None,
    httproutes: list[dict] | None,
) -> Exposure:
    """How far a pod with ``labels`` in ``namespace`` is reachable.

    ``services`` and ``ingresses`` must be those of the pod's namespace (an Ingress cannot point across namespaces);
    ``httproutes`` are those of every scanned namespace, as a route may point at a Service elsewhere. ``services``
    None means they could not be listed (unknown). ``ingresses`` or ``httproutes`` None means the list was forbidden
    or failed; the caller passes ``[]`` when the kind does not exist (the CRD is absent). When Services match but
    nothing proves external reach and one of those lists is None, the level is unknown: an unread Ingress or route
    could have made it external."""
    if services is None:
        return Exposure(level="unknown")
    matched = [s for s in services if _service_selects(s, labels)]
    names = {s.metadata.name for s in matched}
    hosts: set[str] = set()
    routed = False
    for ing in ingresses or []:
        ing_hosts, reaches = _ingress_reach(ing, names)
        routed = routed or reaches
        hosts.update(ing_hosts)
    for route in httproutes or []:
        if _route_backends(route, namespace) & names:
            routed = True
            hosts.update((route.get("spec") or {}).get("hostnames") or [])
    exposed = [
        ExposedService(name=s.metadata.name, type=s.spec.type or "ClusterIP", internal_lb=_internal_lb(s))
        for s in matched
    ]
    external_ips = sorted({ip for s in matched for ip in s.spec.external_ips or []})
    if routed or external_ips or any(_publicly_reachable(e) for e in exposed):
        level = "external"
    elif not matched:
        level = "none"  # a route needs a Service
    elif ingresses is None or httproutes is None:
        level = "unknown"
    else:
        level = "cluster"
    return Exposure(
        level=level,
        services=tuple(sorted(exposed, key=lambda e: e.name)),
        external_ips=tuple(external_ips),
        hosts=tuple(sorted(hosts)),
    )


def _service_selects(service, labels: dict[str, str]) -> bool:
    spec = service.spec
    if spec.type == "ExternalName" or not spec.selector:
        return False
    return all(labels.get(k) == v for k, v in spec.selector.items())


_AWS_SCHEME = "service.beta.kubernetes.io/aws-load-balancer-scheme"
_GKE_TYPE = "networking.gke.io/load-balancer-type"


def _internal_lb(service) -> bool:
    """Whether every recognised provider annotation says internal. A provider's authoritative key decides alone
    when present; its legacy key counts only without it. Any other value, or no annotation, means external."""
    if service.spec.type != "LoadBalancer":
        return False
    annotations = {k: str(v).lower() for k, v in (service.metadata.annotations or {}).items()}
    azure = annotations.get("service.beta.kubernetes.io/azure-load-balancer-internal")
    decisions = []
    if azure is not None:
        decisions.append(azure == "true")
    for authoritative, legacy, legacy_internal in (
        (_AWS_SCHEME, "service.beta.kubernetes.io/aws-load-balancer-internal", "true"),
        (_GKE_TYPE, "cloud.google.com/load-balancer-type", "internal"),
    ):
        if authoritative in annotations:
            decisions.append(annotations[authoritative] == "internal")
        elif legacy in annotations:
            decisions.append(annotations[legacy] == legacy_internal)
    return bool(decisions) and all(decisions)


def _publicly_reachable(e: ExposedService) -> bool:
    return e.type == "NodePort" or (e.type == "LoadBalancer" and not e.internal_lb)


def _ingress_reach(ing, names: set[str]) -> tuple[set[str], bool]:
    """The hosts of the Ingress rules that reach one of ``names``, and whether the Ingress reaches any."""
    spec = ing.spec
    reaches = bool(spec.default_backend and spec.default_backend.service and spec.default_backend.service.name in names)
    hosts: set[str] = set()
    for rule in spec.rules or []:
        paths = (rule.http.paths if rule.http else None) or []
        if any(p.backend and p.backend.service and p.backend.service.name in names for p in paths):
            reaches = True
            if rule.host:
                hosts.add(rule.host)
    return hosts, reaches


def _route_backends(route: dict, namespace: str) -> set[str]:
    """Names of the Services in ``namespace`` an HTTPRoute sends to; kind and group default to Service and ``""``.
    A ref's namespace defaults to the route's. Whether a ReferenceGrant allows a cross-namespace ref is not checked:
    counting it can only over-report, which is the conservative side."""
    route_ns = (route.get("metadata") or {}).get("namespace")
    names: set[str] = set()
    for rule in (route.get("spec") or {}).get("rules") or []:
        for ref in rule.get("backendRefs") or []:
            if ref.get("kind", "Service") != "Service" or ref.get("group", "") != "" or not ref.get("name"):
                continue
            if (ref.get("namespace") or route_ns) == namespace:
                names.add(ref["name"])
    return names


def network(labels: dict[str, str], policies: list | None) -> Network:
    """Whether NetworkPolicies isolate a pod with ``labels``; None ``policies`` means they could not be listed.
    ``policies`` must be those of the pod's namespace. Policies are additive, so a selecting policy with an
    allow-all rule leaves that direction open (its name is still listed)."""
    if policies is None:
        return Network(ingress_isolated=None, egress_isolated=None)
    ingress: list[str] = []
    egress: list[str] = []
    open_in = open_out = False
    for policy in policies:
        spec = policy.spec
        if not selector_matches(spec.pod_selector, labels):
            continue
        types = spec.policy_types or ["Ingress", *(["Egress"] if spec.egress else [])]
        if "Ingress" in types:
            ingress.append(policy.metadata.name)
            open_in = open_in or any(_allows_all(r._from) for r in spec.ingress or [])
        if "Egress" in types:
            egress.append(policy.metadata.name)
            open_out = open_out or any(_allows_all(r.to) for r in spec.egress or [])
    return Network(
        ingress_isolated=bool(ingress) and not open_in,
        egress_isolated=bool(egress) and not open_out,
        ingress_policies=tuple(sorted(ingress)),
        egress_policies=tuple(sorted(egress)),
    )


def _allows_all(peers) -> bool:
    """Whether a rule admits every peer: no peers listed (ports alone restrict nothing about who), or one that
    covers everything."""
    return not peers or any(_peer_is_everyone(p) for p in peers)


def _peer_is_everyone(peer) -> bool:
    block = peer.ip_block
    if block and block.cidr in ("0.0.0.0/0", "::/0") and not block._except:
        return True
    return _empty_selector(peer.namespace_selector, required=True) and _empty_selector(peer.pod_selector)


def _empty_selector(selector, required: bool = False) -> bool:
    if selector is None:
        return not required
    return not selector.match_labels and not selector.match_expressions


def _tri_riskier(a: Tri, b: Tri) -> Tri:
    """True > None > False."""
    if a is True or b is True:
        return True
    return None if a is None or b is None else False


def _isolation_riskier(a: Tri, b: Tri) -> Tri:
    """For an isolation fact the risky value is False (not isolated): False > None > True."""
    if a is False or b is False:
        return False
    return None if a is None or b is None else True


def merge(a: WorkloadFacts, b: WorkloadFacts) -> WorkloadFacts:
    """The riskier value of each fact of two views of the same workload container."""
    return WorkloadFacts(
        pod=_merge_pod(a.pod, b.pod),
        exposure=_merge_exposure(a.exposure, b.exposure),
        network=_merge_network(a.network, b.network),
        rights=_merge_rights(a.rights, b.rights),
    )


def _union(a, b) -> tuple:
    return tuple(sorted(set(a) | set(b)))


def _merge_pod(a: PodSecurity, b: PodSecurity) -> PodSecurity:
    read_only: dict[str, bool] = {}
    for h in (*a.host_path_volumes, *b.host_path_volumes):
        read_only[h.path] = read_only.get(h.path, True) and h.read_only
    return PodSecurity(
        privileged=a.privileged or b.privileged,
        allow_privilege_escalation=a.allow_privilege_escalation or b.allow_privilege_escalation,
        runs_as_root=_tri_riskier(a.runs_as_root, b.runs_as_root),
        read_only_root_fs=a.read_only_root_fs and b.read_only_root_fs,  # a writable root is the risk
        added_capabilities=_union(a.added_capabilities, b.added_capabilities),
        host_network=a.host_network or b.host_network,
        host_pid=a.host_pid or b.host_pid,
        host_ipc=a.host_ipc or b.host_ipc,
        host_path_volumes=tuple(HostPath(path=p, read_only=ro) for p, ro in sorted(read_only.items())),
        service_account=a.service_account,
        automount_token=_tri_riskier(a.automount_token, b.automount_token),
        secret_refs=_union(a.secret_refs, b.secret_refs),
    )


def _merge_exposure(a: Exposure, b: Exposure) -> Exposure:
    by_name: dict[str, ExposedService] = {}
    for s in (*a.services, *b.services):
        old = by_name.get(s.name)
        if old is None:
            by_name[s.name] = s
            continue
        riskier = s if _SERVICE_RISK.get(s.type, 0) > _SERVICE_RISK.get(old.type, 0) else old
        by_name[s.name] = riskier.model_copy(update={"internal_lb": old.internal_lb and s.internal_lb})
    return Exposure(
        level=max(a.level, b.level, key=_EXPOSURE_RANK.__getitem__),
        services=tuple(by_name[n] for n in sorted(by_name)),
        external_ips=_union(a.external_ips, b.external_ips),
        hosts=_union(a.hosts, b.hosts),
    )


def _merge_network(a: Network, b: Network) -> Network:
    return Network(
        ingress_isolated=_isolation_riskier(a.ingress_isolated, b.ingress_isolated),
        egress_isolated=_isolation_riskier(a.egress_isolated, b.egress_isolated),
        ingress_policies=_union(a.ingress_policies, b.ingress_policies),
        egress_policies=_union(a.egress_policies, b.egress_policies),
    )


def _merge_rights(a: Rights, b: Rights) -> Rights:
    if "cluster" in (a.reads_secrets_scope, b.reads_secrets_scope):
        scope = "cluster"
    else:
        union = _union(a.reads_secrets_scope or (), b.reads_secrets_scope or ())
        scope = union or None
    return Rights(
        status=max(a.status, b.status, key=_STATUS_RANK.__getitem__),
        cluster_admin=a.cluster_admin or b.cluster_admin,
        reads_secrets=a.reads_secrets or b.reads_secrets,
        reads_secrets_scope=scope,
        creates_workloads=a.creates_workloads or b.creates_workloads,
        pod_exec=a.pod_exec or b.pod_exec,
        escalates=a.escalates or b.escalates,
        wildcard=a.wildcard or b.wildcard,
        bindings=_union(a.bindings, b.bindings),
    )
