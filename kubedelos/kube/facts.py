"""Attack-surface facts derived from Kubernetes objects the inventory has already listed.

The facts say what a workload's pod spec lets it do on the node (``pod_security``), and ``merge`` folds the
facts of several pods of one workload container into the riskiest view. Everything here is a pure function of
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
