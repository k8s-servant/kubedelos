"""Reduce a ServiceAccount's RBAC bindings to the few rights that matter for attack surface.

``RbacIndex.load`` lists Roles, ClusterRoles, RoleBindings and ClusterRoleBindings once per scan (cluster-wide when
it may, per scanned namespace when it may not), and ``rights`` folds the bindings that name one ServiceAccount
into ``Rights`` flags: cluster admin, reading Secrets, creating workloads, exec into pods, privilege escalation and
wildcard grants. Only Roles and bindings are listed: no Secret is ever read, and nothing in the cluster is changed.
Matching follows Kubernetes: verbs, resources and apiGroups compare case-sensitively, and a narrow grant (one with
``resourceNames``) still counts as a grant.
"""

from dataclasses import dataclass, field

from kubernetes.client.rest import ApiException

from kubedelos.kube.client import KubeApi
from kubedelos.models import Rights

CLUSTER_ADMIN = "cluster-admin"
_READ = {"get", "list", "watch", "*"}
_WORKLOADS = {"pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"}
_EXEC = {"pods/exec", "pods/attach"}
_RBAC = {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
_ESCALATE_VERBS = {"escalate", "bind", "impersonate"}


def _verbs(rule, wanted: set[str]) -> bool:
    verbs = rule.verbs or []
    return "*" in verbs or any(v in wanted for v in verbs)


def _covers(granted: str, wanted: str) -> bool:
    """Whether a rule's resource covers ``wanted``: ``*`` covers everything, subresources included, and
    ``pods/*`` or ``*/exec`` cover ``pods/exec``."""
    if granted in ("*", wanted):
        return True
    base, _, sub = wanted.partition("/")
    return bool(sub) and granted in (f"{base}/*", f"*/{sub}")


def _resources(rule, wanted: set[str]) -> bool:
    return any(_covers(granted, w) for granted in rule.resources or [] for w in wanted)


@dataclass
class _Acc:
    """The flags gathered so far for one ServiceAccount."""

    cluster_admin: bool = False
    creates_workloads: bool = False
    pod_exec: bool = False
    escalates: bool = False
    wildcard: bool = False
    secrets_cluster: bool = False
    secrets_namespaces: set[str] = field(default_factory=set)
    unresolved: bool = False

    def grant_all(self, ns: str | None) -> None:
        """Everything a ``cluster-admin`` grant gives: cluster-wide when ``ns`` is None, else within ``ns``."""
        self.cluster_admin = self.cluster_admin or ns is None
        self.creates_workloads = self.pod_exec = self.escalates = self.wildcard = True
        self._secrets(ns)

    def _secrets(self, ns: str | None) -> None:
        if ns is None:
            self.secrets_cluster = True
        else:
            self.secrets_namespaces.add(ns)

    def apply(self, rule, ns: str | None) -> None:
        """Fold one rule in, granted cluster-wide (``ns`` None) or within ``ns``. A rule naming no resources (only
        nonResourceURLs) grants nothing counted here."""
        resources = rule.resources or []
        if not resources:
            return
        verbs, groups = rule.verbs or [], rule.api_groups or []
        if "*" in verbs or "*" in resources:
            self.wildcard = True
        if ns is None and "*" in verbs and "*" in resources and "*" in groups:
            self.cluster_admin = True
        if _verbs(rule, _READ) and _resources(rule, {"secrets"}) and ("" in groups or "*" in groups):
            self._secrets(ns)
        if _verbs(rule, {"create"}) and _resources(rule, _WORKLOADS):
            self.creates_workloads = True
        if _verbs(rule, {"create", "get"}) and _resources(rule, _EXEC):
            self.pod_exec = True
        if _verbs(rule, _ESCALATE_VERBS) or (_verbs(rule, {"create", "update", "patch"}) and _resources(rule, _RBAC)):
            self.escalates = True

    def rights(self, status: str, bindings: list[str]) -> Rights:
        reads = self.secrets_cluster or bool(self.secrets_namespaces)
        scope = "cluster" if self.secrets_cluster else tuple(sorted(self.secrets_namespaces)) if reads else None
        return Rights(
            status="partial" if self.unresolved else status,
            cluster_admin=self.cluster_admin,
            reads_secrets=reads,
            reads_secrets_scope=scope,
            creates_workloads=self.creates_workloads,
            pod_exec=self.pod_exec,
            escalates=self.escalates,
            wildcard=self.wildcard,
            bindings=tuple(sorted(bindings)),
        )


def _subject_matches(subject, ns: str, service_account: str) -> bool:
    if subject.kind == "ServiceAccount":
        return subject.name == service_account and bool(subject.namespace) and subject.namespace == ns
    if subject.kind == "Group":
        return subject.name in ("system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated")
    return False


def _applies(binding, ns: str, service_account: str) -> bool:
    return any(_subject_matches(s, ns, service_account) for s in binding.subjects or [])


class _Lister:
    """Calls list methods, remembering whether any succeeded and whether any failure was other than 403."""

    def __init__(self) -> None:
        self.read = False
        self.failed = False
        self.errored = False

    def __call__(self, fn, *args) -> list | None:
        try:
            objs = fn(*args)
        except ApiException as exc:
            self.failed = True
            self.errored = self.errored or exc.status != 403
            return None
        self.read = True
        return objs


class RbacIndex:
    """The Roles and bindings listed for one scan; ``rights`` answers per ServiceAccount from them."""

    def __init__(
        self,
        status: str,
        cluster_roles: list | None = None,
        cluster_role_bindings: list | None = None,
        roles: list | None = None,
        role_bindings: list | None = None,
    ) -> None:
        self.status = status
        self._cluster_roles = {r.metadata.name: r.rules or [] for r in cluster_roles or []}
        self._cluster_role_bindings = cluster_role_bindings or []
        self._roles = {(r.metadata.namespace, r.metadata.name): r.rules or [] for r in roles or []}
        self._role_bindings = role_bindings or []

    @classmethod
    def off(cls) -> "RbacIndex":
        return cls("off")

    @classmethod
    def load(cls, api: KubeApi, namespaces: list[str]) -> tuple["RbacIndex", str]:
        """List every Role and binding the scan may see; the second value is the ``rbac`` fact source status:
        ok (everything listed cluster-wide), partial (some lists), forbidden or error (none)."""
        lister = _Lister()
        cluster_roles = lister(api.list_cluster_roles)
        cluster_role_bindings = lister(api.list_cluster_role_bindings)
        roles = lister(api.list_roles, None)
        role_bindings = lister(api.list_role_bindings, None)
        if not lister.failed:
            return cls("ok", cluster_roles, cluster_role_bindings, roles, role_bindings), "ok"
        if roles is None:
            roles = [r for ns in dict.fromkeys(namespaces) for r in lister(api.list_roles, ns) or []]
        if role_bindings is None:
            role_bindings = [b for ns in dict.fromkeys(namespaces) for b in lister(api.list_role_bindings, ns) or []]
        status = "partial" if lister.read else "error" if lister.errored else "forbidden"
        return cls(status, cluster_roles, cluster_role_bindings, roles, role_bindings), status

    def rights(self, ns: str, service_account: str) -> Rights:
        """What ``service_account`` in ``ns`` may do through the bindings that name it."""
        if self.status == "off":
            return Rights(status="off")
        if self.status in ("forbidden", "error"):
            return Rights(status="unknown")
        acc, bindings = _Acc(), []
        for crb in self._cluster_role_bindings:
            if not _applies(crb, ns, service_account):
                continue
            bindings.append(f"ClusterRoleBinding/{crb.metadata.name}")
            name = crb.role_ref.name
            if name == CLUSTER_ADMIN:  # every flag, listed or not
                acc.grant_all(None)
                continue
            self._grant(acc, self._cluster_roles.get(name), None)
        for rb in self._role_bindings:
            if not _applies(rb, ns, service_account):
                continue
            rb_ns = rb.metadata.namespace
            bindings.append(f"RoleBinding/{rb_ns}/{rb.metadata.name}")
            ref = rb.role_ref
            rules = (
                self._cluster_roles.get(ref.name) if ref.kind == "ClusterRole" else self._roles.get((rb_ns, ref.name))
            )
            if rules is None and ref.kind == "ClusterRole" and ref.name == CLUSTER_ADMIN:
                acc.grant_all(rb_ns)  # unlisted, but its grant is known: everything, within rb_ns
                continue
            self._grant(acc, rules, rb_ns)
        return acc.rights("ok" if self.status == "ok" else "partial", bindings)

    @staticmethod
    def _grant(acc: _Acc, rules: list | None, ns: str | None) -> None:
        """Fold a role's rules in; a role that wasn't listed (None) makes the result partial."""
        if rules is None:
            acc.unresolved = True
            return
        for rule in rules:
            acc.apply(rule, ns)
