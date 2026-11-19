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
from urllib3.exceptions import HTTPError

from kubedelos.kube.client import KubeApi
from kubedelos.models import Rights

CLUSTER_ADMIN = "cluster-admin"
_READ = {"get", "list", "watch", "*"}
# Changing a pod template or a pod's image runs arbitrary pods just as creating one does.
_WRITE = {"create", "update", "patch", "*"}
_WORKLOADS = {
    "pods",
    "deployments",
    "statefulsets",
    "daemonsets",
    "replicasets",
    "replicationcontrollers",
    "jobs",
    "cronjobs",
}
# Sinks: (verbs, resources) pairs, any of whose verbs (or ``*``) on any of whose resources sets the flag.
_EXEC_SINKS = (
    ({"create", "get"}, {"pods/exec", "pods/attach"}),  # a shell in, or the stdio of, a running container
    ({"create", "get"}, {"pods/portforward"}),  # a network pivot into the pod
    ({"patch", "update"}, {"pods/ephemeralcontainers"}),  # injects a container into the pod: effectively exec
    ({"create", "get"}, {"nodes/proxy"}),  # the kubelet API, which allows exec into any pod on the node
)
_ESCALATE_SINKS = (
    ({"create", "update", "patch"}, {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}),  # grant more
    ({"create"}, {"serviceaccounts/token"}),  # mints tokens for other ServiceAccounts
)
_ESCALATE_VERBS = {"escalate", "bind", "impersonate"}  # escalate on any resource, whatever it names


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


def _hits(rule, sinks) -> bool:
    return any(_verbs(rule, verbs) and _resources(rule, resources) for verbs, resources in sinks)


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
        if _verbs(rule, _WRITE) and _resources(rule, _WORKLOADS):
            self.creates_workloads = True
        if _hits(rule, _EXEC_SINKS):
            self.pod_exec = True
        # Verb ``*`` on any resource counts as escalate/bind/impersonate on purpose: it overstates, never understates.
        if _verbs(rule, _ESCALATE_VERBS) or _hits(rule, _ESCALATE_SINKS):
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


def _subject_matches(subject, ns: str, service_account: str, binding_ns: str | None) -> bool:
    """Whether a binding subject names the ServiceAccount: directly, by its username
    ``system:serviceaccount:<ns>:<name>`` as a User, or through a group every ServiceAccount in ``ns`` is in.
    ``binding_ns`` is a RoleBinding's namespace (None for a ClusterRoleBinding): as in the Kubernetes authorizer, a
    ServiceAccount subject without a namespace means the RoleBinding's own, and never matches in a
    ClusterRoleBinding."""
    if subject.kind == "ServiceAccount":
        subject_ns = subject.namespace or binding_ns
        return subject.name == service_account and bool(subject_ns) and subject_ns == ns
    if subject.kind == "Group":
        return subject.name in ("system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated")
    if subject.kind == "User":
        return subject.name == f"system:serviceaccount:{ns}:{service_account}"
    return False


def _applies(binding, ns: str, service_account: str, binding_ns: str | None = None) -> bool:
    return any(_subject_matches(s, ns, service_account, binding_ns) for s in binding.subjects or [])


class _Lister:
    """Calls list methods, remembering whether any failed and whether any failure was other than 403. A transport
    error (urllib3 ``HTTPError``, such as a connection reset) counts as a non-403 failure."""

    def __init__(self) -> None:
        self.failed = False
        self.errored = False

    def __call__(self, fn, *args) -> list | None:
        try:
            objs = fn(*args)
        except ApiException as exc:
            self.failed = True
            self.errored = self.errored or exc.status != 403
            return None
        except HTTPError:
            self.failed = self.errored = True
            return None
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
        ok (everything listed cluster-wide), partial (some binding lists), forbidden or error (no binding list)."""
        lister = _Lister()
        cluster_roles = lister(api.list_cluster_roles)
        cluster_role_bindings = lister(api.list_cluster_role_bindings)
        roles = lister(api.list_roles, None)
        role_bindings = lister(api.list_role_bindings, None)
        bindings_read = cluster_role_bindings is not None or role_bindings is not None
        if not lister.failed:
            return cls("ok", cluster_roles, cluster_role_bindings, roles, role_bindings), "ok"
        if roles is None:
            roles = [r for ns in dict.fromkeys(namespaces) for r in lister(api.list_roles, ns) or []]
        if role_bindings is None:
            listed = [lister(api.list_role_bindings, ns) for ns in dict.fromkeys(namespaces)]
            bindings_read = bindings_read or any(b is not None for b in listed)
            role_bindings = [b for batch in listed for b in batch or []]
        # Roles alone say nothing about who holds them: without any binding list there is nothing to go on.
        status = "partial" if bindings_read else "error" if lister.errored else "forbidden"
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
            rb_ns = rb.metadata.namespace
            if not _applies(rb, ns, service_account, rb_ns):
                continue
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
