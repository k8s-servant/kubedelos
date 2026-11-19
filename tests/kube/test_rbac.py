import pytest
from kubernetes.client import V1PolicyRule
from urllib3.exceptions import ProtocolError

from kubedelos.kube.rbac import RbacIndex
from kubedelos.models import Rights
from tests.kube.fakes import FakeKubeApi, cluster_role, cluster_role_binding, role, role_binding

SA = [("ServiceAccount", "sa", "web")]
ADMIN_RULES = [(["*"], ["*"], ["*"], None)]
SECRET_READER = [([""], ["secrets"], ["get"], None)]
ALL_CLUSTER_WIDE = {("clusterroles", "*"), ("clusterrolebindings", "*"), ("roles", "*"), ("rolebindings", "*")}


def _rights(api: FakeKubeApi, ns: str = "web", sa: str = "sa", namespaces: list[str] | None = None) -> Rights:
    index, _ = RbacIndex.load(api, namespaces or ["web"])
    return index.rights(ns, sa)


def test_cluster_admin_binding():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("cluster-admin", ADMIN_RULES)],
        cluster_role_bindings=[cluster_role_binding("admins", "cluster-admin", SA)],
    )
    index, status = RbacIndex.load(api, ["web"])
    rights = index.rights("web", "sa")
    assert status == "ok"
    assert rights == Rights(
        status="ok",
        cluster_admin=True,
        reads_secrets=True,
        reads_secrets_scope="cluster",
        creates_workloads=True,
        pod_exec=True,
        escalates=True,
        wildcard=True,
        bindings=("ClusterRoleBinding/admins",),
    )


def test_cluster_admin_binding_unresolved_still_counts():
    api = FakeKubeApi(cluster_role_bindings=[cluster_role_binding("admins", "cluster-admin", SA)])
    assert _rights(api) == Rights(
        status="ok",
        cluster_admin=True,
        reads_secrets=True,
        reads_secrets_scope="cluster",
        creates_workloads=True,
        pod_exec=True,
        escalates=True,
        wildcard=True,
        bindings=("ClusterRoleBinding/admins",),
    )


def test_cluster_wide_star_rule_is_cluster_admin():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("god", ADMIN_RULES)],
        cluster_role_bindings=[cluster_role_binding("gods", "god", SA)],
    )
    assert _rights(api).cluster_admin


@pytest.mark.parametrize("group", ["system:serviceaccounts", "system:serviceaccounts:web", "system:authenticated"])
def test_group_subjects_apply(group):
    api = FakeKubeApi(
        cluster_roles=[cluster_role("reader", SECRET_READER)],
        cluster_role_bindings=[cluster_role_binding("everyone", "reader", [("Group", group, None)])],
    )
    rights = _rights(api)
    assert rights.reads_secrets and rights.reads_secrets_scope == "cluster"
    assert rights.bindings == ("ClusterRoleBinding/everyone",)


def test_other_subjects_do_not_apply():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("reader", SECRET_READER)],
        cluster_role_bindings=[
            cluster_role_binding(
                "others",
                "reader",
                [
                    ("Group", "system:serviceaccounts:ops", None),
                    ("ServiceAccount", "sa", "ops"),
                    ("ServiceAccount", "other", "web"),
                    ("ServiceAccount", "sa", None),  # no namespace never matches
                    ("User", "sa", None),
                    ("User", "system:serviceaccount:ops:sa", None),
                    ("User", "system:serviceaccount:web:other", None),
                ],
            )
        ],
    )
    rights = _rights(api)
    assert rights == Rights(status="ok")


def test_serviceaccount_username_as_user_subject_applies():
    api = FakeKubeApi(
        roles={"web": [role("reader", "web", SECRET_READER)]},
        role_bindings={
            "web": [role_binding("read", "web", "Role", "reader", [("User", "system:serviceaccount:web:sa", None)])]
        },
    )
    rights = _rights(api)
    assert rights.reads_secrets and rights.reads_secrets_scope == ("web",)
    assert rights.bindings == ("RoleBinding/web/read",)


def test_rolebinding_to_clusterrole_is_namespaced():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("reader", SECRET_READER)],
        role_bindings={"web": [role_binding("read", "web", "ClusterRole", "reader", SA)]},
    )
    rights = _rights(api)
    assert rights.reads_secrets and rights.reads_secrets_scope == ("web",)
    assert not rights.cluster_admin
    assert rights.bindings == ("RoleBinding/web/read",)


def test_rolebinding_to_cluster_admin_is_not_cluster_admin():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("cluster-admin", ADMIN_RULES)],
        role_bindings={"web": [role_binding("admin", "web", "ClusterRole", "cluster-admin", SA)]},
    )
    rights = _rights(api)
    assert not rights.cluster_admin
    assert rights.wildcard and rights.reads_secrets and rights.escalates
    assert rights.reads_secrets_scope == ("web",)


def test_rolebinding_to_unresolved_cluster_admin_sets_namespaced_flags():
    api = FakeKubeApi(
        forbidden_resources={("clusterroles", "*")},
        role_bindings={"web": [role_binding("admin", "web", "ClusterRole", "cluster-admin", SA)]},
    )
    index, status = RbacIndex.load(api, ["web"])
    rights = index.rights("web", "sa")
    assert status == "partial"
    assert rights == Rights(
        status="partial",
        reads_secrets=True,
        reads_secrets_scope=("web",),
        creates_workloads=True,
        pod_exec=True,
        escalates=True,
        wildcard=True,
        bindings=("RoleBinding/web/admin",),
    )


def test_secret_read_in_another_namespace_counts():
    api = FakeKubeApi(
        roles={"ops": [role("reader", "ops", SECRET_READER)]},
        role_bindings={"ops": [role_binding("read", "ops", "Role", "reader", SA)]},
    )
    rights = _rights(api)
    assert rights.reads_secrets and rights.reads_secrets_scope == ("ops",)
    assert rights.bindings == ("RoleBinding/ops/read",)


def test_secret_scope_is_sorted_namespaces():
    api = FakeKubeApi(
        cluster_roles=[cluster_role("reader", SECRET_READER)],
        role_bindings={
            "web": [role_binding("read", "web", "ClusterRole", "reader", SA)],
            "ops": [role_binding("read", "ops", "ClusterRole", "reader", SA)],
        },
    )
    rights = _rights(api)
    assert rights.reads_secrets_scope == ("ops", "web")
    assert rights.bindings == ("RoleBinding/ops/read", "RoleBinding/web/read")


def test_secret_read_needs_core_api_group():
    api = FakeKubeApi(
        roles={"web": [role("reader", "web", [(["example.com"], ["secrets"], ["get"], None)])]},
        role_bindings={"web": [role_binding("read", "web", "Role", "reader", SA)]},
    )
    assert not _rights(api).reads_secrets


def test_resource_names_still_count():
    api = FakeKubeApi(
        roles={"web": [role("reader", "web", [([""], ["secrets"], ["get"], ["one-secret"])])]},
        role_bindings={"web": [role_binding("read", "web", "Role", "reader", SA)]},
    )
    rights = _rights(api)
    assert rights.reads_secrets and rights.reads_secrets_scope == ("web",)


def test_creates_workloads_ignores_api_group():
    api = FakeKubeApi(
        roles={"web": [role("deployer", "web", [(["apps"], ["deployments"], ["create"], None)])]},
        role_bindings={"web": [role_binding("deploy", "web", "Role", "deployer", SA)]},
    )
    rights = _rights(api)
    assert rights.creates_workloads and not rights.wildcard


@pytest.mark.parametrize(
    ("rules", "pod_exec", "escalates"),
    [
        ([([""], ["pods/exec"], ["create"], None)], True, False),
        ([([""], ["pods/attach"], ["get"], None)], True, False),
        ([([""], ["pods/*"], ["create"], None)], True, False),
        ([([""], ["*/exec"], ["create"], None)], True, False),
        ([([""], ["pods"], ["create"], None)], False, False),
        ([(["rbac.authorization.k8s.io"], ["clusterroles"], ["bind"], None)], False, True),
        ([(["rbac.authorization.k8s.io"], ["rolebindings"], ["patch"], None)], False, True),
        ([([""], ["users"], ["impersonate"], None)], False, True),
        ([(["rbac.authorization.k8s.io"], ["roles"], ["get"], None)], False, False),
        ([([""], ["pods/exec"], ["Create"], None)], False, False),  # verbs match case-sensitively
    ],
)
def test_pod_exec_and_escalation_flags(rules, pod_exec, escalates):
    api = FakeKubeApi(
        roles={"web": [role("r", "web", rules)]},
        role_bindings={"web": [role_binding("b", "web", "Role", "r", SA)]},
    )
    rights = _rights(api)
    assert (rights.pod_exec, rights.escalates) == (pod_exec, escalates)


@pytest.mark.parametrize(
    ("rule", "wildcard"),
    [
        (([""], ["*"], ["get"], None), True),
        (([""], ["configmaps"], ["*"], None), True),
        ((["*"], ["configmaps"], ["get"], None), False),
        (([""], ["configmaps"], ["get"], None), False),
    ],
)
def test_wildcard_flag(rule, wildcard):
    api = FakeKubeApi(
        roles={"web": [role("r", "web", [rule])]},
        role_bindings={"web": [role_binding("b", "web", "Role", "r", SA)]},
    )
    rights = _rights(api)
    assert rights.wildcard == wildcard
    assert not rights.cluster_admin


def test_star_resource_covers_subresources():
    api = FakeKubeApi(
        roles={"web": [role("r", "web", [([""], ["*"], ["create"], None)])]},
        role_bindings={"web": [role_binding("b", "web", "Role", "r", SA)]},
    )
    rights = _rights(api)
    assert rights.pod_exec and rights.creates_workloads and rights.escalates


def test_non_resource_rule_counts_for_nothing():
    metrics = cluster_role("metrics")
    metrics.rules = [V1PolicyRule(non_resource_urls=["*"], verbs=["*"])]
    api = FakeKubeApi(cluster_roles=[metrics], cluster_role_bindings=[cluster_role_binding("m", "metrics", SA)])
    assert _rights(api) == Rights(status="ok", bindings=("ClusterRoleBinding/m",))


def test_no_bindings_full_view_is_ok_and_clean():
    index, status = RbacIndex.load(FakeKubeApi(), ["web"])
    assert status == "ok"
    assert index.rights("web", "sa") == Rights(status="ok")


def test_unresolved_ref_in_full_view_is_partial():
    api = FakeKubeApi(role_bindings={"web": [role_binding("b", "web", "Role", "gone", SA)]})
    index, status = RbacIndex.load(api, ["web"])
    assert status == "ok"
    rights = index.rights("web", "sa")
    assert rights.status == "partial"
    assert rights.bindings == ("RoleBinding/web/b",)


def test_cluster_lists_forbidden_falls_back_per_namespace():
    api = FakeKubeApi(
        forbidden_resources=ALL_CLUSTER_WIDE,
        roles={"web": [role("execer", "web", [([""], ["pods/exec"], ["create"], None)])]},
        role_bindings={"web": [role_binding("exec", "web", "Role", "execer", SA)]},
    )
    index, status = RbacIndex.load(api, ["web"])
    rights = index.rights("web", "sa")
    assert status == "partial"
    assert rights.status == "partial"
    assert rights.pod_exec
    assert rights.bindings == ("RoleBinding/web/exec",)


def test_fallback_keeps_the_cluster_lists_that_succeeded():
    api = FakeKubeApi(
        forbidden_resources={("roles", "*"), ("rolebindings", "*")},
        cluster_roles=[cluster_role("reader", SECRET_READER)],
        cluster_role_bindings=[cluster_role_binding("everyone", "reader", SA)],
        role_bindings={"web": [role_binding("read", "web", "ClusterRole", "reader", SA)]},
    )
    index, status = RbacIndex.load(api, ["web", "ops"])
    rights = index.rights("web", "sa")
    assert status == "partial"
    assert rights.reads_secrets_scope == "cluster"
    assert rights.bindings == ("ClusterRoleBinding/everyone", "RoleBinding/web/read")
    assert sorted(api.calls) == sorted(
        [
            "list_cluster_roles",
            "list_cluster_role_bindings",
            "list_roles",
            "list_role_bindings",
            "list_roles",
            "list_roles",
            "list_role_bindings",
            "list_role_bindings",
        ]
    )


def test_each_list_called_once_with_full_view():
    api = FakeKubeApi()
    index, _ = RbacIndex.load(api, ["web", "ops"])
    index.rights("web", "sa")
    index.rights("ops", "sa")
    assert sorted(api.calls) == ["list_cluster_role_bindings", "list_cluster_roles", "list_role_bindings", "list_roles"]


def test_nothing_listable_is_unknown():
    api = FakeKubeApi(forbidden_resources=ALL_CLUSTER_WIDE | {("roles", "web"), ("rolebindings", "web")})
    index, status = RbacIndex.load(api, ["web"])
    assert status == "forbidden"
    assert index.rights("web", "sa").status == "unknown"


def test_server_error_is_error_not_forbidden():
    # The fake answers 404 for methods in ``missing``: any non-403 ApiException stands for a server error here.
    api = FakeKubeApi(missing={"list_cluster_roles", "list_cluster_role_bindings", "list_roles", "list_role_bindings"})
    index, status = RbacIndex.load(api, ["web"])
    assert status == "error"
    assert index.rights("web", "sa").status == "unknown"


def test_transport_error_is_error_not_an_exception():
    api = FakeKubeApi()

    def reset(*_args):
        raise ProtocolError("Connection aborted.", ConnectionResetError())

    for method in ("list_cluster_roles", "list_cluster_role_bindings", "list_roles", "list_role_bindings"):
        setattr(api, method, reset)
    index, status = RbacIndex.load(api, ["web"])
    assert status == "error"
    assert index.rights("web", "sa").status == "unknown"


def test_server_error_with_something_read_is_partial():
    api = FakeKubeApi(missing={"list_cluster_roles"})
    _, status = RbacIndex.load(api, ["web"])
    assert status == "partial"


def test_off_index():
    assert RbacIndex.off().rights("web", "sa") == Rights(status="off")
