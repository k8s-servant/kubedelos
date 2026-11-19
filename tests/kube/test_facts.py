import pytest
from kubernetes.client import (
    V1Capabilities,
    V1ConfigMapEnvSource,
    V1Container,
    V1EnvFromSource,
    V1EnvVar,
    V1EnvVarSource,
    V1HostPathVolumeSource,
    V1LabelSelector,
    V1LabelSelectorRequirement,
    V1PodSecurityContext,
    V1PodSpec,
    V1ProjectedVolumeSource,
    V1SecretEnvSource,
    V1SecretKeySelector,
    V1SecretProjection,
    V1SecretVolumeSource,
    V1SecurityContext,
    V1Volume,
    V1VolumeMount,
    V1VolumeProjection,
)

from kubedelos.kube.facts import INTERNAL_LB_ANNOTATIONS, exposure, merge, network, pod_security, selector_matches
from kubedelos.models import ExposedService, Exposure, HostPath, Network, PodSecurity, Rights, WorkloadFacts
from tests.kube.fakes import httproute, ingress, network_policy, service


def _spec(containers=None, **kw) -> V1PodSpec:
    return V1PodSpec(containers=containers or [V1Container(name="app", image="x")], **kw)


def _ps(spec=None, container=None, sa=None) -> PodSecurity:
    spec = spec or _spec()
    return pod_security(spec, container or spec.containers[0], sa)


def test_container_context_overrides_pod_run_as_user():
    c = V1Container(name="app", image="x", security_context=V1SecurityContext(run_as_user=1000))
    spec = _spec([c], security_context=V1PodSecurityContext(run_as_user=0))
    assert _ps(spec, c).runs_as_root is False


def test_pod_run_as_user_zero_is_root():
    spec = _spec(security_context=V1PodSecurityContext(run_as_user=0))
    assert _ps(spec).runs_as_root is True


def test_runs_as_root_unknown_when_nothing_says():
    assert _ps().runs_as_root is None


def test_run_as_non_root_means_not_root():
    spec = _spec(security_context=V1PodSecurityContext(run_as_non_root=True))
    assert _ps(spec).runs_as_root is False


def test_privileged_implies_privilege_escalation():
    c = V1Container(
        name="app", image="x", security_context=V1SecurityContext(privileged=True, allow_privilege_escalation=False)
    )
    p = _ps(_spec([c]), c)
    assert p.privileged is True
    assert p.allow_privilege_escalation is True


def test_defaults_when_security_context_unset():
    p = _ps()
    assert (p.privileged, p.allow_privilege_escalation, p.read_only_root_fs) == (False, True, False)
    assert (p.host_network, p.host_pid, p.host_ipc) == (False, False, False)
    assert p.service_account == "default"


def test_explicit_hardening_and_capabilities():
    c = V1Container(
        name="app",
        image="x",
        security_context=V1SecurityContext(
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=V1Capabilities(add=["SYS_ADMIN", "NET_RAW"]),
        ),
    )
    spec = _spec([c], host_network=True, host_pid=True, host_ipc=True, service_account_name="sa1")
    p = _ps(spec, c)
    assert (p.allow_privilege_escalation, p.read_only_root_fs) == (False, True)
    assert p.added_capabilities == ("NET_RAW", "SYS_ADMIN")
    assert (p.host_network, p.host_pid, p.host_ipc) == (True, True, True)
    assert p.service_account == "sa1"


def test_host_path_only_when_this_container_mounts_it():
    a = V1Container(
        name="a",
        image="x",
        volume_mounts=[
            V1VolumeMount(name="z", mount_path="/z", read_only=True),
            V1VolumeMount(name="d", mount_path="/d"),
            V1VolumeMount(name="e", mount_path="/e"),
        ],
    )
    b = V1Container(name="b", image="x")
    vols = [
        V1Volume(name="z", host_path=V1HostPathVolumeSource(path="/var/z")),
        V1Volume(name="d", host_path=V1HostPathVolumeSource(path="/var/a")),
        V1Volume(name="e", empty_dir={}),
        V1Volume(name="unmounted", host_path=V1HostPathVolumeSource(path="/etc")),
    ]
    spec = _spec([a, b], volumes=vols)
    assert _ps(spec, a).host_path_volumes == (
        HostPath(path="/var/a", read_only=False),
        HostPath(path="/var/z", read_only=True),
    )
    assert _ps(spec, b).host_path_volumes == ()


def test_secret_refs_from_volumes_env_envfrom_and_projected():
    c = V1Container(
        name="app",
        image="x",
        volume_mounts=[V1VolumeMount(name="v1", mount_path="/1"), V1VolumeMount(name="v2", mount_path="/2")],
        env=[
            V1EnvVar(
                name="E",
                value_from=V1EnvVarSource(secret_key_ref=V1SecretKeySelector(name="b", key="k")),
            ),
            V1EnvVar(name="plain", value="x"),
        ],
        env_from=[
            V1EnvFromSource(secret_ref=V1SecretEnvSource(name="c")),
            V1EnvFromSource(config_map_ref=V1ConfigMapEnvSource(name="cm")),
        ],
    )
    vols = [
        V1Volume(name="v1", secret=V1SecretVolumeSource(secret_name="a")),
        V1Volume(
            name="v2",
            projected=V1ProjectedVolumeSource(
                sources=[V1VolumeProjection(secret=V1SecretProjection(name="d")), V1VolumeProjection()]
            ),
        ),
        V1Volume(name="v3", secret=V1SecretVolumeSource(secret_name="not-mounted")),
    ]
    assert _ps(_spec([c], volumes=vols), c).secret_refs == ("a", "b", "c", "d")


@pytest.mark.parametrize(
    ("pod_value", "sa", "expected"),
    [
        (False, {"s": True}, False),
        (False, {"s": None}, False),
        (False, {}, False),
        (True, {"s": False}, True),
        (None, {"s": False}, False),
        (None, {"s": True}, True),
        (None, {"s": None}, True),
        (None, {}, True),
        (None, None, None),
        (True, None, True),
    ],
)
def test_automount(pod_value, sa, expected):
    spec = _spec(service_account_name="s", automount_service_account_token=pod_value)
    assert _ps(spec, sa=sa).automount_token is expected


def _facts(root=None, level="none", services=(), policies=(), rights=None, **pod_kw) -> WorkloadFacts:
    pod = dict(
        privileged=False,
        allow_privilege_escalation=False,
        runs_as_root=root,
        read_only_root_fs=True,
        host_network=False,
        host_pid=False,
        host_ipc=False,
        service_account="default",
        automount_token=None,
    )
    pod.update(pod_kw)
    return WorkloadFacts(
        pod=PodSecurity(**pod),
        exposure=Exposure(level=level, services=tuple(services)),
        network=Network(ingress_isolated=None, egress_isolated=None, ingress_policies=tuple(policies)),
        rights=rights or Rights(status="off"),
    )


def test_merge_takes_the_riskier_value():
    assert merge(_facts(root=True), _facts(root=False)).pod.runs_as_root is True
    assert merge(_facts(root=None), _facts(root=False)).pod.runs_as_root is None
    assert merge(_facts(root=False), _facts(root=False)).pod.runs_as_root is False
    m = merge(_facts(level="cluster", policies=("b",)), _facts(level="external", policies=("a", "b")))
    assert m.exposure.level == "external"
    assert m.network.ingress_policies == ("a", "b")


def test_merge_pod_bools_and_tuples():
    a = _facts(privileged=True, added_capabilities=("B",), secret_refs=("s1",), read_only_root_fs=True)
    b = _facts(added_capabilities=("A",), secret_refs=("s1", "s0"), read_only_root_fs=False)
    p = merge(a, b).pod
    assert p.privileged is True
    assert p.read_only_root_fs is False
    assert p.added_capabilities == ("A", "B")
    assert p.secret_refs == ("s0", "s1")


def test_merge_host_paths_read_only_only_if_both():
    a = _facts(host_path_volumes=(HostPath(path="/a", read_only=True), HostPath(path="/b", read_only=True)))
    b = _facts(host_path_volumes=(HostPath(path="/a", read_only=False), HostPath(path="/c", read_only=True)))
    assert merge(a, b).pod.host_path_volumes == (
        HostPath(path="/a", read_only=False),
        HostPath(path="/b", read_only=True),
        HostPath(path="/c", read_only=True),
    )


def test_merge_services_dedupe_by_name_keep_riskier_type():
    a = _facts(services=[ExposedService(name="s", type="ClusterIP", internal_lb=True)])
    b = _facts(
        services=[
            ExposedService(name="s", type="LoadBalancer", internal_lb=True),
            ExposedService(name="a", type="NodePort"),
        ]
    )
    assert merge(a, b).exposure.services == (
        ExposedService(name="a", type="NodePort"),
        ExposedService(name="s", type="LoadBalancer", internal_lb=True),
    )
    c = _facts(services=[ExposedService(name="s", type="LoadBalancer", internal_lb=False)])
    assert merge(a, c).exposure.services[0].internal_lb is False


def test_merge_rights():
    a = _facts(rights=Rights(status="ok", reads_secrets=True, reads_secrets_scope=("ns1",), bindings=("x",)))
    b = _facts(rights=Rights(status="partial", pod_exec=True, reads_secrets_scope=("ns2",), bindings=("y",)))
    r = merge(a, b).rights
    assert (r.status, r.reads_secrets, r.pod_exec, r.cluster_admin) == ("partial", True, True, False)
    assert r.reads_secrets_scope == ("ns1", "ns2")
    assert r.bindings == ("x", "y")
    c = _facts(rights=Rights(status="unknown", reads_secrets_scope="cluster"))
    assert merge(a, c).rights.reads_secrets_scope == "cluster"
    assert merge(a, c).rights.status == "unknown"
    assert merge(_facts(), _facts(rights=Rights(status="ok"))).rights.status == "ok"
    assert merge(_facts(), _facts()).rights.reads_secrets_scope is None


def test_merge_network_isolation_riskier_is_not_isolated():
    a = _facts().model_copy(update={"network": Network(ingress_isolated=True, egress_isolated=None)})
    b = _facts().model_copy(update={"network": Network(ingress_isolated=False, egress_isolated=True)})
    n = merge(a, b).network
    assert (n.ingress_isolated, n.egress_isolated) == (False, None)


# --- exposure and network policies ---

ADMIN = {"app": "web"}


def _exposure(services, ingresses=None, routes=None, labels=None, ns="default"):
    return exposure(labels if labels is not None else ADMIN, services, ingresses, routes)


def test_selectorless_and_externalname_services_match_nothing():
    services = [
        service("nosel", "default", None, type="NodePort"),
        service("empty", "default", {}, type="LoadBalancer"),
        service("ext", "default", ADMIN, type="ExternalName"),
    ]
    assert _exposure(services) == Exposure(level="none")


def test_clusterip_is_cluster_nodeport_is_external():
    cluster = _exposure([service("b", "default", ADMIN), service("a", "default", {"app": "other"})])
    assert cluster.level == "cluster"
    assert cluster.services == (ExposedService(name="b", type="ClusterIP"),)
    external = _exposure([service("np", "default", ADMIN, type="NodePort")])
    assert external.level == "external"


def test_selector_must_be_subset_of_pod_labels():
    assert _exposure([service("s", "default", {"app": "web", "tier": "x"})]).level == "none"
    assert _exposure([service("s", "default", ADMIN)], labels={"app": "web", "tier": "x"}).level == "cluster"


def test_service_type_defaults_to_clusterip_and_services_are_sorted():
    unset = service("z", "default", ADMIN)
    unset.spec.type = None
    result = _exposure([unset, service("a", "default", ADMIN)])
    assert [(s.name, s.type) for s in result.services] == [("a", "ClusterIP"), ("z", "ClusterIP")]


def test_external_ips_make_external_and_are_unioned():
    result = _exposure(
        [
            service("a", "default", ADMIN, external_ips=["9.9.9.9", "1.1.1.1"]),
            service("b", "default", ADMIN, external_ips=["1.1.1.1"]),
        ]
    )
    assert result.level == "external"
    assert result.external_ips == ("1.1.1.1", "9.9.9.9")


def test_public_load_balancer_is_external():
    result = _exposure([service("lb", "default", ADMIN, type="LoadBalancer")])
    assert result.level == "external"
    assert result.services == (ExposedService(name="lb", type="LoadBalancer", internal_lb=False),)


@pytest.mark.parametrize("key, value", sorted(INTERNAL_LB_ANNOTATIONS.items()))
def test_internal_load_balancer_is_cluster(key, value):
    lb = service("lb", "default", ADMIN, type="LoadBalancer", annotations={key: value.upper()})
    result = _exposure([lb])
    assert result.level == "cluster"
    assert result.services == (ExposedService(name="lb", type="LoadBalancer", internal_lb=True),)


def test_ingress_and_httproute_backends_make_external_and_collect_hosts():
    services = [service("web", "default", ADMIN)]
    ingresses = [
        ingress("i1", "default", rules=[("b.example.com", "web"), ("x.example.com", "other")]),
        ingress("i2", "default", default_backend="web"),
        ingress("i3", "default", rules=[("skip.example.com", "other")]),
    ]
    routes = [
        httproute("r", "default", ["a.example.com"], [("web",)]),
        httproute("r2", "default", ["no.example.com"], [("other",)]),
    ]
    result = _exposure(services, ingresses, routes)
    assert result.level == "external"
    assert result.hosts == ("a.example.com", "b.example.com", "x.example.com")


def test_ingress_to_unmatched_service_stays_cluster():
    result = _exposure(
        [service("web", "default", ADMIN)], [ingress("i", "default", rules=[("h.example.com", "other")])]
    )
    assert result == Exposure(level="cluster", services=(ExposedService(name="web", type="ClusterIP"),))


def test_httproute_to_other_kind_is_ignored():
    routes = [httproute("r", "default", ["a.example.com"], [("web", "ServiceImport", "multicluster.x-k8s.io")])]
    assert _exposure([service("web", "default", ADMIN)], None, routes).level == "cluster"


def test_httproute_backend_with_omitted_kind_and_group_is_a_service():
    ref = {"name": "web"}
    route = {
        "metadata": {"namespace": "default"},
        "spec": {"hostnames": ["a.example.com"], "rules": [{"backendRefs": [ref]}]},
    }
    assert httproute("r", "default", backends=[("web", None, None)])["spec"]["rules"][0]["backendRefs"] == [ref]
    result = _exposure([service("web", "default", ADMIN)], None, [route])
    assert result.level == "external"
    assert result.hosts == ("a.example.com",)


def test_httproute_backend_in_another_namespace_is_ignored():
    routes = [httproute("r", "default", ["a.example.com"], [("web", "Service", "", "other")])]
    assert _exposure([service("web", "default", ADMIN)], None, routes).level == "cluster"
    same = [httproute("r", "default", ["a.example.com"], [("web", "Service", "", "default")])]
    assert _exposure([service("web", "default", ADMIN)], None, same).level == "external"


def test_httproute_without_rules_or_hostnames_is_read_defensively():
    route = {"metadata": {"namespace": "default"}, "spec": {}}
    assert _exposure([service("web", "default", ADMIN)], None, [route]).level == "cluster"


def test_services_unlistable_is_unknown():
    assert _exposure(None, [ingress("i", "default", default_backend="web")]).level == "unknown"


def test_no_services_is_none():
    assert _exposure([]) == Exposure(level="none")


def _sel(labels=None, expressions=None) -> V1LabelSelector:
    return V1LabelSelector(
        match_labels=labels,
        match_expressions=[V1LabelSelectorRequirement(key=k, operator=o, values=v) for k, o, v in expressions or []]
        or None,
    )


def test_empty_pod_selector_selects_everything():
    assert selector_matches(V1LabelSelector(), {}) is True
    assert selector_matches(V1LabelSelector(), {"a": "b"}) is True
    assert selector_matches(None, {"a": "b"}) is True
    policy = network_policy("p", "default")
    assert network(ADMIN, [policy]).ingress_isolated is True


@pytest.mark.parametrize(
    "op, values, labels, expected",
    [
        ("In", ["a", "b"], {"k": "a"}, True),
        ("In", ["a", "b"], {"k": "c"}, False),
        ("In", ["a"], {}, False),
        ("NotIn", ["a"], {"k": "c"}, True),
        ("NotIn", ["a"], {"k": "a"}, False),
        ("NotIn", ["a"], {}, True),
        ("Exists", None, {"k": "x"}, True),
        ("Exists", None, {}, False),
        ("DoesNotExist", None, {}, True),
        ("DoesNotExist", None, {"k": "x"}, False),
    ],
)
def test_match_expressions_operators(op, values, labels, expected):
    assert selector_matches(_sel(expressions=[("k", op, values)]), labels) is expected


def test_match_labels_and_expressions_are_anded():
    selector = _sel({"a": "1"}, [("k", "Exists", None)])
    assert selector_matches(selector, {"a": "1", "k": "v"}) is True
    assert selector_matches(selector, {"a": "1"}) is False
    assert selector_matches(selector, {"a": "2", "k": "v"}) is False


def test_policy_types_default_from_rules():
    default = network_policy("default-types", "default", ADMIN)
    with_egress = network_policy("with-egress", "default", ADMIN, egress=True)
    explicit = network_policy("explicit", "default", ADMIN, policy_types=["Egress"])
    other = network_policy("other", "default", {"app": "x"}, policy_types=["Ingress", "Egress"])
    result = network(ADMIN, [default, with_egress, explicit, other])
    assert result == Network(
        ingress_isolated=True,
        egress_isolated=True,
        ingress_policies=("default-types", "with-egress"),
        egress_policies=("explicit", "with-egress"),
    )


def test_no_selecting_policy_is_not_isolated():
    result = network(ADMIN, [network_policy("o", "default", {"app": "x"})])
    assert result == Network(ingress_isolated=False, egress_isolated=False)
    assert network(ADMIN, []) == Network(ingress_isolated=False, egress_isolated=False)


def test_policies_unlistable_is_unknown_isolation():
    assert network(ADMIN, None) == Network(ingress_isolated=None, egress_isolated=None)
