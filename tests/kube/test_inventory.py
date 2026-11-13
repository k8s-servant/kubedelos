import pytest
from fakes import FakeKubeApi, cronjob, deployment, namespace, node, pod

from kubedelos.config import Settings
from kubedelos.kube.inventory import InventoryWarning, collect, parse_image_id
from kubedelos.models import ImageRef

DIGEST = "sha256:" + "a" * 64
ID = f"docker-pullable://nginx@{DIGEST}"


def test_inventory_dedupes_by_digest():
    api = FakeKubeApi(
        namespaces=[namespace("web")],
        pods={
            "web": [
                pod("p1", "web", image_id=ID, owner=("ReplicaSet", "front-5d9"), labels={"pod-template-hash": "5d9"}),
                pod(
                    "p2",
                    "web",
                    image="nginx:1.26",
                    image_id=ID,
                    owner=("ReplicaSet", "front-5d9"),
                    labels={"pod-template-hash": "5d9"},
                ),
                pod("p3", "web", image_id=ID),
            ]
        },
    )
    items, warnings = collect(api, Settings())
    assert warnings == []
    assert len(items) == 1
    assert items[0].image.digest == DIGEST
    # p1 and p2 are the same Deployment workload; the bare pod is a second one
    assert [(w.kind, w.name) for w in items[0].workloads] == [("Deployment", "front"), ("Pod", "p3")]


def test_inventory_includes_init_ephemeral_and_templates():
    api = FakeKubeApi(
        namespaces=[namespace("ops")],
        pods={
            "ops": [pod("p", "ops", image="app:1", init=("init", "busybox:1", ""), ephemeral=("dbg", "alpine:3", ""))]
        },
        deployments={"ops": [deployment("idle", "ops", "idle:1", 0), deployment("busy", "ops", "busy:1", 2)]},
        cronjobs={"ops": [cronjob("nightly", "ops", "job:1")]},
    )
    items, _ = collect(api, Settings())
    refs = {i.image.ref: i.workloads[0] for i in items}
    assert set(refs) == {
        "docker.io/library/app:1",
        "docker.io/library/busybox:1",
        "docker.io/library/alpine:3",
        "docker.io/library/idle:1",
        "docker.io/library/job:1",
    }
    assert (refs["docker.io/library/idle:1"].kind, refs["docker.io/library/idle:1"].name) == ("Deployment", "idle")
    assert (refs["docker.io/library/job:1"].kind, refs["docker.io/library/job:1"].name) == ("CronJob", "nightly")
    assert refs["docker.io/library/alpine:3"].container == "dbg"


@pytest.mark.parametrize(
    ("image_id", "expected"),
    [
        ("", ImageRef(ref="docker.io/library/nginx:latest", repo="docker.io/library/nginx", tag="latest")),
        (
            "sha256:abc",
            ImageRef(ref="docker.io/library/nginx:latest", repo="docker.io/library/nginx", tag="latest"),
        ),
        (
            "docker-pullable://nginx@sha256:" + "c" * 64,
            ImageRef(
                ref="docker.io/library/nginx@sha256:" + "c" * 64,
                repo="docker.io/library/nginx",
                digest="sha256:" + "c" * 64,
            ),
        ),
        ("nginx", ImageRef(ref="docker.io/library/nginx:latest", repo="docker.io/library/nginx", tag="latest")),
    ],
)
def test_inventory_imageid_variants(image_id, expected):
    assert parse_image_id("nginx", image_id) == expected


@pytest.mark.parametrize(
    ("image", "image_id", "ref", "tag"),
    [
        ("bitnami/redis", "", "docker.io/bitnami/redis:latest", "latest"),
        ("ghcr.io/x/y:1", "", "ghcr.io/x/y:1", "1"),
        ("localhost:5000/app", "", "localhost:5000/app:latest", "latest"),
        ("ghcr.io/x/y:1", "docker://ghcr.io/x/y@sha256:" + "c" * 64, "ghcr.io/x/y@sha256:" + "c" * 64, "1"),
        ("nginx@sha256:" + "c" * 64, "", "docker.io/library/nginx@sha256:" + "c" * 64, None),
        ("MyReg.Example.com/app:1", "", "myreg.example.com/app:1", "1"),
        (
            "nginx:1.19",
            "docker.io/library/nginx@sha256:" + "c" * 64,
            "docker.io/library/nginx@sha256:" + "c" * 64,
            "1.19",
        ),
        (
            "nginx:1.19",
            "docker-pullable://index.docker.io/library/nginx@sha256:" + "c" * 64,
            "docker.io/library/nginx@sha256:" + "c" * 64,
            "1.19",
        ),
    ],
)
def test_parse_image_id_registries_and_tags(image, image_id, ref, tag):
    parsed = parse_image_id(image, image_id)
    assert (parsed.ref, parsed.tag) == (ref, tag)


def test_inventory_forbidden_namespace_skipped():
    api = FakeKubeApi(
        namespaces=[namespace("ok"), namespace("secret")],
        pods={"ok": [pod("p", "ok")], "secret": [pod("q", "secret")]},
        forbidden={"secret"},
    )
    items, warnings = collect(api, Settings())
    assert [w.namespace for i in items for w in i.workloads] == ["ok"]
    assert warnings == [InventoryWarning("skipped namespace secret: forbidden", coverage=True)]


def test_inventory_namespace_list_forbidden_with_explicit_namespaces():
    api = FakeKubeApi(pods={"a": [pod("p", "a")]}, namespaces_forbidden=True)
    items, warnings = collect(api, Settings(namespaces=["a"]))
    assert len(items) == 1
    assert items[0].workloads[0].owner is None
    assert len(warnings) == 1
    assert "owner info unavailable" in warnings[0].text
    assert warnings[0].coverage is False  # every selected namespace is still scanned


def test_inventory_namespace_list_forbidden_without_selection_raises():
    from kubernetes.client.rest import ApiException

    with pytest.raises(ApiException):
        collect(FakeKubeApi(namespaces_forbidden=True), Settings())


def test_inventory_namespace_selection_and_exclusion():
    api = FakeKubeApi(
        namespaces=[namespace("a"), namespace("b"), namespace("c")],
        pods={n: [pod("p", n, image=f"{n}:1")] for n in "abc"},
    )
    items, _ = collect(api, Settings(namespaces=["a", "b"], exclude_namespaces=["b"]))
    assert [w.namespace for i in items for w in i.workloads] == ["a"]


def test_inventory_platform_from_node():
    api = FakeKubeApi(
        namespaces=[namespace("d")],
        pods={
            "d": [
                pod("on-arm", "d", image="a:1", node_name="n-arm"),
                pod("no-node", "d", image="b:1"),
            ]
        },
        nodes=[node("n-arm", "arm64"), node("n-amd1", "amd64"), node("n-amd2", "amd64")],
    )
    items, _ = collect(api, Settings())
    assert {i.image.repo: i.platform for i in items} == {
        "docker.io/library/a": "linux/arm64",  # from the pod's own node, the minority arch
        "docker.io/library/b": "linux/amd64",  # most common node arch
    }


def test_inventory_forbidden_resource_skips_only_that_resource():
    api = FakeKubeApi(
        namespaces=[namespace("d")],
        pods={"d": [pod("p", "d")]},
        deployments={"d": [deployment("idle", "d", "idle:1", 0)]},
        cronjobs={"d": [cronjob("nightly", "d", "job:1")]},
        forbidden_resources={("cronjobs", "d")},
    )
    items, warnings = collect(api, Settings())
    assert {i.image.ref for i in items} == {"docker.io/library/nginx:1.25", "docker.io/library/idle:1"}
    assert warnings == [InventoryWarning("skipped cronjobs in namespace d: forbidden", coverage=True)]


def test_inventory_missing_selected_namespace_warns():
    api = FakeKubeApi(namespaces=[namespace("a")], pods={"a": [pod("p", "a")]})
    items, warnings = collect(api, Settings(namespaces=["a", "ghost"]))
    assert len(items) == 1
    assert warnings == [InventoryWarning("namespace ghost not found", coverage=True)]


def test_inventory_platform_defaults_to_amd64_without_nodes():
    api = FakeKubeApi(namespaces=[namespace("d")], pods={"d": [pod("p", "d")]})
    items, _ = collect(api, Settings())
    assert items[0].platform == "linux/amd64"


def test_inventory_job_owner_keeps_kind():
    api = FakeKubeApi(namespaces=[namespace("d")], pods={"d": [pod("p", "d", owner=("Job", "migrate-1"))]})
    items, _ = collect(api, Settings())
    assert (items[0].workloads[0].kind, items[0].workloads[0].name) == ("Job", "migrate-1")


def test_owner_from_namespace_annotation():
    api = FakeKubeApi(
        namespaces=[namespace("pay", {"kubedelos.io/owner-email": "a@x.io"}, {"kubedelos.io/team": "pay"})],
        pods={"pay": [pod("p", "pay")]},
        deployments={"pay": [deployment("idle", "pay", "idle:1", 0)]},
    )
    items, _ = collect(api, Settings())
    assert items
    for item in items:
        for w in item.workloads:
            assert (w.owner, w.team) == ("a@x.io", "pay")


@pytest.mark.parametrize("bad", ["sha256:abc", "sha256:" + "C" * 64, "sha256:" + "c" * 63, "sha256:" + "c" * 65])
def test_parse_image_id_malformed_digest_is_tag_ref(bad):
    parsed = parse_image_id("nginx", f"docker-pullable://nginx@{bad}")
    assert parsed.digest is None and parsed.ref == "docker.io/library/nginx:latest"
    spec = parse_image_id(f"nginx@{bad}", "")
    assert spec.digest is None and spec.ref == "docker.io/library/nginx:latest"


def test_parse_image_id_ignores_local_import_image_id():
    # kind and `ctr import` report a synthetic repo in imageID; its digest does not belong to the spec image
    parsed = parse_image_id("myapp:dev", "docker.io/library/import-2024-01-01@sha256:" + "c" * 64)
    assert parsed == ImageRef(ref="docker.io/library/myapp:dev", repo="docker.io/library/myapp", tag="dev")


def test_parse_image_id_other_repo_falls_back_to_spec_digest():
    spec_digest = "sha256:" + "d" * 64
    parsed = parse_image_id(f"reg.example.com/app@{spec_digest}", "docker.io/library/import-x@sha256:" + "c" * 64)
    assert parsed.ref == f"reg.example.com/app@{spec_digest}" and parsed.digest == spec_digest


def test_inventory_nodes_forbidden_is_informational():
    api = FakeKubeApi(namespaces=[namespace("d")], pods={"d": [pod("p", "d")]}, nodes_forbidden=True)
    items, warnings = collect(api, Settings())
    assert items[0].platform == "linux/amd64"
    assert [(w.text, w.coverage) for w in warnings] == [
        ("cannot list nodes: HTTP 403; assuming a default platform", False)
    ]


def test_inventory_namespace_scoped_identity_has_no_coverage_gaps():
    api = FakeKubeApi(pods={"team": [pod("p", "team")]}, namespaces_forbidden=True, nodes_forbidden=True)
    items, warnings = collect(api, Settings(namespaces=["team"]))
    assert len(items) == 1
    assert len(warnings) == 2
    assert not any(w.coverage for w in warnings)


def test_inventory_platform_uses_node_os():
    api = FakeKubeApi(
        namespaces=[namespace("d")],
        pods={"d": [pod("win", "d", image="win:1", node_name="n-win"), pod("lin", "d", image="lin:1", node_name="n1")]},
        nodes=[node("n-win", "amd64", os="windows"), node("n1", "arm64"), node("n2", "arm64", os="")],
    )
    items, warnings = collect(api, Settings())
    assert warnings == []
    assert {i.image.repo: i.platform for i in items} == {
        "docker.io/library/win": "windows/amd64",  # kept and scanned for its own platform, not skipped
        "docker.io/library/lin": "linux/arm64",
    }


def _refs(items):
    return sorted(i.image.ref for i in items)


def test_namespace_selector_filters_namespaces():
    api = FakeKubeApi(
        namespaces=[namespace("a", labels={"team": "x"}), namespace("b", labels={"team": "y"})],
        pods={"a": [pod("p", "a", image="a:1")], "b": [pod("p", "b", image="b:1")]},
    )
    items, _ = collect(api, Settings(namespace_selector="team=x"))
    assert _refs(items) == ["docker.io/library/a:1"]
    assert ("list_namespaces", "team=x") in api.selectors


def test_selector_passed_to_every_namespaced_list():
    api = FakeKubeApi(
        namespaces=[namespace("a")],
        pods={"a": [pod("web", "a", image="web:1", labels={"app": "web"}), pod("db", "a", image="db:1")]},
    )
    items, _ = collect(api, Settings(selector="app=web"))
    assert _refs(items) == ["docker.io/library/web:1"]
    for method in ("list_pods", "list_deployments", "list_statefulsets", "list_cronjobs"):
        assert (method, "app=web") in api.selectors


def test_namespace_selector_with_forbidden_namespace_list_fails_closed():
    api = FakeKubeApi(namespaces_forbidden=True, pods={"a": [pod("p", "a")]})
    with pytest.raises(RuntimeError, match="--namespace-selector"):
        collect(api, Settings(namespaces=["a"], namespace_selector="team=x"))


def test_named_namespace_outside_selector_warns():
    api = FakeKubeApi(
        namespaces=[namespace("a", labels={"team": "x"}), namespace("b")],
        pods={"a": [pod("p", "a", image="a:1")], "b": [pod("p", "b", image="b:1")]},
    )
    items, warnings = collect(api, Settings(namespaces=["a", "b"], namespace_selector="team=x"))
    assert _refs(items) == ["docker.io/library/a:1"]
    assert InventoryWarning("namespace b does not match --namespace-selector; not scanned", coverage=False) in warnings


def test_invalid_selector_is_a_clear_error():
    api = FakeKubeApi(namespaces=[namespace("a")], pods={"a": [pod("p", "a")]})
    with pytest.raises(ValueError, match=r"invalid label selector 'app in \('"):
        collect(api, Settings(selector="app in ("))


@pytest.mark.parametrize("pattern", ["nginx:*", "library/nginx:*", "docker.io/library/nginx:*"])
def test_exclude_image_matches_any_docker_hub_spelling(pattern):
    api = FakeKubeApi(
        namespaces=[namespace("a")],
        pods={"a": [pod("short", "a", image="nginx:1.19"), pod("long", "a", image="docker.io/library/nginx:1.19")]},
    )
    items, _ = collect(api, Settings(exclude_images=[pattern]))
    assert items == []


def test_exclude_image_keeps_others_and_warns():
    api = FakeKubeApi(
        namespaces=[namespace("a")],
        pods={"a": [pod("pause", "a", image="registry.k8s.io/pause:3.9"), pod("web", "a", image="nginx:1.19")]},
    )
    items, warnings = collect(api, Settings(exclude_images=["registry.k8s.io/*"]))
    assert _refs(items) == ["docker.io/library/nginx:1.19"]
    assert InventoryWarning("excluded 1 image(s) matching --exclude-image", coverage=False) in warnings


def test_exclude_image_digest_only_ref():
    image = f"registry.example/team/app@{DIGEST}"
    api = FakeKubeApi(namespaces=[namespace("a")], pods={"a": [pod("p", "a", image=image)]})
    assert collect(api, Settings(exclude_images=["*:1.19"]))[0] != []
    assert collect(api, Settings(exclude_images=["registry.example/team/*"]))[0] == []


def test_no_exclusion_no_warning():
    api = FakeKubeApi(namespaces=[namespace("a")], pods={"a": [pod("p", "a")]})
    _, warnings = collect(api, Settings())
    assert not any("--exclude-image" in w.text for w in warnings)
