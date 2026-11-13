import pytest
from fakes import FakeKubeApi, cronjob, deployment, namespace, node, pod

from kubedelos.config import Settings
from kubedelos.kube.inventory import collect, parse_image_id
from kubedelos.models import ImageRef

DIGEST = "sha256:" + "a" * 8
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
            "docker-pullable://nginx@sha256:abc",
            ImageRef(ref="docker.io/library/nginx@sha256:abc", repo="docker.io/library/nginx", digest="sha256:abc"),
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
        ("ghcr.io/x/y:1", "docker://ghcr.io/x/y@sha256:abc", "ghcr.io/x/y@sha256:abc", "1"),
        ("nginx@sha256:abc", "", "docker.io/library/nginx@sha256:abc", None),
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
    assert warnings == ["skipped namespace secret: forbidden"]


def test_inventory_namespace_list_forbidden_with_explicit_namespaces():
    api = FakeKubeApi(pods={"a": [pod("p", "a")]}, namespaces_forbidden=True)
    items, warnings = collect(api, Settings(namespaces=["a"]))
    assert len(items) == 1
    assert items[0].workloads[0].owner is None
    assert len(warnings) == 1
    assert "owner info unavailable" in warnings[0]


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
    assert warnings == ["skipped cronjobs in namespace d: forbidden"]


def test_inventory_missing_selected_namespace_warns():
    api = FakeKubeApi(namespaces=[namespace("a")], pods={"a": [pod("p", "a")]})
    items, warnings = collect(api, Settings(namespaces=["a", "ghost"]))
    assert len(items) == 1
    assert warnings == ["namespace ghost not found"]


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
