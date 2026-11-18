"""Renders the Helm chart with ``helm template`` and checks the documents it produces.

The chart is the install path of ``kubedelos serve``; these tests pin its hardening, its read-only RBAC and that the
ConfigMap it writes loads as ``Settings``. They skip without ``helm`` unless ``KUBEDELOS_REQUIRE_HELM=1`` (CI sets it).
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from kubedelos.config import Settings

CHART = Path(__file__).resolve().parents[2] / "charts" / "kubedelos"
BASE = {"clusterName": "my-cluster"}

if shutil.which("helm") is None:
    if os.environ.get("KUBEDELOS_REQUIRE_HELM") == "1":
        pytest.fail("helm is required (KUBEDELOS_REQUIRE_HELM=1) but is not on PATH", pytrace=False)
    pytest.skip("helm is not installed", allow_module_level=True)


def _run(values: dict | None, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    values_file = tmp_path / "values.yaml"
    values_file.write_text(yaml.safe_dump(values or {}))
    return subprocess.run(
        ["helm", "template", "t", str(CHART), "-n", "kd", "-f", str(values_file)],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def render(tmp_path):
    def _render(values: dict | None = None) -> list[dict]:
        result = _run({**BASE, **(values or {})}, tmp_path)
        assert result.returncode == 0, result.stderr
        return [doc for doc in yaml.safe_load_all(result.stdout) if doc]

    return _render


@pytest.fixture
def render_error(tmp_path):
    def _render_error(values: dict | None = None) -> str:
        result = _run(values, tmp_path)
        assert result.returncode != 0, "the render was expected to fail"
        return result.stderr

    return _render_error


def kind(docs: list[dict], name: str) -> dict:
    found = [doc for doc in docs if doc["kind"] == name]
    assert len(found) == 1, f"expected one {name}, got {len(found)}"
    return found[0]


def test_missing_cluster_name_fails_to_render(render_error):
    assert "clusterName is required" in render_error({})


def test_deployment_is_one_hardened_replica(render):
    deployment = kind(render(), "Deployment")
    spec = deployment["spec"]
    assert spec["replicas"] == 1
    assert spec["strategy"]["type"] == "Recreate"
    pod = spec["template"]["spec"]
    security = pod["securityContext"]
    assert security["runAsNonRoot"] is True
    assert security["runAsUser"] == 65532
    assert security["fsGroup"] == 65532
    assert security["seccompProfile"]["type"] == "RuntimeDefault"
    assert pod["automountServiceAccountToken"] is True
    assert pod["terminationGracePeriodSeconds"] == 60
    container = pod["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    for probe in ("livenessProbe", "readinessProbe"):
        assert container[probe]["httpGet"] == {"path": "/healthz", "port": "http"}
    mounts = {mount["mountPath"]: mount["name"] for mount in container["volumeMounts"]}
    volumes = {volume["name"]: volume for volume in pod["volumes"]}
    assert "persistentVolumeClaim" in volumes[mounts["/data"]]
    assert "emptyDir" in volumes[mounts["/tmp"]]


def test_replicas_is_not_a_value(render_error):
    assert render_error({**BASE, "replicas": 2})


def test_image_defaults_to_app_version_and_digest_wins(render):
    container = kind(render(), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "ghcr.io/k8s-servant/kubedelos:0.0.0"
    digest = "sha256:" + "a" * 64
    container = kind(render({"image": {"digest": digest}}), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == f"ghcr.io/k8s-servant/kubedelos@{digest}"


def test_service_maps_80_to_8080(render):
    port = kind(render(), "Service")["spec"]["ports"][0]
    assert (port["port"], port["targetPort"]) == (80, "http")
    container = kind(render(), "Deployment")["spec"]["template"]["spec"]["containers"][0]
    assert container["ports"][0] == {"name": "http", "containerPort": 8080, "protocol": "TCP"}


def test_pvc_defaults_and_existing_claim(render):
    docs = render()
    pvc = kind(docs, "PersistentVolumeClaim")
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "10Gi"
    volumes = {v["name"]: v for v in kind(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == pvc["metadata"]["name"]

    docs = render({"persistence": {"existingClaim": "mine"}})
    assert not [doc for doc in docs if doc["kind"] == "PersistentVolumeClaim"]
    volumes = {v["name"]: v for v in kind(docs, "Deployment")["spec"]["template"]["spec"]["volumes"]}
    assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "mine"


def test_clusterrole_is_read_only_and_exact(render):
    rules = kind(render(), "ClusterRole")["rules"]
    actual = {(tuple(r["apiGroups"]), tuple(r["resources"])): set(r["verbs"]) for r in rules}
    assert len(actual) == len(rules)
    assert actual == {
        (("",), ("namespaces", "pods", "nodes")): {"get", "list"},
        (("apps",), ("deployments", "statefulsets")): {"list"},
        (("batch",), ("cronjobs",)): {"list"},
    }
    binding = kind(render(), "ClusterRoleBinding")
    assert binding["subjects"][0]["kind"] == "ServiceAccount"
    assert binding["subjects"][0]["namespace"] == "kd"


def test_configmap_env(render):
    data = kind(render(), "ConfigMap")["data"]
    assert data["KUBEDELOS_CLUSTER_NAME"] == "my-cluster"
    for name in ("NAMESPACE_SELECTOR", "SELECTOR"):
        assert f"KUBEDELOS_{name}" not in data
    assert data["KUBEDELOS_NAMESPACES"] == "[]"
    expected = {
        "KUBEDELOS_SWEEP_ENABLED": "true",
        "KUBEDELOS_SWEEP_SCHEDULE": "0 3 * * *",
        "KUBEDELOS_SWEEP_TIMEZONE": "UTC",
        "KUBEDELOS_RETENTION_DAYS": "180",
        "KUBEDELOS_READ_ONLY": "false",
        "KUBEDELOS_TRUST_PROXY_HEADERS": "false",
        "KUBEDELOS_IDENTITY_HEADER": "X-Auth-Request-Email",
        "KUBEDELOS_SECURE_COOKIES": "true",
        "KUBEDELOS_PARALLELISM": "4",
        "KUBEDELOS_SCAN_TIMEOUT_S": "600",
        "KUBEDELOS_LOG_LEVEL": "info",
    }
    for key, value in expected.items():
        assert data[key] == value
    assert all(isinstance(value, str) for value in data.values())

    scoped = kind(
        render(
            {
                "scope": {
                    "namespaces": ["web", "jobs"],
                    "excludeNamespaces": ["kube-system"],
                    "excludeImages": ["docker.io/library/*"],
                    "namespaceSelector": "team=a",
                    "selector": "app=b",
                }
            }
        ),
        "ConfigMap",
    )["data"]
    assert json.loads(scoped["KUBEDELOS_NAMESPACES"]) == ["web", "jobs"]
    assert json.loads(scoped["KUBEDELOS_EXCLUDE_NAMESPACES"]) == ["kube-system"]
    assert json.loads(scoped["KUBEDELOS_EXCLUDE_IMAGES"]) == ["docker.io/library/*"]
    assert scoped["KUBEDELOS_NAMESPACE_SELECTOR"] == "team=a"
    assert scoped["KUBEDELOS_SELECTOR"] == "app=b"


def test_configmap_values_load_as_settings(render, monkeypatch):
    docs = render({"scope": {"namespaces": ["web", "jobs"]}, "sweep": {"enabled": False}, "readOnly": True})
    for key, value in kind(docs, "ConfigMap")["data"].items():
        monkeypatch.setenv(key, value)
    settings = Settings()
    assert settings.namespaces == ["web", "jobs"]
    assert settings.cluster_name == "my-cluster"
    assert settings.sweep_enabled is False
    assert settings.read_only is True
    assert settings.secure_cookies is True
    assert "t-kubedelos.kd.svc.cluster.local" in settings.allowed_hosts


def test_allowed_hosts_include_the_service_names(render):
    docs = render({"clusterDomain": "example.local"})
    hosts = kind(docs, "ConfigMap")["data"]["KUBEDELOS_ALLOWED_HOSTS"].split(",")
    name = kind(docs, "Service")["metadata"]["name"]
    assert hosts[:4] == [name, f"{name}.kd", f"{name}.kd.svc", f"{name}.kd.svc.example.local"]
    extra = kind(render({"extraAllowedHosts": ["kubedelos.example.com"]}), "ConfigMap")["data"]
    assert extra["KUBEDELOS_ALLOWED_HOSTS"].endswith(",kubedelos.example.com")


def test_deployment_rolls_on_config_change(render):
    def checksum(values):
        return kind(render(values), "Deployment")["spec"]["template"]["metadata"]["annotations"]["checksum/config"]

    assert checksum({}) == checksum({})
    assert checksum({}) != checksum({"retentionDays": 30})
