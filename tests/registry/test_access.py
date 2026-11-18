import json
import stat

from kubedelos.config import Settings
from kubedelos.models import ImageRef, InventoryItem
from kubedelos.registry.access import RegistryAccess
from tests.kube.fakes import FakeKubeApi, secret

HOST = "registry.example.com"


def _item(pull_secrets=()):
    ref = ImageRef(ref=f"{HOST}/team/app:1", repo=f"{HOST}/team/app")
    return InventoryItem(image=ref, platform="linux/amd64", pull_secrets=list(pull_secrets))


def _config(host, user):
    return json.dumps({"auths": {host: {"username": user, "password": "p-sentinel"}}}).encode()


def _mounted(tmp_path, host=HOST, user="mounted"):
    path = tmp_path / "mounted.json"
    path.write_bytes(_config(host, user))
    return path


def _settings(tmp_path, **kw):
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    return Settings(secrets_dir=secrets, data_dir=tmp_path / "data", cache_dir=tmp_path / "cache", **kw)


def _written(access):
    return json.loads((access.docker_config / "config.json").read_text())["auths"]


def test_mounted_config_is_written_for_its_host(tmp_path):
    settings = _settings(tmp_path, docker_configs=[_mounted(tmp_path)])
    with RegistryAccess(settings).for_item(_item()) as access:
        assert _written(access)[HOST]["username"] == "mounted"
        assert stat.S_IMODE((access.docker_config / "config.json").stat().st_mode) == 0o600
    assert list(settings.secrets_dir.iterdir()) == []


def test_pull_secret_overrides_mounted_config(tmp_path):
    settings = _settings(tmp_path, docker_configs=[_mounted(tmp_path)], pod_pull_secret_namespaces=["web"])
    api = FakeKubeApi(
        secrets={("web", "regcred"): secret("regcred", "web", {".dockerconfigjson": _config(HOST, "pod")})}
    )
    with RegistryAccess(settings, api).for_item(_item([("web", "regcred")])) as access:
        assert _written(access)[HOST]["username"] == "pod"


def test_no_file_without_secrets_dir():
    with RegistryAccess.none().for_item(_item()) as access:
        assert access.docker_config is None


def test_no_file_without_entries_for_host(tmp_path):
    settings = _settings(tmp_path, docker_configs=[_mounted(tmp_path, host="other.example.com")])
    with RegistryAccess(settings).for_item(_item()) as access:
        assert access.docker_config is None
    assert list(settings.secrets_dir.iterdir()) == []


def test_pull_secrets_are_ignored_without_namespaces(tmp_path):
    settings = _settings(tmp_path)
    api = FakeKubeApi(
        secrets={("web", "regcred"): secret("regcred", "web", {".dockerconfigjson": _config(HOST, "pod")})}
    )
    with RegistryAccess(settings, api).for_item(_item([("web", "regcred")])) as access:
        assert access.docker_config is None
