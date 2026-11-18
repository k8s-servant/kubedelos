import re
from pathlib import Path

import platformdirs
import pytest
from pydantic import ValidationError

from kubedelos.config import Settings, setting_sources


def test_defaults_use_platformdirs(monkeypatch):
    monkeypatch.delenv("KUBEDELOS_CACHE_DIR", raising=False)
    monkeypatch.setattr(platformdirs, "user_cache_dir", lambda *a, **k: "/patched/cache")
    assert Settings().cache_dir == Path("/patched/cache")


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_DATA_DIR", "/x")
    assert Settings().db_path == Path("/x/kubedelos.db")


def test_parallelism_bounds():
    with pytest.raises(ValidationError):
        Settings(parallelism=0)
    with pytest.raises(ValidationError):
        Settings(parallelism=33)


def test_pkg_types_default_is_os_and_library():
    settings = Settings()
    assert settings.pkg_types == ("library", "os")
    assert settings.scan_level == "library,os"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("library,os", ("library", "os")),
        ("OS, Library", ("library", "os")),
        (["os", "os", "library"], ("library", "os")),
        ("os", ("os",)),
    ],
)
def test_pkg_types_normalised(value, expected):
    assert Settings(pkg_types=value).pkg_types == expected


@pytest.mark.parametrize("value", ["", "secrets", [], "os,,"])
def test_pkg_types_rejects_unknown_and_empty(value):
    with pytest.raises(ValidationError):
        Settings(pkg_types=value)


def test_pkg_types_from_env(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_PKG_TYPES", "os")
    assert Settings().pkg_types == ("os",)


def test_selectors_default_none_and_blank_is_none():
    assert Settings().selector is None and Settings().namespace_selector is None
    assert Settings(selector="  ", namespace_selector="").selector is None
    assert Settings(namespace_selector=" team=x ").namespace_selector == "team=x"


def test_exclude_images_from_env_json(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_EXCLUDE_IMAGES", '["a/*","b:*"]')
    assert Settings().exclude_images == ["a/*", "b:*"]


def test_scope_is_canonical():
    import json

    a = Settings(namespaces=["b", "a"], exclude_images=["y", "x"], selector="app=web")
    b = Settings(namespaces=["a", "b"], exclude_images=["x", "y"], selector="app=web")
    assert a.scope == b.scope
    assert json.loads(a.scope) == {
        "namespaces": ["a", "b"], "exclude_namespaces": [], "namespace_selector": None, "selector": "app=web",
        "exclude_images": ["x", "y"],
    }  # fmt: skip


def test_setting_sources_name_the_flag_the_environment_or_the_default():
    settings = Settings(context="c", parallelism=2, scan_timeout_s=5)
    environ = {"KUBEDELOS_PARALLELISM": "2", "kubedelos_scan_timeout_s": "5", "KUBEDELOS_CONTEXT": "x", "HOME": "/h"}
    sources = setting_sources(settings, flags={"context"}, environ=environ)
    assert set(sources) == set(Settings.model_fields)
    assert sources["context"] == "flag"  # a flag wins over the variable, as in Settings(**flags)
    assert sources["parallelism"] == "environment"
    assert (
        sources["scan_timeout_s"] == "environment"
    )  # variable names are case-insensitive, as pydantic-settings reads them
    assert sources["namespaces"] == "default"


def test_no_setting_is_named_like_a_secret():
    # The Settings page lists every field; a credential must never become one.
    # secrets_dir is only the path of a directory, not a value.
    names = [name for name in Settings.model_fields if re.search(r"token|password|secret|key|credential", name)]
    assert names == ["secrets_dir"]


def test_scope_ignores_repeated_values():
    once = Settings(namespaces=["a", "b"], exclude_namespaces=["c"], exclude_images=["x"])
    twice = Settings(namespaces=["b", "a", "b"], exclude_namespaces=["c", "c"], exclude_images=["x", "x"])
    assert once.scope == twice.scope


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("Registry.Example.com/team/*", "registry.example.com/team/*"),
        ("INDEX.DOCKER.IO/library/nginx:*", "docker.io/library/nginx:*"),
        ("index.docker.io/*", "docker.io/*"),
        ("localhost:5000/App/*", "localhost:5000/App/*"),  # only the host is case-insensitive
        ("Team/App:*", "Team/App:*"),  # no host: left as written
        ("nginx:1.*", "nginx:1.*"),
    ],
)
def test_exclude_image_hosts_are_normalised_like_image_names(pattern, expected):
    assert Settings(exclude_images=[pattern]).exclude_images == [expected]


def test_sweep_timezone_must_be_a_known_zone():
    with pytest.raises(ValidationError, match="sweep_timezone"):
        Settings(sweep_timezone="Mars/Olympus")
    assert Settings(sweep_timezone="Europe/Vilnius").sweep_timezone == "Europe/Vilnius"


def test_allowed_hosts_normalised():
    assert Settings(allowed_hosts=["Example.COM", "[::1]"]).allowed_hosts == ["example.com", "::1"]


def test_allowed_hosts_from_env_json(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_ALLOWED_HOSTS", '["Example.com"]')
    assert Settings().allowed_hosts == ["example.com"]


def test_retention_days_not_negative():
    with pytest.raises(ValidationError):
        Settings(retention_days=-1)
    assert Settings(retention_days=0).retention_days == 0


def test_serve_defaults():
    settings = Settings()
    assert (settings.cluster_name, settings.sweep_schedule, settings.sweep_timezone) == (None, "0 3 * * *", "UTC")
    assert settings.sweep_enabled is True and settings.retention_days == 180
    assert settings.allowed_hosts == ["localhost", "127.0.0.1"]


def test_allowed_hosts_from_env_comma_list(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_ALLOWED_HOSTS", "Example.com, [::1]")
    assert Settings().allowed_hosts == ["example.com", "::1"]
    monkeypatch.setenv("KUBEDELOS_ALLOWED_HOSTS", "[::1],a.example.com,")
    assert Settings().allowed_hosts == ["::1", "a.example.com"]


def test_allowed_hosts_drop_a_port():
    assert Settings(allowed_hosts=["Example.com:8080", "[::1]:8080", "::1"]).allowed_hosts == [
        "example.com",
        "::1",
        "::1",
    ]


def test_serve_write_settings_default():
    settings = Settings()
    assert settings.read_only is False
    assert settings.trust_proxy_headers is False
    assert settings.identity_header == "X-Auth-Request-Email"


def test_identity_header_must_be_a_header_name():
    for bad in ("X Auth", ""):
        with pytest.raises(ValidationError):
            Settings(identity_header=bad)
    assert Settings(identity_header="Remote-User").identity_header == "Remote-User"


def test_secure_cookies_and_trivy_dir_from_env(monkeypatch):
    assert (Settings().secure_cookies, Settings().trivy_dir) == (False, None)
    monkeypatch.setenv("KUBEDELOS_SECURE_COOKIES", "true")
    monkeypatch.setenv("KUBEDELOS_TRIVY_DIR", "/opt/trivy")
    settings = Settings()
    assert settings.secure_cookies is True and settings.trivy_dir == Path("/opt/trivy")


def test_docker_configs_need_secrets_dir(tmp_path):
    assert Settings().docker_configs == [] and Settings().secrets_dir is None
    with pytest.raises(ValidationError, match="KUBEDELOS_SECRETS_DIR is required for registry credentials"):
        Settings(docker_configs=[tmp_path / "a.json"])
    settings = Settings(docker_configs=[tmp_path / "a.json"], secrets_dir=tmp_path)
    assert settings.docker_configs == [tmp_path / "a.json"]


def test_docker_configs_from_env_comma_or_json(monkeypatch, tmp_path):
    monkeypatch.setenv("KUBEDELOS_SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("KUBEDELOS_DOCKER_CONFIGS", "/a/one.json, /b/two.json")
    assert Settings().docker_configs == [Path("/a/one.json"), Path("/b/two.json")]
    monkeypatch.setenv("KUBEDELOS_DOCKER_CONFIGS", '["/a/one.json"]')
    assert Settings().docker_configs == [Path("/a/one.json")]
