from pathlib import Path

import platformdirs
import pytest
from pydantic import ValidationError

from kubedelos.config import Settings


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
