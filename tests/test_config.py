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
