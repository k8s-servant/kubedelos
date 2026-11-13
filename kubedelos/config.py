"""Runtime settings, loaded from ``KUBEDELOS_*`` environment variables."""

from pathlib import Path

import platformdirs
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

APP_NAME = "kubedelos"


def _default_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir(APP_NAME))


def _default_data_dir() -> Path:
    return Path(platformdirs.user_data_dir(APP_NAME))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUBEDELOS_")

    kubeconfig: Path | None = None
    context: str | None = None
    namespaces: list[str] = []  # empty means all
    exclude_namespaces: list[str] = []
    cache_dir: Path = Field(default_factory=_default_cache_dir)
    data_dir: Path = Field(default_factory=_default_data_dir)
    trivy_path: Path | None = None
    parallelism: int = Field(default=4, ge=1, le=32)
    scan_timeout_s: int = 600
    owner_annotation: str = "kubedelos.io/owner-email"
    team_label: str = "kubedelos.io/team"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "kubedelos.db"
