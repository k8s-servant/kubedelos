"""Runtime settings, loaded from ``KUBEDELOS_*`` environment variables and the flags of ``kubedelos ui``.

``setting_sources`` says where each value came from, for the UI's Settings page.
"""

import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import platformdirs
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

APP_NAME = "kubedelos"
PKG_TYPES = frozenset({"os", "library"})  # Trivy's --pkg-types values kubedelos supports


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
    namespace_selector: str | None = None  # kubectl label-selector syntax, applied by the API server
    selector: str | None = None  # pod and workload labels, same syntax
    exclude_images: list[str] = []  # globs matched against the normalised image name, see kube.inventory.image_names
    cache_dir: Path = Field(default_factory=_default_cache_dir)
    data_dir: Path = Field(default_factory=_default_data_dir)
    trivy_path: Path | None = None
    parallelism: int = Field(default=4, ge=1, le=32)
    scan_timeout_s: int = 600
    layer_cache: bool = True  # keep each parallel scan's Trivy layer cache on disk between runs
    owner_annotation: str = "kubedelos.io/owner-email"
    team_label: str = "kubedelos.io/team"
    # NoDecode: KUBEDELOS_PKG_TYPES=os,library is a plain comma list, not JSON.
    pkg_types: Annotated[tuple[str, ...], NoDecode] = ("library", "os")

    @field_validator("namespace_selector", "selector", mode="before")
    @classmethod
    def _blank_selector_is_none(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("exclude_images")
    @classmethod
    def _normalise_pattern_hosts(cls, value: list[str]) -> list[str]:
        """Lowercase a pattern's registry host and spell Docker Hub ``docker.io``, as image names are (see
        ``kube.inventory.image_names``), so ``Registry.Example.com/*`` or ``index.docker.io/*`` still match.
        """
        patterns = []
        for pattern in value:
            first, sep, rest = pattern.partition("/")
            if sep and ("." in first or ":" in first or first == "localhost"):
                host = first.lower()
                pattern = f"{'docker.io' if host == 'index.docker.io' else host}/{rest}"
            patterns.append(pattern)
        return patterns

    @field_validator("pkg_types", mode="before")
    @classmethod
    def _normalise_pkg_types(cls, value: Any) -> tuple[str, ...]:
        """Accept ``"os,library"`` or a list, case- and order-insensitively, so one scan level has one spelling."""
        items = value.split(",") if isinstance(value, str) else list(value)
        names = [str(item).strip().lower() for item in items]
        if not names or any(name not in PKG_TYPES for name in names):
            raise ValueError(f"must be a comma-separated list of {', '.join(sorted(PKG_TYPES))}")
        return tuple(sorted(set(names)))

    @property
    def scan_level(self) -> str:
        """The package types as one normalised string, e.g. ``library,os``: part of the cache key and of each run."""
        return ",".join(self.pkg_types)

    @property
    def scope(self) -> str:
        """What a run covers, as canonical JSON: equal scopes mean comparable runs (with the same scan level)."""
        scope = {
            "namespaces": sorted(set(self.namespaces)),
            "exclude_namespaces": sorted(set(self.exclude_namespaces)),
            "namespace_selector": self.namespace_selector,
            "selector": self.selector,
            "exclude_images": sorted(set(self.exclude_images)),
        }
        return json.dumps(scope, sort_keys=True, separators=(",", ":"))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "kubedelos.db"


Source = Literal["flag", "environment", "default"]


def setting_sources(settings: Settings, *, flags: Collection[str], environ: Mapping[str, str]) -> dict[str, Source]:
    """Where each field of ``settings`` came from: a flag (which wins, as in ``Settings(**flags)``), its
    ``KUBEDELOS_*`` variable (matched case-insensitively, as pydantic-settings reads them), or the default.
    """
    prefix = settings.model_config.get("env_prefix", "")
    names = {name.upper() for name in environ}
    sources: dict[str, Source] = {}
    for field in type(settings).model_fields:
        if field in flags:
            sources[field] = "flag"
        elif (prefix + field).upper() in names:
            sources[field] = "environment"
        else:
            sources[field] = "default"
    return sources
