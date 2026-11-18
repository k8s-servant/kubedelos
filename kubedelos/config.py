"""Runtime settings, loaded from ``KUBEDELOS_*`` environment variables and the flags of ``kubedelos ui``.

``setting_sources`` says where each value came from, for the UI's Settings page.
"""

import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import platformdirs
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

APP_NAME = "kubedelos"
PKG_TYPES = frozenset({"os", "library"})  # Trivy's --pkg-types values kubedelos supports


def _default_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir(APP_NAME))


def _default_data_dir() -> Path:
    return Path(platformdirs.user_data_dir(APP_NAME))


def host_name(host: str) -> str:
    """The hostname of a Host header value: its port dropped, an IPv6 literal's brackets stripped, lowercased."""
    if host.startswith("["):
        name, closed, _ = host[1:].partition("]")
        return name.lower() if closed else ""
    return host.partition(":")[0].lower()


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
    trivy_dir: Path | None = None  # a directory holding <pinned version>/trivy, as the container image bundles it
    parallelism: int = Field(default=4, ge=1, le=32)
    scan_timeout_s: int = 600
    layer_cache: bool = True  # keep each parallel scan's Trivy layer cache on disk between runs
    owner_annotation: str = "kubedelos.io/owner-email"
    team_label: str = "kubedelos.io/team"
    # NoDecode: KUBEDELOS_PKG_TYPES=os,library is a plain comma list, not JSON.
    pkg_types: Annotated[tuple[str, ...], NoDecode] = ("library", "os")

    cluster_name: str | None = None  # the name runs are stored under, instead of the kube context (set by serve)
    sweep_schedule: str = "0 3 * * *"  # cron expression of the scheduled sweep
    sweep_timezone: str = "UTC"
    sweep_enabled: bool = True
    retention_days: int = Field(default=180, ge=0)
    allowed_hosts: Annotated[list[str], NoDecode] = ["localhost", "127.0.0.1"]  # Host header values the UI answers to
    read_only: bool = False  # serve only: refuse every write, so the UI is view-only
    trust_proxy_headers: bool = False  # serve only: read the user's name from ``identity_header``
    secure_cookies: bool = False  # serve only: mark the CSRF cookie Secure, for a UI reached over HTTPS
    identity_header: str = "X-Auth-Request-Email"  # set by the sign-in proxy in front of serve
    secrets_dir: Path | None = None  # serve only: a private directory for the per-scan docker configs
    docker_configs: Annotated[list[Path], NoDecode] = []  # mounted docker config.json files with registry credentials
    # Namespaces whose pods' imagePullSecrets kubedelos may read (names only here, contents at scan time). Namespace
    # names, not secret values.
    pod_pull_secret_namespaces: Annotated[list[str], NoDecode] = []

    @field_validator("sweep_timezone")
    @classmethod
    def _known_time_zone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {value!r}") from exc
        return value

    @field_validator("identity_header")
    @classmethod
    def _header_name(cls, value: str) -> str:
        value = value.strip()
        if not value or not all(char.isascii() and (char.isalnum() or char == "-") for char in value):
            raise ValueError("must be an HTTP header name (letters, digits and hyphens)")
        return value

    @model_validator(mode="after")
    def _credentials_need_secrets_dir(self) -> Self:
        if (self.docker_configs or self.pod_pull_secret_namespaces) and self.secrets_dir is None:
            raise ValueError("KUBEDELOS_SECRETS_DIR is required for registry credentials")
        return self

    @model_validator(mode="after")
    def _secrets_dir_is_its_own(self) -> Self:
        """``kubedelos serve`` empties this directory at start, so it must never be, hold or sit in other data."""
        if self.secrets_dir is None:
            return self
        secrets = self.secrets_dir.resolve()
        for label, other in (("data_dir", self.data_dir), ("cache_dir", self.cache_dir)):
            other = other.resolve()
            if secrets == other or secrets.is_relative_to(other) or other.is_relative_to(secrets):
                raise ValueError(f"KUBEDELOS_SECRETS_DIR must not equal, contain or sit inside {label}")
        if any(path.resolve().is_relative_to(secrets) for path in self.docker_configs):
            raise ValueError("KUBEDELOS_SECRETS_DIR must not contain a docker config file")
        return self

    @field_validator("allowed_hosts", "docker_configs", "pod_pull_secret_namespaces", mode="before")
    @classmethod
    def _split_list(cls, value: Any) -> Any:
        """Accept a JSON list or a comma-separated string (``a.example.com,b.example.com``, as a Helm chart sets it)."""
        if not isinstance(value, str):
            return value
        if value.lstrip().startswith("["):
            try:
                return json.loads(value)
            except ValueError:
                pass  # "[::1],a.example.com" is a comma list that starts with an IPv6 literal
        return [item.strip() for item in value.split(",") if item.strip()]

    @field_validator("allowed_hosts")
    @classmethod
    def _normalise_allowed_hosts(cls, value: list[str]) -> list[str]:
        """Lowercase each host and drop its port and the brackets of an IPv6 literal, as a Host header is compared."""
        hosts = [host.strip() for host in value]
        # A bare IPv6 literal (``::1``) has no port to drop; host_name would read it as an empty host.
        return [host.lower() if host.count(":") > 1 and "[" not in host else host_name(host) for host in hosts]

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
