"""Registry credentials for one scan run: which docker config, if any, each image is scanned with.

Mounted configs are read once per run; the pull secrets a pod names are read on demand and override them for the
image's host. A config file exists only while one image is scanned, and only when ``secrets_dir`` is set and there is at
least one entry for the image's host; otherwise Trivy's environment is left alone.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from kubedelos.config import Settings
from kubedelos.kube.client import KubeApi
from kubedelos.models import InventoryItem, registry_host
from kubedelos.registry import dockerconfig
from kubedelos.registry.dockerconfig import Auths
from kubedelos.registry.pullsecrets import PullSecrets


@dataclass(frozen=True)
class ScanAccess:
    """What one image's scan needs: the ``DOCKER_CONFIG`` directory, or None to leave the environment alone."""

    docker_config: Path | None


class RegistryAccess:
    """Builds the per-image :class:`ScanAccess` for a run."""

    def __init__(self, settings: Settings, api: KubeApi | None = None) -> None:
        self._secrets_dir = settings.secrets_dir
        self._mounted: Auths = dockerconfig.load_mounted(settings.docker_configs) if settings.secrets_dir else {}
        namespaces = settings.pod_pull_secret_namespaces
        self._pulls = PullSecrets(api, namespaces) if api is not None and namespaces else None

    @classmethod
    def none(cls) -> "RegistryAccess":
        """No credentials at all."""
        return cls(Settings.model_construct(secrets_dir=None, docker_configs=[], pod_pull_secret_namespaces=[]))

    @contextmanager
    def for_item(self, item: InventoryItem) -> Iterator[ScanAccess]:
        """The access for ``item``; the config file it names is removed on exit, whatever happens inside."""
        host = registry_host(item.image)
        auths = dockerconfig.for_host(self._mounted, host)
        if self._pulls is not None and item.pull_secrets:
            auths = {**auths, **self._pulls.auths_for(item.pull_secrets, host)}
        if self._secrets_dir is None or not auths:
            yield ScanAccess(None)
            return
        with dockerconfig.temp_config(self._secrets_dir, auths) as directory:
            yield ScanAccess(directory)
