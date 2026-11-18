"""Read docker config files, merge their credentials, and write a minimal per-scan config for Trivy.

Registry credentials come from mounted ``config.json`` files. Only their ``auths`` section is kept (credential
helpers and stores cannot run in the container), keys are normalised to a bare host, and each scan gets a
throwaway config with just the entries it needs. Credential contents never reach logs or error messages: only
paths and exception class names do.
"""

import json
import logging
import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

Auths = dict[str, dict[str, str]]  # normalised host -> {"auth": ...} or {"username": ..., "password": ...}

DOCKER_HUB = "docker.io"
DOCKER_HUB_KEY = "https://index.docker.io/v1/"  # how docker (and so Trivy) spells Docker Hub in ``auths``
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


def normalise_host(key: str) -> str:
    """A registry host as image names spell it: scheme, path and trailing slash dropped, lowercased."""
    host = key.strip().lower()
    host = host.split("://", 1)[-1].split("/", 1)[0]
    return DOCKER_HUB if host in _DOCKER_HUB_HOSTS else host


def _usable(entry: object) -> dict[str, str] | None:
    if not isinstance(entry, dict):
        return None
    if isinstance(entry.get("auth"), str) and entry["auth"]:
        return {"auth": entry["auth"]}
    username, password = entry.get("username"), entry.get("password")
    if isinstance(username, str) and isinstance(password, str) and username:
        return {"username": username, "password": password}
    return None


def parse(raw: bytes) -> Auths:
    """The usable ``auths`` entries of a docker config, by normalised host. Raises ``ValueError`` (without any
    file content in the message) for a config that is not a JSON object.
    """
    try:
        document = json.loads(raw)
    except ValueError:
        raise ValueError("not valid JSON") from None
    if not isinstance(document, dict):
        raise ValueError("not a JSON object")
    auths = document.get("auths")
    if not isinstance(auths, dict):
        return {}
    result: Auths = {}
    for key, entry in auths.items():
        usable = _usable(entry)
        if usable is not None:
            result.setdefault(normalise_host(key), usable)
    return result


def load_mounted(paths: list[Path]) -> Auths:
    """Merge the configs at ``paths``; the first file to name a host wins. A missing or bad file is skipped."""
    merged: Auths = {}
    for path in paths:
        try:
            auths = parse(path.read_bytes())
        except (OSError, ValueError) as exc:
            logger.warning("skipped docker config %s: %s", path, type(exc).__name__)
            continue
        for host, entry in auths.items():
            merged.setdefault(host, entry)
    return merged


def for_host(auths: Auths, host: str) -> Auths:
    """The entries for ``host`` only."""
    host = normalise_host(host)
    return {host: auths[host]} if host in auths else {}


TEMP_PREFIX = "kubedelos-docker-"


@contextmanager
def temp_config(secrets_dir: Path, auths: Auths) -> Iterator[Path]:
    """A directory under ``secrets_dir`` holding a ``config.json`` of ``auths``, for ``DOCKER_CONFIG``.

    The directory is mode 0700 and the file 0600; both are removed on exit, also when the body raises.
    """
    directory = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=secrets_dir))  # mkdtemp creates it 0700
    try:
        body = {"auths": {DOCKER_HUB_KEY if host == DOCKER_HUB else host: entry for host, entry in auths.items()}}
        fd = os.open(directory / "config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(body, handle)
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def clear(secrets_dir: Path) -> None:
    """Remove the directories :func:`temp_config` left in ``secrets_dir`` (a crashed scan), keeping everything else.

    Only entries with :data:`TEMP_PREFIX` go, so a ``secrets_dir`` pointed at the wrong place deletes nothing else.
    """
    try:
        entries = list(secrets_dir.iterdir())
    except FileNotFoundError:
        return
    for entry in entries:
        if not entry.name.startswith(TEMP_PREFIX) or entry.is_symlink() or not entry.is_dir():
            continue
        try:
            shutil.rmtree(entry)
        except OSError as exc:
            logger.warning("could not remove leftover %s: %s", entry.name, type(exc).__name__)
