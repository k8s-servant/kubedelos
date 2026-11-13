"""Find the Trivy binary, or download the pinned release and verify it against its embedded SHA-256."""

import hashlib
import hmac
import os
import platform
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

import httpx

from kubedelos.config import Settings
from kubedelos.trivy import pins

DOWNLOAD_URL = "https://github.com/aquasecurity/trivy/releases/download/v{version}/{asset}"
_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024  # the real tarballs are ~50 MB; stop a runaway response filling the disk
_CHUNK = 1024 * 1024

_SUPPORTED_OS = {"linux", "darwin"}
_ARCH = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}


class TrivyVerificationError(Exception):
    """The downloaded release does not match its pinned hash, or its archive is not shaped as expected."""


def platform_key() -> tuple[str, str]:
    """Return the ``(os, arch)`` key of :data:`pins.ASSETS` for this machine."""
    system, machine = platform.system().lower(), platform.machine().lower()
    arch = _ARCH.get(machine)
    if system not in _SUPPORTED_OS or arch is None:
        raise RuntimeError(
            f"unsupported platform {system}/{machine}: kubedelos ships Trivy for linux and darwin on amd64 and arm64"
        )
    return system, arch


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _cached_path(settings: Settings) -> Path:
    return settings.cache_dir / "trivy" / pins.TRIVY_VERSION / "trivy"


def ensure_trivy(settings: Settings, *, download: bool = True, client: httpx.Client | None = None) -> Path:
    """Return a usable Trivy binary: ``settings.trivy_path``, the cached pinned release, or a fresh download of it.

    ``client`` is the HTTP client used for the download; by default a new one is created and closed.
    """
    if settings.trivy_path is not None:
        if not _is_executable(settings.trivy_path):
            raise FileNotFoundError(
                f"KUBEDELOS_TRIVY_PATH points to {settings.trivy_path}, which is not an executable file"
            )
        return settings.trivy_path

    target = _cached_path(settings)
    if _is_executable(target):
        return target
    if not download:
        raise FileNotFoundError(
            f"Trivy {pins.TRIVY_VERSION} is not installed at {target}. "
            "Run `kubedelos trivy install`, or set KUBEDELOS_TRIVY_PATH to an existing binary."
        )

    asset, sha256 = pins.ASSETS[platform_key()]
    url = DOWNLOAD_URL.format(version=pins.TRIVY_VERSION, asset=asset)
    target.parent.mkdir(parents=True, exist_ok=True)

    if client is None:
        with httpx.Client(follow_redirects=True, timeout=_TIMEOUT) as owned:
            _install(owned, url, asset, sha256, target)
    else:
        _install(client, url, asset, sha256, target)
    return target


def _install(client: httpx.Client, url: str, asset: str, sha256: str, target: Path) -> None:
    """Download ``url`` next to ``target``, verify it, and move its ``trivy`` member into place atomically."""
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".download-", suffix=".tar.gz")
    archive = Path(tmp_name)
    staging: Path | None = None
    try:
        with os.fdopen(fd, "wb") as out:
            actual = _download(client, url, out)
        if not hmac.compare_digest(actual, sha256):
            raise TrivyVerificationError(f"SHA-256 mismatch for {asset}: expected {sha256}, got {actual}")

        staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=".extract-"))
        extracted = _extract_trivy(archive, staging, asset)
        extracted.chmod(0o755)
        os.replace(extracted, target)
    finally:
        archive.unlink(missing_ok=True)
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _download(client: httpx.Client, url: str, out: BinaryIO) -> str:
    digest = hashlib.sha256()
    size = 0
    with client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes(_CHUNK):
            size += len(chunk)
            if size > _MAX_DOWNLOAD_BYTES:
                raise TrivyVerificationError(f"{url} is larger than {_MAX_DOWNLOAD_BYTES} bytes")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def _extract_trivy(archive: Path, staging: Path, asset: str) -> Path:
    """Extract the single regular file named ``trivy`` at the archive root; refuse unsafe or ambiguous archives."""
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise TrivyVerificationError(f"{asset} contains an unsafe path: {member.name!r}")
        candidates = [m for m in members if m.name in ("trivy", "./trivy")]
        if len(candidates) != 1:
            raise TrivyVerificationError(f"{asset} must contain exactly one 'trivy' entry, found {len(candidates)}")
        member = candidates[0]
        if not member.isreg():
            raise TrivyVerificationError(f"'trivy' in {asset} is not a regular file")
        tar.extract(member, path=staging, filter="data")
    return staging / "trivy"
