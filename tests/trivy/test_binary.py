import hashlib
import io
import stat
import tarfile

import httpx
import pytest
from typer.testing import CliRunner

from kubedelos import cli
from kubedelos.config import Settings
from kubedelos.trivy import binary, pins
from kubedelos.trivy.binary import TrivyVerificationError, ensure_trivy

FAKE_BINARY = b"#!/bin/sh\necho fake trivy\n"


def _tarball(*members: tuple[str, bytes], symlink: tuple[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink[0])
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            tar.addfile(info)
    return buf.getvalue()


@pytest.fixture
def linux_amd64(monkeypatch):
    monkeypatch.setattr(binary.platform, "system", lambda: "Linux")
    monkeypatch.setattr(binary.platform, "machine", lambda: "x86_64")
    return pins.ASSETS[("linux", "amd64")][0]


def _serve(monkeypatch, asset: str, payload: bytes, *, pinned: bytes | None = None):
    """Pin the hash of `pinned` (default: the payload itself) and return a client serving `payload`."""
    monkeypatch.setitem(pins.ASSETS, ("linux", "amd64"), (asset, hashlib.sha256(pinned or payload).hexdigest()))
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=payload)

    return httpx.Client(transport=httpx.MockTransport(handler)), requests


def _leftovers(settings: Settings) -> list[str]:
    root = settings.cache_dir / "trivy"
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.exists() else []


def test_pins_cover_supported_platforms():
    assert pins.TRIVY_VERSION == "0.76.1"
    assert set(pins.ASSETS) == {("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64")}
    for asset, sha in pins.ASSETS.values():
        assert asset.startswith("trivy_0.76.1_") and asset.endswith(".tar.gz")
        assert len(sha) == 64 and int(sha, 16) >= 0


def test_ensure_trivy_downloads_and_verifies(tmp_path, monkeypatch, linux_amd64):
    settings = Settings(cache_dir=tmp_path)
    client, requests = _serve(monkeypatch, linux_amd64, _tarball(("LICENSE", b"l"), ("trivy", FAKE_BINARY)))

    path = ensure_trivy(settings, client=client)

    assert path == tmp_path / "trivy" / "0.76.1" / "trivy"
    assert path.read_bytes() == FAKE_BINARY
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert [str(r.url) for r in requests] == [
        f"https://github.com/aquasecurity/trivy/releases/download/v0.76.1/{linux_amd64}"
    ]
    assert _leftovers(settings) == ["0.76.1", "0.76.1/trivy"]  # LICENSE not extracted, no temp files

    # a second call uses the cached binary and makes no request
    assert ensure_trivy(settings, client=client) == path
    assert len(requests) == 1


def test_ensure_trivy_accepts_dot_slash_member(tmp_path, monkeypatch, linux_amd64):
    client, _ = _serve(monkeypatch, linux_amd64, _tarball(("./trivy", FAKE_BINARY)))
    assert ensure_trivy(Settings(cache_dir=tmp_path), client=client).read_bytes() == FAKE_BINARY


def test_ensure_trivy_hash_mismatch_raises_and_cleans(tmp_path, monkeypatch, linux_amd64):
    settings = Settings(cache_dir=tmp_path)
    client, _ = _serve(monkeypatch, linux_amd64, _tarball(("trivy", FAKE_BINARY)), pinned=b"something else")

    with pytest.raises(TrivyVerificationError, match="SHA-256 mismatch"):
        ensure_trivy(settings, client=client)

    assert _leftovers(settings) == ["0.76.1"]


def test_ensure_trivy_http_error_cleans(tmp_path, monkeypatch, linux_amd64):
    settings = Settings(cache_dir=tmp_path)
    monkeypatch.setitem(pins.ASSETS, ("linux", "amd64"), (linux_amd64, "0" * 64))
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))

    with pytest.raises(httpx.HTTPStatusError):
        ensure_trivy(settings, client=client)

    assert _leftovers(settings) == ["0.76.1"]


@pytest.mark.parametrize(
    "payload",
    [
        _tarball(("../trivy", FAKE_BINARY)),
        _tarball(("trivy", FAKE_BINARY), ("../../evil", b"x")),
        _tarball(("/etc/trivy", FAKE_BINARY)),
        _tarball(symlink=("trivy", "/bin/sh")),
        _tarball(("bin/trivy", FAKE_BINARY)),
        _tarball(("trivy", FAKE_BINARY), ("./trivy", FAKE_BINARY)),
    ],
    ids=["dotdot-trivy", "dotdot-sibling", "absolute", "symlink", "nested", "duplicate"],
)
def test_ensure_trivy_rejects_path_traversal_member(tmp_path, monkeypatch, linux_amd64, payload):
    settings = Settings(cache_dir=tmp_path / "cache")
    client, _ = _serve(monkeypatch, linux_amd64, payload)

    with pytest.raises(TrivyVerificationError):
        ensure_trivy(settings, client=client)

    assert _leftovers(settings) == ["0.76.1"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["cache"]  # nothing escaped the cache dir


def test_ensure_trivy_prefers_explicit_path(tmp_path, monkeypatch):
    explicit = tmp_path / "my-trivy"
    explicit.write_bytes(FAKE_BINARY)
    explicit.chmod(0o755)

    def no_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no download expected")

    client = httpx.Client(transport=httpx.MockTransport(no_network))
    assert ensure_trivy(Settings(cache_dir=tmp_path / "cache", trivy_path=explicit), client=client) == explicit


def test_ensure_trivy_explicit_path_not_executable_raises(tmp_path):
    explicit = tmp_path / "my-trivy"
    explicit.write_bytes(FAKE_BINARY)
    explicit.chmod(0o644)
    with pytest.raises(FileNotFoundError, match="KUBEDELOS_TRIVY_PATH"):
        ensure_trivy(Settings(cache_dir=tmp_path / "cache", trivy_path=explicit))


def test_ensure_trivy_no_download_raises_when_missing(tmp_path):
    with pytest.raises(FileNotFoundError, match="kubedelos trivy install"):
        ensure_trivy(Settings(cache_dir=tmp_path), download=False)
    assert not (tmp_path / "trivy").exists()


def test_ensure_trivy_unsupported_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(binary.platform, "system", lambda: "Windows")
    monkeypatch.setattr(binary.platform, "machine", lambda: "AMD64")
    with pytest.raises(RuntimeError, match="unsupported platform"):
        ensure_trivy(Settings(cache_dir=tmp_path))


@pytest.mark.parametrize(
    ("system", "machine", "key"),
    [
        ("Linux", "x86_64", ("linux", "amd64")),
        ("Linux", "aarch64", ("linux", "arm64")),
        ("Darwin", "x86_64", ("darwin", "amd64")),
        ("Darwin", "arm64", ("darwin", "arm64")),
    ],
)
def test_platform_key_mapping(monkeypatch, system, machine, key):
    monkeypatch.setattr(binary.platform, "system", lambda: system)
    monkeypatch.setattr(binary.platform, "machine", lambda: machine)
    assert binary.platform_key() == key


def test_cli_trivy_install_prints_path_and_version(tmp_path, monkeypatch):
    monkeypatch.setenv("KUBEDELOS_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("KUBEDELOS_TRIVY_PATH", raising=False)
    target = tmp_path / "trivy" / "0.76.1" / "trivy"
    monkeypatch.setattr(cli, "ensure_trivy", lambda settings: target)

    r = CliRunner().invoke(cli.app, ["trivy", "install"])

    assert r.exit_code == 0, r.output
    assert "0.76.1" in r.stdout
    assert str(target) in r.stdout


def test_cli_trivy_install_reports_verification_failure(monkeypatch):
    def fail(settings):
        raise TrivyVerificationError("SHA-256 mismatch for trivy_0.76.1_Linux-64bit.tar.gz")

    monkeypatch.setattr(cli, "ensure_trivy", fail)
    r = CliRunner().invoke(cli.app, ["trivy", "install"])

    assert r.exit_code == 1
    assert "SHA-256 mismatch" in r.stderr
