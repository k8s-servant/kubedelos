"""The wheel's contents, the container image's hashed lock files and the MCP Registry entry (server.json), all kept in
step with pyproject.toml."""

import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

EXPECTED = (
    "kubedelos/web/templates/base.html",
    "kubedelos/web/templates/dashboard.html",
    "kubedelos/web/templates/findings.html",
    "kubedelos/web/templates/partials/run_line.html",
    "kubedelos/web/static/app.css",
    "kubedelos/web/static/logo.svg",
    "kubedelos/web/static/htmx.min.js",
)


def test_wheel_contains_templates_and_static(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(tmp_path), str(repo_root)], check=True
    )
    (wheel,) = tmp_path.glob("kubedelos-*.whl")
    names = set(zipfile.ZipFile(wheel).namelist())
    assert set(EXPECTED) <= names


ROOT = Path(__file__).resolve().parent.parent


def _locked(path: Path) -> dict[str, tuple[str, int]]:
    """Each package pinned in a hashed lock file: canonical name -> (version, number of hashes)."""
    pins: dict[str, tuple[str, int]] = {}
    name = None
    for line in path.read_text().splitlines():
        if pin := re.match(r"^([A-Za-z0-9_.-]+)==(\S+)", line):
            name = canonicalize_name(pin[1])
            pins[name] = (pin[2], 0)
        elif name and re.fullmatch(r"--hash=sha256:[0-9a-f]{64}( \\)?", line.strip()):
            version, hashes = pins[name]
            pins[name] = (version, hashes + 1)
    return pins


def _assert_locked(requirements: list[str], lock: Path) -> None:
    pins = _locked(lock)
    assert pins and all(hashes for _, hashes in pins.values()), f"{lock.name}: a pin without hashes"
    for text in requirements:
        req = Requirement(text)
        name = canonicalize_name(req.name)
        assert name in pins, f"{req.name} is not in {lock.name}: run scripts/lock-image.sh"
        assert req.specifier.contains(pins[name][0], prereleases=True), (
            f"{lock.name} pins {req.name}=={pins[name][0]}, outside {req.specifier}: run scripts/lock-image.sh"
        )


def test_image_lock_satisfies_the_runtime_dependencies():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    _assert_locked(project["project"]["dependencies"], ROOT / "requirements" / "image.txt")


def test_build_lock_satisfies_the_build_system():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    _assert_locked(project["build-system"]["requires"], ROOT / "requirements" / "build.txt")


def test_locks_are_resolved_for_the_image_python():
    base = re.search(r"^FROM python:(\d+\.\d+)-alpine@", (ROOT / "Dockerfile").read_text(), re.M)
    target = re.search(r"--python-version (\d+\.\d+)", (ROOT / "scripts" / "lock-image.sh").read_text())
    assert base and target and base[1] == target[1]


def test_mcp_registry_entry_matches_the_package():
    # The MCP Registry checks that the PyPI description names the server, and installs the version server.json gives;
    # release-please bumps both versions, so they must stay listed in its config.
    root = Path(__file__).resolve().parent.parent
    server = json.loads((root / "server.json").read_text())
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    (package,) = server["packages"]
    assert f"<!-- mcp-name: {server['name']} -->" in (root / "README.pypi.md").read_text()
    assert server["version"] == package["version"] == version
    assert package["registryType"] == "pypi" and package["identifier"] == "kubedelos"
    assert package["packageArguments"] == [{"type": "positional", "value": "mcp"}]
    assert len(server["description"]) <= 100
    bumped = {
        f["jsonpath"]
        for f in json.loads((root / "release-please-config.json").read_text())["packages"]["."]["extra-files"]
        if f["path"] == "server.json"
    }
    assert bumped == {"$.version", "$.packages[0].version"}
