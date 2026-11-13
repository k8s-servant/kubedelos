"""End-to-end scan of a throwaway kind cluster. Needs kind, docker and network access."""

import contextlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "e2e-kind.sh"


def _docker_running() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_script(out: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run the script in its own process group; on timeout or Ctrl-C let its EXIT trap delete the cluster."""
    proc = subprocess.Popen(
        [str(SCRIPT), str(out)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def test_kind_scan(tmp_path: Path) -> None:
    if any(shutil.which(tool) is None for tool in ("kind", "docker", "kubectl")):
        pytest.skip("kind, docker and kubectl are required")
    if not _docker_running():
        pytest.skip("docker is not running")

    out = tmp_path / "out.json"
    env = os.environ.copy()
    env["KUBEDELOS_CACHE_DIR"] = str(tmp_path / "cache")
    env["KUBEDELOS_DATA_DIR"] = str(tmp_path / "data")
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env['PATH']}"

    proc = _run_script(out, env, timeout=1800)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"

    rows = json.loads(out.read_text())
    nginx = [r for r in rows if r["image"].startswith("docker.io/library/nginx")]
    assert any(r["severity"] == "CRITICAL" for r in nginx)
    web = [r for r in rows if r["namespace"] == "web"]
    assert web
    assert all(r["owner"] == "web@example.com" for r in web)

    # busybox:1.36 has zero findings, so it never appears in the JSON rows. Check that it was scanned.
    with contextlib.closing(sqlite3.connect(tmp_path / "data" / "kubedelos.db")) as db:
        busybox = db.execute(
            "SELECT i.status FROM image_result i JOIN workload w ON w.image_result_id = i.id "
            "WHERE w.namespace = 'jobs' AND i.ref LIKE '%busybox%'"
        ).fetchall()
    assert busybox
    assert {status for (status,) in busybox} == {"ok"}
