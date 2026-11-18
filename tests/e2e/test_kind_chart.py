"""End-to-end install of the Helm chart on a throwaway kind cluster, waiting for a scheduled sweep that also
scans a private registry:2 through mounted and pod pull secrets. Needs kind, helm, docker, kubectl and network access."""

import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.e2e

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "e2e-chart.sh"


def _docker_running() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_script(env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run the script in its own process group; on timeout or Ctrl-C let its EXIT trap delete the cluster."""
    proc = subprocess.Popen(
        [str(SCRIPT)],
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


def test_kind_chart() -> None:
    if any(shutil.which(tool) is None for tool in ("kind", "docker", "kubectl", "helm")):
        pytest.skip("kind, docker, kubectl and helm are required")
    if not _docker_running():
        pytest.skip("docker is not running")

    # The first sweep downloads the Trivy DB (up to 15 minutes), on top of the image build and cluster creation.
    proc = _run_script(os.environ.copy(), timeout=2400)
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert re.search(r"^sweep run \d+: (ok|partial), nginx:1\.19 scanned$", proc.stdout, re.MULTILINE), proc.stdout

    # The private registry: a mounted config and a listed namespace's pull secret get an image scanned, while an
    # unlisted namespace and an Opaque Secret are refused (auth), and the per-scan config files are gone afterwards.
    for line in (
        "registry e2e-mounted: scanned",
        "registry e2e-pull: scanned",
        "registry e2e-unlisted: error auth",
        "registry e2e-opaque: error auth",
        "secrets dir empty",
    ):
        assert re.search(rf"^{re.escape(line)}$", proc.stdout, re.MULTILINE), f"missing {line!r}:\n{proc.stdout}"
