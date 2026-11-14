import subprocess
import sys
import zipfile
from pathlib import Path

EXPECTED = (
    "kubedelos/web/templates/base.html",
    "kubedelos/web/templates/dashboard.html",
    "kubedelos/web/templates/findings.html",
    "kubedelos/web/templates/partials/run_line.html",
    "kubedelos/web/static/app.css",
)


def test_wheel_contains_templates_and_static(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(tmp_path), str(repo_root)], check=True
    )
    (wheel,) = tmp_path.glob("kubedelos-*.whl")
    names = set(zipfile.ZipFile(wheel).namelist())
    assert set(EXPECTED) <= names
