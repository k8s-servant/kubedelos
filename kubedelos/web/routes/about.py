"""The About page (``GET /about``): how fresh the data is, what is running, and the project.

The first card answers "can I trust what I see?": when Trivy built the vulnerability and Java DBs in use (read from
the ``metadata.json`` Trivy writes next to them) and when the shown context was last scanned. The DBs are updated at
the start of a scan, so a DB past its next update says the next scan fetches a newer one. Then the kubedelos and
Trivy versions, the license and the project links (from the package metadata), and what kubedelos never does.
"""

import platform
from datetime import datetime
from importlib.metadata import metadata

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from kubedelos import __version__
from kubedelos.analytics import ago
from kubedelos.config import Settings
from kubedelos.store.queries import newest_run
from kubedelos.trivy.cache import DbInfo, db_info
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.web.pages import open_db, render, shown_context

router = APIRouter()

SECURITY_POLICY = "Security"  # the Project-URL label of the security policy


def db_text(info: DbInfo | None, now: datetime, *, missing: str) -> str:
    """A DB's age as the page shows it, or ``missing`` when it was never downloaded."""
    if info is None:
        return f"not downloaded: {missing}"
    text = f"built {ago(info.updated_at, now)}, downloaded {ago(info.downloaded_at, now)}"
    return text + (" · a newer one is out: the next scan downloads it" if now >= info.next_update else "")


def project_links() -> list[tuple[str, str]]:
    """The package's ``Project-URL`` entries, as (label, url)."""
    return [
        (label.strip(), url.strip())
        for entry in metadata("kubedelos").get_all("Project-URL") or []
        for label, _, url in [entry.partition(",")]
    ]


@router.get("/about", response_class=HTMLResponse)
def about(request: Request) -> HTMLResponse:
    current: Settings = request.app.state.settings
    now = request.app.state.clock()
    with open_db(request) as conn:
        context = shown_context(request, conn)
        newest = newest_run(conn, context, cluster_scope=False)
    if newest is None:
        scanned = "none yet"
    elif newest.finished_at is None:
        scanned = f"Run {newest.number}, still running"
    else:
        scanned = f"Run {newest.number}, {ago(newest.finished_at, now)}"
    trivy = f"custom: {current.trivy_path}" if current.trivy_path else f"v{TRIVY_VERSION} (pinned, checksum-verified)"
    ctx = {
        "now": now,
        "run": newest,  # the sidebar's "scanned N ago"
        "freshness": [
            ("Vulnerability DB", db_text(db_info(current.cache_dir, "db"), now, missing="the first scan downloads it")),
            (
                "Java DB",
                db_text(db_info(current.cache_dir, "java-db"), now, missing="a scan of library packages downloads it"),
            ),
            (f"Newest scan of {context}", scanned),
        ],
        "running": [
            ("kubedelos", __version__),
            ("Trivy", trivy),
            ("Python", platform.python_version()),
            ("License", metadata("kubedelos").get("License-Expression") or "see LICENSE"),
        ],
        "links": project_links(),
    }
    return render(request, "about.html", ctx)
