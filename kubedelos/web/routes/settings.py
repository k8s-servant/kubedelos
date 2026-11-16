"""The Settings page (``GET /settings``): every setting in effect, read-only, and where its value came from.

Each ``Settings`` field is listed with its value and its source (``config.setting_sources``): a flag given to
``kubedelos ui``, its ``KUBEDELOS_*`` variable, or the default. The page answers "why did the scan do that?"; the Scans
form can still change the scope, parallel images and package types for one scan. Below the table: the database file,
the data and cache directories, the Trivy in use and the log level.

No credentials are shown: ``Settings`` holds none (a test keeps it that way), and registry logins stay in Docker's own
config, which this page never reads.
"""

import os
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from kubedelos.config import Settings, setting_sources
from kubedelos.store.queries import newest_run
from kubedelos.trivy.pins import TRIVY_VERSION
from kubedelos.web.pages import open_db, render, shown_context

router = APIRouter()

FLAGS = {"context": "--context", "kubeconfig": "--kubeconfig"}  # the settings `kubedelos ui` takes as flags
FALLBACKS = {  # what an unset setting means
    "kubeconfig": "$KUBECONFIG or ~/.kube/config",
    "context": "the kubeconfig's current context",
    "trivy_path": "the pinned Trivy",
}
EMPTY_LISTS = {
    "namespaces": "none (every namespace)",
    "exclude_namespaces": "none",
    "exclude_images": "none",
}


def shown_value(field: str, value: object) -> str:
    """A setting's value as the page shows it: lists comma-joined, an unset value named as such."""
    if isinstance(value, list | tuple):
        return ", ".join(str(v) for v in value) if value else EMPTY_LISTS.get(field, "none")
    if value is None:
        return f"not set: {FALLBACKS[field]}" if field in FALLBACKS else "not set"
    return str(value)


def _rows(settings: Settings, flags: frozenset[str]) -> list[dict]:
    sources = setting_sources(settings, flags=flags, environ=os.environ)
    prefix = settings.model_config.get("env_prefix", "")
    return [
        {
            "field": field,
            "variable": (prefix + field).upper(),
            "flag": FLAGS.get(field),
            "value": shown_value(field, getattr(settings, field)),
            "source": sources[field],
        }
        for field in type(settings).model_fields
    ]


@router.get("/settings", response_class=HTMLResponse)
def settings(request: Request) -> HTMLResponse:
    current: Settings = request.app.state.settings
    with open_db(request) as conn:
        context = shown_context(request, conn)
        newest = newest_run(conn, context, cluster_scope=False)  # the sidebar's "scanned N ago"
    trivy = f"custom: {Path(current.trivy_path)}" if current.trivy_path else f"v{TRIVY_VERSION} (pinned)"
    ctx = {
        "now": request.app.state.clock(),
        "run": newest,
        "rows": _rows(current, request.app.state.flags),
        "files": [
            ("Database file", str(current.db_path)),
            ("Data directory", str(current.data_dir)),
            ("Cache directory", str(current.cache_dir)),
            ("Trivy", trivy),
            ("Log level", os.environ.get("KUBEDELOS_LOG_LEVEL") or "default (no access log)"),
        ],
    }
    return render(request, "settings.html", ctx)
