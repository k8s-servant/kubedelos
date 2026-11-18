"""``GET /healthz``: the liveness and readiness probe of ``kubedelos serve``.

Healthy means the queue worker's thread is alive (without it no scan would ever start) and the scan database opens
read-only. The probe never writes and never creates the database. The laptop UI has no probe, so there the route is a
plain 404; the serve middleware lets this one path through whatever the Host header says, since the kubelet probes by
pod IP.
"""

import sqlite3

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse

from kubedelos.web.pages import open_db
from kubedelos.web.security import HEALTH_PATH

router = APIRouter()


@router.get(HEALTH_PATH, response_class=PlainTextResponse)
def healthz(request: Request) -> PlainTextResponse:
    if not request.app.state.serve:
        raise HTTPException(status_code=404)
    try:
        with open_db(request) as conn:
            conn.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        return PlainTextResponse("unhealthy", status_code=503)
    if not request.app.state.worker.alive():
        return PlainTextResponse("unhealthy", status_code=503)
    return PlainTextResponse("ok")
