import sqlite3

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse

from kubedelos.web.pages import open_db, render


@pytest.fixture(autouse=True)
def _test_routes(app):
    @app.get("/_page")
    def page(request: Request):
        return render(request, "base.html", {})

    @app.get("/_db")
    def db(request: Request):
        with open_db(request) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            try:
                conn.execute("CREATE TABLE t (x)")
            except sqlite3.OperationalError as exc:
                return PlainTextResponse(f"{version} {exc}")
        return PlainTextResponse("writable")


def test_render_escapes_context(app, client):
    app.state.context = "<script>alert(1)</script>"
    html = client.get("/_page").text
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_open_db_is_read_only(client):
    response = client.get("/_db")
    assert response.status_code == 200
    version, _, error = response.text.partition(" ")
    assert int(version) > 0
    assert "readonly" in error
