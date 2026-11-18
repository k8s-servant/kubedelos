"""Tests for ``GET /healthz``: the liveness probe of ``kubedelos serve``, absent from the laptop UI."""

import os

import kubedelos.store.db


def test_healthz_ok_with_any_host(serve_client):
    response = serve_client.get("/healthz", headers={"host": "10.0.0.7:8080"})
    assert response.status_code == 200
    assert response.text == "ok"
    assert response.headers["content-type"].startswith("text/plain")
    assert "content-security-policy" in response.headers


def test_healthz_unhealthy_when_worker_dead(serve_client, worker):
    worker.running = False
    response = serve_client.get("/healthz")
    assert response.status_code == 503
    assert response.text == "unhealthy"


def test_healthz_unhealthy_when_the_database_cannot_open(serve_client, serve_app):
    os.remove(serve_app.state.settings.db_path)
    response = serve_client.get("/healthz")
    assert response.status_code == 503
    assert not serve_app.state.settings.db_path.exists()  # opened read-only: the probe never creates it


def test_healthz_opens_the_database_read_only(serve_client, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the probe must not open a writable connection")

    monkeypatch.setattr(kubedelos.store.db, "connect", refuse)
    assert serve_client.get("/healthz").status_code == 200


def test_healthz_absent_on_laptop(client):
    assert client.get("/healthz").status_code == 404
