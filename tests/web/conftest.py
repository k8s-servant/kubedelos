"""Shared fixtures for the web UI tests: a migrated database, a seeding Repo and a logged-in TestClient."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from kubedelos.config import Settings
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from kubedelos.web.app import create_app

TOKEN = "startup-token-for-tests"  # distinctive, so the access-log test can search for it
PORT = 9370
BASE_URL = f"http://127.0.0.1:{PORT}"
CONTEXT = "my-cluster"


class Clock:
    """Deterministic time: starts at a fixed instant and moves one minute per call, so runs keep their order."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(minutes=1)
        return self.now


@dataclass
class Seed:
    repo: Repo
    settings: Settings
    context: str
    clock: Clock


@pytest.fixture
def token():
    return TOKEN


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture
def seed(settings):
    conn = connect(settings.db_path)
    clock = Clock()
    yield Seed(repo=Repo(conn, clock=clock), settings=settings, context=CONTEXT, clock=clock)
    conn.close()


@pytest.fixture
def app(seed):
    connect(seed.settings.db_path).close()  # create and migrate first, as `kubedelos ui` does at startup
    return create_app(seed.settings, context=seed.context, token=TOKEN, port=PORT, clock=seed.clock)


@pytest.fixture
def anon(app):
    """A client with no session cookie."""
    with TestClient(app, base_url=BASE_URL) as client:
        yield client


@pytest.fixture
def client(app):
    """A client that has opened the startup URL, so its cookie jar holds a session."""
    with TestClient(app, base_url=BASE_URL) as client:
        response = client.get(f"/?token={TOKEN}", follow_redirects=False)
        assert response.status_code == 303
        yield client
