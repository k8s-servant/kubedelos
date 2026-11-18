"""Shared fixtures for the web UI tests: a migrated database, a seeding Repo, a logged-in TestClient and clients of
the ``kubedelos serve`` app (with fakes for its queue worker and sweeper), writable or read-only."""

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from kubedelos.config import Settings
from kubedelos.store.db import connect
from kubedelos.store.repo import Repo
from kubedelos.web.app import create_app, create_serve_app
from kubedelos.web.jobs import ScanRunner
from kubedelos.web.security import ServeGuard

TOKEN = "startup-token-for-tests"  # distinctive, so the access-log test can search for it
PORT = 9370
BASE_URL = f"http://127.0.0.1:{PORT}"
CONTEXT = "my-cluster"
SERVE_HOST = "example.com"
NEXT_SWEEP = datetime(2026, 1, 2, 3, 0, tzinfo=UTC)
SERVE_ORIGIN = "https://kubedelos.example.com"
IDENTITY_HEADER = "X-Auth-Request-Email"


class Clock:
    """Deterministic time: starts at a fixed instant and moves one minute per call, so runs keep their order."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)
        self.step = timedelta(minutes=1)  # a test that sets ``now`` to an exact instant sets this to zero

    def __call__(self) -> datetime:
        self.now += self.step
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
def kube_contexts():
    """The context names the test kubeconfig holds; a test may change the list, and the app reads it on each page."""
    return [CONTEXT]


@pytest.fixture
def app(seed, kube_contexts):
    connect(seed.settings.db_path).close()  # create and migrate first, as `kubedelos ui` does at startup
    return create_app(
        seed.settings,
        context=seed.context,
        token=TOKEN,
        port=PORT,
        clock=seed.clock,
        list_contexts=lambda: list(kube_contexts),
    )


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


class FakeWorker:
    """The queue worker as the serve app sees it: whether its thread is alive, and how often a route woke it."""

    def __init__(self) -> None:
        self.running = True
        self.woken = 0

    def alive(self) -> bool:
        return self.running

    def wake(self) -> None:
        self.woken += 1


class FakeSweeper:
    """The sweep scheduler as the serve app sees it: the next fire time (None with sweeps off) and stop."""

    def __init__(self) -> None:
        self.next = NEXT_SWEEP

    def next_run(self) -> datetime | None:
        return self.next

    def stop(self) -> None:
        pass


@pytest.fixture
def worker():
    return FakeWorker()


@pytest.fixture
def sweeper():
    return FakeSweeper()


def build_serve_app(
    seed, worker, sweeper, allowed_hosts=(SERVE_HOST,), *, read_only=False, trust_proxy_headers=False, **configured
):
    """The serve app over the seed's database, storing runs under ``my-cluster`` and answering ``allowed_hosts``;
    ``configured`` sets more of its Settings (``namespaces=["web"]``, say)."""
    connect(seed.settings.db_path).close()  # create and migrate first, as `kubedelos serve` does at startup
    settings = Settings(
        data_dir=seed.settings.data_dir,
        cluster_name=CONTEXT,
        allowed_hosts=list(allowed_hosts),
        read_only=read_only,
        trust_proxy_headers=trust_proxy_headers,
        **configured,
    )
    runner = ScanRunner(settings, CONTEXT, clock=seed.clock, fixed_cluster=True)
    return create_serve_app(settings, runner=runner, worker=worker, sweeper=sweeper, clock=seed.clock)


@pytest.fixture
def serve_app(seed, worker, sweeper):
    return build_serve_app(seed, worker, sweeper)


@pytest.fixture
def serve_client(serve_app):
    """A client of the writable serve app with default settings; it needs no session, only an allowed Host."""
    with TestClient(serve_app, base_url=f"http://{SERVE_HOST}") as client:
        yield client


@pytest.fixture
def make_serve_client(seed, worker, sweeper):
    """A factory of serve clients, each over its own app: ``make_serve_client(read_only=True)`` and so on; other
    keywords set the app's Settings. The client's base URL is the first allowed host, and every client is closed when
    the test ends."""
    with contextlib.ExitStack() as stack:

        def make(*, read_only=False, trust_proxy_headers=False, allowed_hosts=(SERVE_HOST,), **configured):
            app = build_serve_app(
                seed,
                worker,
                sweeper,
                allowed_hosts,
                read_only=read_only,
                trust_proxy_headers=trust_proxy_headers,
                **configured,
            )
            return stack.enter_context(TestClient(app, base_url=f"http://{allowed_hosts[0]}"))

        yield make


def serve_cookie(client) -> str:
    """The CSRF cookie the serve client holds, getting one first if it has none."""
    if client.cookies.get(ServeGuard.CSRF_COOKIE) is None:
        assert client.get("/scans").status_code == 200
    return client.cookies.get(ServeGuard.CSRF_COOKIE)


def serve_token(client, identity=None) -> str:
    return client.app.state.serve_guard.csrf_token(serve_cookie(client), identity)


def serve_headers(identity=None, origin=SERVE_ORIGIN) -> dict:
    headers = {"origin": origin}
    if identity is not None:
        headers[IDENTITY_HEADER] = identity
    return headers


def signed_post(client, path, data, identity=None, origin=None):
    """POST ``data`` to ``path`` with the cookie and the matching CSRF token, as the page's form would. The Origin is
    ``https://`` plus the client's host unless ``origin`` names another."""
    data = {**data, "csrf_token": serve_token(client, identity)}
    origin = origin or f"https://{client.base_url.host}"
    return client.post(path, data=data, headers=serve_headers(identity, origin), follow_redirects=False)
