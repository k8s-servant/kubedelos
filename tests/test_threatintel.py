import gzip
import json
import logging
import sqlite3
from datetime import UTC, date, datetime, timedelta

import httpx
import pytest

from kubedelos import __version__, threatintel
from kubedelos.config import Settings
from kubedelos.store.db import connect

NOW = datetime(2026, 11, 20, 8, 0, tzinfo=UTC)
DATED_EPSS = "https://epss.empiricalsecurity.com/epss_scores-2026-11-20.csv.gz"


def kev_body(entries=None, version="2026.11.19"):
    if entries is None:
        entries = [
            {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-10"},
            {"cveID": "CVE-2024-0002", "dateAdded": "2024-02-11"},
            {"cveID": "CVE-2023-9999", "dateAdded": "2023-12-01"},
        ]
    return json.dumps({"catalogVersion": version, "vulnerabilities": entries}).encode()


def epss_body(
    rows=None, header="cve,epss,percentile", meta="#model_version:v2025.03.14,score_date:2026-11-20T12:55:00Z"
):
    if rows is None:
        rows = ["CVE-2024-0001,0.97000,0.99900", "CVE-2024-0003,0.00100,0.10000"]
    lines = ([meta] if meta else []) + [header, *rows]
    return gzip.compress(("\n".join(lines) + "\n").encode())


class Feeds:
    """A fake KEV and EPSS server: answers the two URLs (EPSS through a redirect to its dated file) and records every
    request."""

    def __init__(self, kev=None, epss=None, *, status=200):
        self.kev = kev_body() if kev is None else kev
        self.epss = epss_body() if epss is None else epss
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url == threatintel.KEV_URL:
            return httpx.Response(self.status, content=self.kev)
        if url == threatintel.EPSS_URL:
            return httpx.Response(302, headers={"Location": DATED_EPSS})
        if url == DATED_EPSS:
            return httpx.Response(self.status, content=self.epss)
        return httpx.Response(404)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self), follow_redirects=True)


@pytest.fixture
def conn(tmp_path):
    conn = connect(tmp_path / "kubedelos.db")
    yield conn
    conn.close()


def _intel(conn):
    rows = conn.execute("SELECT vuln_id, kev, kev_added, epss, epss_percentile FROM threat_intel ORDER BY vuln_id")
    return {r[0]: tuple(r[1:]) for r in rows}


def _feeds(conn):
    return {r[0]: (r[1], r[2], r[3]) for r in conn.execute("SELECT name, fetched_at, version, rows FROM threat_feed")}


def test_refresh_stores_both_feeds(conn):
    assert threatintel.refresh(conn, Feeds().client(), NOW) == {"kev": "updated", "epss": "updated"}
    assert _intel(conn) == {
        "CVE-2023-9999": (1, "2023-12-01", None, None),
        "CVE-2024-0001": (1, "2024-01-10", 0.97, 0.999),
        "CVE-2024-0002": (1, "2024-02-11", None, None),
        "CVE-2024-0003": (0, None, 0.001, 0.1),
    }
    assert date.fromisoformat(_intel(conn)["CVE-2024-0001"][1]) == date(2024, 1, 10)
    assert _feeds(conn) == {
        "kev": (NOW.isoformat(), "2026.11.19", 3),
        "epss": (NOW.isoformat(), "2026-11-20T12:55:00Z", 2),
    }


def test_a_new_copy_replaces_the_old_one(conn):
    threatintel.refresh(conn, Feeds().client(), NOW)
    newer = Feeds(
        kev=kev_body(
            [{"cveID": "CVE-2024-0002", "dateAdded": "2024-02-11"}, {"cveID": "CVE-2024-0004", "dateAdded": None}]
        ),
        epss=epss_body(["CVE-2024-0002,0.20000,0.80000"]),
    )
    assert threatintel.refresh(conn, newer.client(), NOW + timedelta(hours=25)) == {"kev": "updated", "epss": "updated"}
    assert _intel(conn) == {"CVE-2024-0002": (1, "2024-02-11", 0.2, 0.8), "CVE-2024-0004": (1, None, None, None)}


def test_parse_epss_without_the_model_line():
    version, rows = threatintel.parse_epss(epss_body(meta=None))
    assert version is None
    assert rows == {"CVE-2024-0001": (0.97, 0.999), "CVE-2024-0003": (0.001, 0.1)}


def test_parse_kev_reads_the_version_and_dates():
    version, rows = threatintel.parse_kev(kev_body([{"cveID": "CVE-2024-0001", "dateAdded": "not a date"}]))
    assert version == "2026.11.19"
    assert rows == {"CVE-2024-0001": None}


def test_fresh_feed_is_not_downloaded(conn):
    threatintel.refresh(conn, Feeds().client(), NOW)
    again = Feeds()
    assert threatintel.refresh(conn, again.client(), NOW + timedelta(hours=23)) == {"kev": "fresh", "epss": "fresh"}
    assert again.requests == []
    assert threatintel.refresh(conn, again.client(), NOW + timedelta(hours=24)) == {
        "kev": "updated",
        "epss": "updated",
    }
    assert again.requests != []


def test_requests_carry_nothing(conn):
    feeds = Feeds()
    threatintel.refresh(conn, feeds.client(), NOW)
    assert [str(r.url) for r in feeds.requests] == [threatintel.KEV_URL, threatintel.EPSS_URL, DATED_EPSS]
    for request in feeds.requests:
        assert request.method == "GET"
        assert request.url.query == b""
        assert request.content == b""
        assert request.url.host in {"www.cisa.gov", "epss.empiricalsecurity.com"}


def test_refresh_feeds_builds_a_client_with_the_user_agent(tmp_path, monkeypatch):
    feeds = Feeds()
    built = {}
    real_client = httpx.Client

    def client(**kwargs):
        built.update(kwargs)
        return real_client(transport=httpx.MockTransport(feeds), **kwargs)

    monkeypatch.setattr(threatintel.httpx, "Client", client)
    settings = Settings(data_dir=tmp_path / "data", threat_feeds=True)
    assert threatintel.refresh_feeds(settings, now=NOW) == {"kev": "updated", "epss": "updated"}
    assert built["follow_redirects"] is True
    assert built["timeout"].connect == 10 and built["timeout"].read == 30
    assert {r.headers["user-agent"] for r in feeds.requests} == {f"kubedelos/{__version__}"}


def test_refresh_feeds_uses_the_given_client_and_settings_db(tmp_path):
    settings = Settings(data_dir=tmp_path / "data", threat_feeds=True)
    assert threatintel.refresh_feeds(settings, client=Feeds().client(), now=NOW) == {
        "kev": "updated",
        "epss": "updated",
    }
    conn = connect(settings.db_path)
    assert len(_intel(conn)) == 4
    conn.close()


BROKEN = {
    "truncated gzip": ("epss", Feeds(epss=epss_body()[:-12])),
    "html with status 200": ("kev", Feeds(kev=b"<html><body>maintenance</body></html>")),
    "kev with no vulnerabilities": ("kev", Feeds(kev=kev_body([]))),
    "epss with a wrong header": ("epss", Feeds(epss=epss_body(header="id,score,rank"))),
    "status 503": ("both", Feeds(status=503)),
    "over MAX_DOWNLOAD": ("both", Feeds(kev=b"x" * 1025, epss=epss_body() + b"x" * 1025)),
}


@pytest.mark.parametrize("case", list(BROKEN))
def test_broken_download_keeps_the_last_copy(conn, case, caplog, monkeypatch):
    which, feeds = BROKEN[case]
    threatintel.refresh(conn, Feeds().client(), NOW)
    if case == "over MAX_DOWNLOAD":
        monkeypatch.setattr(threatintel, "MAX_DOWNLOAD", 1024)  # the real limit is 32 MiB
    before_intel, before_feeds = _intel(conn), _feeds(conn)
    later = NOW + timedelta(days=2)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        result = threatintel.refresh(conn, feeds.client(), later)
    failed = {"kev", "epss"} if which == "both" else {which}
    assert {name for name, status in result.items() if status == "failed"} == failed
    assert {name for name, status in result.items() if status != "failed"} == {"kev", "epss"} - failed
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == len(failed)
    assert all(r.getMessage().startswith("threat feed ") and " not updated: " in r.getMessage() for r in warnings)
    assert _intel(conn) == before_intel  # a feed that did update got the same body again
    for name in failed:
        assert _feeds(conn)[name] == before_feeds[name]


def test_invalid_rows_are_skipped(conn):
    kev = kev_body(
        [
            {"cveID": "GHSA-xxxx-yyyy-zzzz", "dateAdded": "2024-01-01"},
            {"cveID": "cve-2024-1", "dateAdded": "2024-01-01"},
            {"cveID": "cve-2024-12345", "dateAdded": "2024-03-03"},
            {"cveID": 42},
            "not an object",
        ]
    )
    epss = epss_body(
        [
            "GHSA-xxxx-yyyy-zzzz,0.5,0.5",
            "CVE-2024-0005,1.5,0.9",
            "CVE-2024-0006,nan,0.9",
            "CVE-2024-0007,high,0.9",
            "CVE-2024-0008,0.3",
            "cve-2024-12345,0.25000,0.75000",
        ]
    )
    assert threatintel.refresh(conn, Feeds(kev=kev, epss=epss).client(), NOW) == {"kev": "updated", "epss": "updated"}
    assert _intel(conn) == {"CVE-2024-12345": (1, "2024-03-03", 0.25, 0.75)}
    assert _feeds(conn)["kev"][2] == 1 and _feeds(conn)["epss"][2] == 1


def test_unreachable_host_fails_softly(conn, caplog):
    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(transport=httpx.MockTransport(refuse), follow_redirects=True)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        assert threatintel.refresh(conn, client, NOW) == {"kev": "failed", "epss": "failed"}
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 2
    assert _feeds(conn) == {}


def test_concurrent_refresh_stores_once(tmp_path):
    """The second refresh reads a stale feed, and the first stores while the second downloads: under the write lock
    the second finds the feed fresh and stores nothing."""
    first = connect(tmp_path / "kubedelos.db")
    second = connect(tmp_path / "kubedelos.db")
    first_feeds = Feeds()
    stored: list[dict] = []
    second_feeds = Feeds(kev=kev_body([{"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01"}]))

    def racing(request):
        if not stored:
            stored.append(threatintel.refresh(first, first_feeds.client(), NOW))
        return second_feeds(request)

    client = httpx.Client(transport=httpx.MockTransport(racing), follow_redirects=True)
    try:
        result = threatintel.refresh(second, client, NOW + timedelta(minutes=1))
        assert stored == [{"kev": "updated", "epss": "updated"}]
        assert result == {"kev": "fresh", "epss": "fresh"}
        assert {name: row[0] for name, row in _feeds(second).items()} == {
            "kev": NOW.isoformat(),
            "epss": NOW.isoformat(),
        }
        assert "CVE-2025-0001" not in _intel(second)
        assert len(first_feeds.requests) == 3  # KEV, EPSS and its redirect: one download each
    finally:
        first.close()
        second.close()


def test_store_holds_no_lock_after_a_refresh(conn, tmp_path):
    threatintel.refresh(conn, Feeds().client(), NOW)
    other = sqlite3.connect(tmp_path / "kubedelos.db", timeout=0)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")
    finally:
        other.close()


def test_refresh_feeds_off(tmp_path, monkeypatch):
    def no_client(*args, **kwargs):
        raise AssertionError("a client was built with the feeds off")

    monkeypatch.setattr(threatintel.httpx, "Client", no_client)
    settings = Settings(data_dir=tmp_path / "data")
    assert settings.threat_feeds is False  # the autouse fixture
    assert threatintel.refresh_feeds(settings) is None
    assert threatintel.refresh_in_background(settings) is None
    assert not (tmp_path / "data").exists()


def test_refresh_feeds_never_raises(tmp_path, monkeypatch, caplog):
    def broken_connect(path):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(threatintel.db, "connect", broken_connect)
    settings = Settings(data_dir=tmp_path / "data", threat_feeds=True)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        assert threatintel.refresh_feeds(settings, client=Feeds().client(), now=NOW) == {
            "kev": "failed",
            "epss": "failed",
        }
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 2


def test_refresh_in_background_runs_a_daemon_thread(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(threatintel, "refresh_feeds", lambda settings: calls.append(settings))
    settings = Settings(data_dir=tmp_path / "data", threat_feeds=True)
    thread = threatintel.refresh_in_background(settings)
    assert thread is not None and thread.daemon
    thread.join(5)
    assert calls == [settings]


def _kev(n):
    return kev_body([{"cveID": f"CVE-2024-{i:04d}", "dateAdded": "2024-01-01"} for i in range(1, n + 1)])


def test_a_feed_that_shrank_sharply_is_refused(conn, caplog):
    threatintel.refresh(conn, Feeds(kev=_kev(4)).client(), NOW)
    before_intel, before_feeds = _intel(conn), _feeds(conn)
    later = NOW + timedelta(days=2)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        assert threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), later)["kev"] == "failed"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and warnings[0].startswith("threat feed kev not updated: ")
    assert _intel(conn) == before_intel and _feeds(conn)["kev"] == before_feeds["kev"]
    assert threatintel.refresh(conn, Feeds(kev=_kev(3)).client(), later)["kev"] == "updated"  # at least half
    assert _feeds(conn)["kev"] == (later.isoformat(), "2026.11.19", 3)


def test_a_first_copy_has_no_floor(conn):
    assert threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), NOW)["kev"] == "updated"


def test_epss_decompressed_size_is_bounded(monkeypatch):
    assert threatintel.MAX_EPSS_CSV == 64 * 2**20
    monkeypatch.setattr(threatintel, "MAX_EPSS_CSV", 64)
    with pytest.raises(threatintel.FeedError, match="decompressed"):
        threatintel.parse_epss(epss_body(["CVE-2024-0001,0.5,0.5"] * 10))


def test_feed_rows_are_bounded(monkeypatch):
    assert threatintel.MAX_FEED_ROWS == 2_000_000
    monkeypatch.setattr(threatintel, "MAX_FEED_ROWS", 2)
    with pytest.raises(threatintel.FeedError, match="rows"):
        threatintel.parse_kev(_kev(3))
    with pytest.raises(threatintel.FeedError, match="rows"):
        threatintel.parse_epss(epss_body([f"CVE-2024-{i:04d},0.5,0.5" for i in range(1, 4)]))
    assert len(threatintel.parse_kev(_kev(2))[1]) == 2


def test_a_shrunk_feed_is_accepted_once_the_old_copy_is_a_week_old(conn):
    threatintel.refresh(conn, Feeds(kev=_kev(4)).client(), NOW)
    assert threatintel.SHRINK_GRACE == 7 * threatintel.MAX_AGE
    within = NOW + timedelta(days=7) - timedelta(minutes=1)
    assert threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), within)["kev"] == "failed"
    assert _feeds(conn)["kev"] == (NOW.isoformat(), "2026.11.19", 4)
    after = NOW + timedelta(days=7, minutes=1)
    assert threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), after)["kev"] == "updated"
    assert _feeds(conn)["kev"] == (after.isoformat(), "2026.11.19", 1)


def test_accepting_a_shrunk_feed_after_the_grace_is_logged(conn, caplog):
    threatintel.refresh(conn, Feeds(kev=_kev(4)).client(), NOW)
    after = NOW + timedelta(days=8)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        assert threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), after)["kev"] == "updated"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == ["threat feed kev shrank from 4 to 1 rows; accepted because the stored copy is 8 days old"]


def test_the_refusal_says_the_old_copy_is_kept_for_a_week(conn, caplog):
    threatintel.refresh(conn, Feeds(kev=_kev(4)).client(), NOW)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        threatintel.refresh(conn, Feeds(kev=_kev(1)).client(), NOW + timedelta(days=2))
    assert "kept until it is older than 7 days" in caplog.records[-1].getMessage()


def test_a_redirect_that_leaves_https_is_refused(conn, caplog):
    threatintel.refresh(conn, Feeds().client(), NOW)
    before_intel, before_feeds = _intel(conn), _feeds(conn)
    plain = "http://example.com/kev.json"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if str(request.url) == threatintel.KEV_URL:
            return httpx.Response(302, headers={"Location": plain})
        return httpx.Response(200, content=kev_body())

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    later = NOW + timedelta(days=2)
    with caplog.at_level(logging.WARNING, logger="kubedelos.threatintel"):
        assert threatintel.refresh(conn, client, later)["kev"] == "failed"
    assert plain not in seen
    kev_warnings = [r.getMessage() for r in caplog.records if r.getMessage().startswith("threat feed kev ")]
    assert len(kev_warnings) == 1 and "https" in kev_warnings[0]
    assert _intel(conn) == before_intel and _feeds(conn)["kev"] == before_feeds["kev"]
