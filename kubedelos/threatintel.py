"""The threat feeds behind the risk score: CISA KEV (known exploited) and EPSS (likelihood of exploitation).

Each feed is downloaded at most once every ``MAX_AGE`` and stored in ``threat_intel`` (one row per CVE) and
``threat_feed`` (when it was fetched, its version and row count). These are the only requests kubedelos makes besides
Trivy's and the registries': a plain GET to each fixed URL, with no query string, no body and nothing about the
cluster. ``KUBEDELOS_THREAT_FEEDS=false`` turns them off.

A feed never fails a scan or the UI start. A download that is too large, an HTTP error, or a body that is not the
feed (no valid row, too many rows, a wrong header, broken JSON or gzip, or fewer than half the rows of a stored
copy younger than ``SHRINK_GRACE``) is logged as one warning and the last stored copy is kept.
Storing is one ``BEGIN IMMEDIATE`` transaction that checks freshness again under the lock, so two processes that
refresh at once store the feed once.
"""

import gzip
import io
import json
import logging
import math
import re
import sqlite3
import threading
import zlib
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import httpx

from kubedelos import __version__
from kubedelos.config import Settings
from kubedelos.store import db
from kubedelos.store.queue import write_lock

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# EPSS moved from epss.cyentia.com in 2025 (the old host 301-redirects here); this URL 302s to the dated file.
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_AGE = timedelta(hours=24)
# How long a sharply smaller copy is refused: after that the old copy is replaced anyway, so a feed that really did
# lose half its rows heals itself instead of being refused for ever.
SHRINK_GRACE = 7 * MAX_AGE
MAX_DOWNLOAD = 32 * 2**20
MAX_EPSS_CSV = 64 * 2**20  # decompressed; the real file is about 10 MB
MAX_FEED_ROWS = 2_000_000  # per feed; EPSS had about 409,000 rows and KEV about 1,800 in November 2026
FEEDS = ("kev", "epss")

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_EPSS_HEADER = "cve,epss,percentile"
_LINE_LIMIT = 4096  # an EPSS row is about 40 bytes; a longer line is read in pieces, each an invalid row

logger = logging.getLogger(__name__)


class FeedError(Exception):
    """A download that is not a usable copy of the feed."""


def _cve(value: object) -> str | None:
    """The id uppercased, if it is a CVE id; GHSA and other ids are not scored from the feeds."""
    if not isinstance(value, str):
        return None
    value = value.strip().upper()
    return value if _CVE.fullmatch(value) else None


def _date(value: object) -> date | None:
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def parse_kev(body: bytes) -> tuple[str | None, dict[str, date | None]]:
    """The KEV catalog's ``catalogVersion`` and ``{cveID: dateAdded}`` for its valid entries."""
    try:
        catalog = json.loads(body)
    except ValueError as exc:  # UnicodeDecodeError is a ValueError too
        raise FeedError("not JSON") from exc
    entries = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
    if not isinstance(entries, list):
        raise FeedError("no vulnerabilities list")
    rows: dict[str, date | None] = {}
    for entry in entries:
        if isinstance(entry, dict) and (cve := _cve(entry.get("cveID"))):
            rows[cve] = _date(entry.get("dateAdded"))
            _check_rows(rows)
    if not rows:
        raise FeedError("no valid entry")
    version = catalog.get("catalogVersion")
    return (version if isinstance(version, str) else None), rows


def _check_rows(rows: dict) -> None:
    if len(rows) > MAX_FEED_ROWS:
        raise FeedError(f"more than {MAX_FEED_ROWS} rows")


def _probability(text: str) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) and 0.0 <= value <= 1.0 else None


def _lines(body: bytes) -> Iterator[str]:
    """The decompressed lines of a gzip body, stopping with ``FeedError`` past ``MAX_EPSS_CSV`` bytes."""
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as unzipped:
            while line := unzipped.readline(_LINE_LIMIT):
                total += len(line)
                if total > MAX_EPSS_CSV:
                    raise FeedError(f"more than {MAX_EPSS_CSV} bytes decompressed")
                yield line.decode("utf-8", errors="replace").strip()
    except (OSError, EOFError, zlib.error) as exc:  # BadGzipFile is an OSError; a truncated file raises EOFError
        raise FeedError(f"broken gzip: {exc}") from exc


def parse_epss(body: bytes) -> tuple[str | None, dict[str, tuple[float, float]]]:
    """The EPSS ``score_date`` (from the optional ``#model_version:…,score_date:…`` line) and ``{cve: (epss,
    percentile)}`` for its valid rows."""
    lines = _lines(body)
    first = next(lines, "")
    version = None
    if first.startswith("#"):
        meta = dict(part.partition(":")[::2] for part in first[1:].split(","))
        version = meta.get("score_date") or None
        first = next(lines, "")
    if first.lower() != _EPSS_HEADER:
        raise FeedError("unexpected header")
    rows: dict[str, tuple[float, float]] = {}
    for line in lines:
        fields = line.split(",")
        if len(fields) != 3 or not (cve := _cve(fields[0])):
            continue
        epss, percentile = _probability(fields[1]), _probability(fields[2])
        if epss is not None and percentile is not None:
            rows[cve] = (epss, percentile)
            _check_rows(rows)
    if not rows:
        raise FeedError("no valid row")
    return version, rows


def _download(client: httpx.Client, url: str) -> bytes:
    """The body at ``url``, streamed and cut off past ``MAX_DOWNLOAD`` bytes."""
    with client.stream("GET", url) as response:
        if response.status_code >= 400:
            raise FeedError(f"HTTP {response.status_code}")
        chunks, size = [], 0
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > MAX_DOWNLOAD:
                raise FeedError(f"more than {MAX_DOWNLOAD} bytes")
            chunks.append(chunk)
    return b"".join(chunks)


def _is_fresh(conn: sqlite3.Connection, name: str, now: datetime) -> bool:
    row = conn.execute("SELECT fetched_at FROM threat_feed WHERE name = ?", (name,)).fetchone()
    if row is None:
        return False
    # A copy from the future (the clock went back) is not fresh, so it is replaced rather than kept for ever.
    return timedelta(0) <= now - datetime.fromisoformat(row[0]) < MAX_AGE


def _store_kev(conn: sqlite3.Connection, rows: dict[str, date | None]) -> None:
    conn.execute("UPDATE threat_intel SET kev = 0, kev_added = NULL WHERE kev != 0 OR kev_added IS NOT NULL")
    conn.executemany(
        "INSERT INTO threat_intel (vuln_id, kev, kev_added) VALUES (?, 1, ?)"
        " ON CONFLICT (vuln_id) DO UPDATE SET kev = 1, kev_added = excluded.kev_added",
        ((cve, added.isoformat() if added else None) for cve, added in rows.items()),
    )


def _store_epss(conn: sqlite3.Connection, rows: dict[str, tuple[float, float]]) -> None:
    conn.execute("UPDATE threat_intel SET epss = NULL, epss_percentile = NULL WHERE epss IS NOT NULL")
    conn.executemany(
        "INSERT INTO threat_intel (vuln_id, epss, epss_percentile) VALUES (?, ?, ?)"
        " ON CONFLICT (vuln_id) DO UPDATE SET epss = excluded.epss, epss_percentile = excluded.epss_percentile",
        ((cve, epss, percentile) for cve, (epss, percentile) in rows.items()),
    )


# Per feed: its URL, its parser and the function that writes its columns.
_FETCH = {"kev": (KEV_URL, parse_kev, _store_kev), "epss": (EPSS_URL, parse_epss, _store_epss)}


def _store(conn: sqlite3.Connection, name: str, version: str | None, rows: dict, now: datetime) -> bool:
    """Replace the stored copy of feed ``name`` in one transaction; False if another refresh stored it meanwhile.

    A copy with fewer than half the rows of the stored one is refused while the stored one is younger than
    ``SHRINK_GRACE``: a feed does not lose half its CVEs in a day, so it is more likely broken or cut short, and storing
    it would drop real KEV and EPSS marks. Past that, the smaller copy is taken as the feed's real new size.
    """
    with write_lock(conn):
        if _is_fresh(conn, name, now):
            return False
        stored = conn.execute("SELECT rows, fetched_at FROM threat_feed WHERE name = ?", (name,)).fetchone()
        if stored is not None and len(rows) * 2 < stored[0]:
            age = now - datetime.fromisoformat(stored[1])
            if age < SHRINK_GRACE:
                raise FeedError(
                    f"{len(rows)} rows, fewer than half of the stored {stored[0]}; the old copy is kept until it is"
                    f" older than {SHRINK_GRACE.days} days"
                )
            logger.warning(
                "threat feed %s shrank from %d to %d rows; accepted because the stored copy is %d days old",
                name,
                stored[0],
                len(rows),
                age.days,
            )
        _FETCH[name][2](conn, rows)
        conn.execute("DELETE FROM threat_intel WHERE kev = 0 AND epss IS NULL")
        conn.execute(
            "INSERT INTO threat_feed (name, fetched_at, version, rows) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (name) DO UPDATE SET fetched_at = excluded.fetched_at, version = excluded.version,"
            " rows = excluded.rows",
            (name, now.isoformat(), version, len(rows)),
        )
    return True


def refresh(conn: sqlite3.Connection, client: httpx.Client, now: datetime) -> dict[str, str]:
    """Download each stale feed and store it: per feed ``"fresh"`` (skipped), ``"updated"`` or ``"failed"``."""
    results: dict[str, str] = {}
    for name in FEEDS:
        try:
            if _is_fresh(conn, name, now):
                results[name] = "fresh"
                continue
            url, parse, _ = _FETCH[name]
            version, rows = parse(_download(client, url))
            results[name] = "updated" if _store(conn, name, version, rows, now) else "fresh"
        except Exception as exc:  # a feed never fails its caller; the old copy stays
            logger.warning("threat feed %s not updated: %s", name, exc)
            results[name] = "failed"
    return results


def refresh_feeds(
    settings: Settings, *, client: httpx.Client | None = None, now: datetime | None = None
) -> dict[str, str] | None:
    """Refresh the feeds in ``settings.db_path``, or return None when ``threat_feeds`` is off. Never raises for a
    feed. A client is built unless one is given; each is closed by whoever made it."""
    if not settings.threat_feeds:
        return None
    now = now if now is not None else datetime.now(UTC)
    try:
        conn = db.connect(settings.db_path)
    except Exception as exc:
        for name in FEEDS:
            logger.warning("threat feed %s not updated: %s", name, exc)
        return dict.fromkeys(FEEDS, "failed")
    own = client is None
    if client is None:
        client = httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"User-Agent": f"kubedelos/{__version__}"},
        )
    try:
        return refresh(conn, client, now)
    finally:
        if own:
            client.close()
        conn.close()


def _refresh_quietly(settings: Settings) -> None:
    try:
        refresh_feeds(settings)
    except Exception as exc:  # refresh_feeds logs per feed; this is the last guard of a thread nobody joins
        logger.warning("threat feeds not updated: %s", exc)


def refresh_in_background(settings: Settings) -> threading.Thread | None:
    """Refresh the feeds on a daemon thread, so the UI starts at once; None when ``threat_feeds`` is off."""
    if not settings.threat_feeds:
        return None
    thread = threading.Thread(target=_refresh_quietly, args=(settings,), name="kubedelos-threat-feeds", daemon=True)
    thread.start()
    return thread
