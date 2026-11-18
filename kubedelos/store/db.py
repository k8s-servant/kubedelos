"""Connection setup and schema migrations."""

import os
import sqlite3
import time
from pathlib import Path

_BUSY_TIMEOUT_MS = 5000

# Each script moves the schema one version forward; PRAGMA user_version is the count applied.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE scan_run (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL CHECK (status IN ('running', 'ok', 'partial', 'cancelled', 'failed')),
        context TEXT,
        trigger TEXT,
        trivy_version TEXT,
        images_total INTEGER,
        images_error INTEGER
    );
    CREATE TABLE image_result (
        id INTEGER PRIMARY KEY,
        run_id INTEGER NOT NULL REFERENCES scan_run(id),
        image_key TEXT NOT NULL,
        ref TEXT NOT NULL,
        repo TEXT,
        tag TEXT,
        digest TEXT,
        platform TEXT,
        status TEXT NOT NULL,
        error_kind TEXT,
        error TEXT,
        os_family TEXT
    );
    CREATE TABLE workload (
        id INTEGER PRIMARY KEY,
        image_result_id INTEGER NOT NULL REFERENCES image_result(id),
        namespace TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT NOT NULL,
        container TEXT NOT NULL,
        owner TEXT,
        team TEXT
    );
    CREATE TABLE finding (
        id INTEGER PRIMARY KEY,
        image_result_id INTEGER NOT NULL REFERENCES image_result(id),
        vuln_id TEXT NOT NULL,
        pkg_name TEXT,
        installed_version TEXT,
        fixed_version TEXT,
        severity TEXT NOT NULL,
        title TEXT,
        primary_url TEXT,
        target TEXT,
        pkg_type TEXT
    );
    CREATE TABLE image_cache (
        image_key TEXT NOT NULL,
        platform TEXT NOT NULL,
        trivy_db_version TEXT,
        scanned_at TEXT NOT NULL,
        report_json BLOB NOT NULL,
        PRIMARY KEY (image_key, platform)
    );
    CREATE INDEX idx_finding_severity ON finding(severity);
    CREATE INDEX idx_finding_image_result ON finding(image_result_id);
    CREATE INDEX idx_image_result_run ON image_result(run_id);
    CREATE INDEX idx_workload_namespace ON workload(namespace);
    CREATE INDEX idx_workload_image_result ON workload(image_result_id);
    """,
    # 2: the scan level (Trivy --pkg-types). Old cache rows have no level, so they are dropped rather than guessed:
    # an OS-only result served to an os,library run would read as "no library vulnerabilities". Runs and findings stay.
    """
    ALTER TABLE scan_run ADD COLUMN pkg_types TEXT;
    ALTER TABLE finding ADD COLUMN pkg_class TEXT;
    DROP TABLE image_cache;
    CREATE TABLE image_cache (
        image_key TEXT NOT NULL,
        platform TEXT NOT NULL,
        scan_level TEXT NOT NULL,
        trivy_db_version TEXT,
        scanned_at TEXT NOT NULL,
        report_json BLOB NOT NULL,
        PRIMARY KEY (image_key, platform, scan_level)
    );
    """,
    # 3: what each run covered (namespaces, selectors, exclusions) as canonical JSON, so runs compare like with like.
    """
    ALTER TABLE scan_run ADD COLUMN scope TEXT;
    """,
    # 4: the inventory warnings of each run, so a reader can tell a run that could not see everything.
    """
    CREATE TABLE run_warning (
        id INTEGER PRIMARY KEY,
        run_id INTEGER NOT NULL REFERENCES scan_run(id),
        text TEXT NOT NULL,
        coverage INTEGER NOT NULL CHECK (coverage IN (0, 1))
    );
    CREATE INDEX idx_run_warning_run ON run_warning(run_id);
    """,
    # 5: the indexes the UI's reads need on a large database. idx_finding_unit holds every column the unit counts,
    # the fix lists and the findings filter read, keyed by image row then the unit key, so a run's units are read from
    # the index alone and a page's rows are found by (image row, CVE). It replaces idx_finding_image_result (its prefix)
    # and idx_finding_severity, which led the planner to read the Critical/High rows of every run in the database.
    """
    CREATE INDEX idx_scan_run_context ON scan_run(context, status, id);
    CREATE INDEX idx_finding_vuln ON finding(vuln_id);
    CREATE INDEX idx_finding_unit
        ON finding(image_result_id, vuln_id, pkg_name, installed_version, severity, fixed_version, pkg_class);
    DROP INDEX idx_finding_image_result;
    DROP INDEX idx_finding_severity;
    """,
    # 6: the token of the process that owns a running run (kubedelos.store.runlock), so a stale "running" row can be
    # told from a scan still going on in another terminal. Rows from before this migration have no owner.
    """
    ALTER TABLE scan_run ADD COLUMN owner TEXT;
    """,
    # 7: accepted risk (kubedelos.store.accepted). Matched on read, so a revoke or an expiry takes effect at once. A NULL
    # context means all clusters; a NULL namespace, repo or package means anywhere. Dates are ISO text.
    """
    CREATE TABLE acceptance (
        id INTEGER PRIMARY KEY,
        vuln_id TEXT NOT NULL,
        context TEXT,
        namespace TEXT,
        repo TEXT,
        pkg_name TEXT,
        reason TEXT NOT NULL,
        owner TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        revoked_at TEXT
    );
    CREATE INDEX idx_acceptance_vuln ON acceptance(vuln_id);
    """,
    # 8: each run's number within its context (1, 2, 3, ...), which the UI shows; the id stays the key and stays in
    # URLs. Stored, not counted on read, so a run keeps its number when older runs are deleted. A unique index treats
    # NULLs as distinct, so runs with no context get their own partial index.
    """
    ALTER TABLE scan_run ADD COLUMN number INTEGER;
    UPDATE scan_run SET number = (
        SELECT n FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY context ORDER BY id) AS n FROM scan_run) o
        WHERE o.id = scan_run.id
    );
    CREATE UNIQUE INDEX idx_scan_run_number ON scan_run(context, number);
    CREATE UNIQUE INDEX idx_scan_run_number_no_context ON scan_run(number) WHERE context IS NULL;
    """,
    # 9: how long each image's scan took (seconds, retry included), so the UI can show where a run's time went. NULL
    # for cached results and for rows scanned before this migration.
    """
    ALTER TABLE image_result ADD COLUMN duration_s REAL;
    """,
    # 10: who asked for each run (NULL for the CLI and the schedule), and the queue of scan requests that kubedelos
    # serve works through one at a time.
    """
    ALTER TABLE scan_run ADD COLUMN requested_by TEXT;
    CREATE TABLE scan_request (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('scan', 'retry')),
        trigger TEXT NOT NULL CHECK (trigger IN ('schedule', 'ui')),
        requested_by TEXT,
        requested_at TEXT NOT NULL,
        target_run_id INTEGER REFERENCES scan_run(id),
        overrides TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('queued', 'started', 'cancelled')),
        run_id INTEGER REFERENCES scan_run(id)
    );
    CREATE INDEX idx_scan_request_state ON scan_request(state, id);
    """,
]


def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version >= len(MIGRATIONS):
        return
    # Another kubedelos process may be migrating the same file. Take the write lock first and read the version under
    # it, so a migration the other process just applied is skipped instead of run twice. In the default (legacy)
    # transaction mode, executescript() would commit that transaction before it runs; autocommit=True leaves it open.
    # user_version is transactional in SQLite, so a failed script leaves the version untouched. The version only
    # grows, so the one read above is a safe place to start.
    autocommit, conn.autocommit = conn.autocommit, True
    try:
        for index in range(version, len(MIGRATIONS)):
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("PRAGMA user_version").fetchone()[0] > index:
                conn.execute("COMMIT")
                continue
            conn.executescript(f"{MIGRATIONS[index]}\nPRAGMA user_version = {index + 1};")
            conn.execute("COMMIT")
    except sqlite3.Error:
        if conn.in_transaction:
            conn.execute("ROLLBACK")  # rollback() does nothing while autocommit is True
        raise
    finally:
        conn.autocommit = autocommit


def _use_wal(conn: sqlite3.Connection) -> None:
    # Switching a new file to WAL needs an exclusive lock, and SQLite fails at once instead of waiting busy_timeout for
    # it. Another kubedelos process opening the same new file at the same moment holds it briefly, so retry.
    deadline = time.monotonic() + _BUSY_TIMEOUT_MS / 1000
    while True:
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            return
        except sqlite3.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.05)


def connect(path: Path) -> sqlite3.Connection:
    """Open (creating if needed) the database at ``path`` and bring its schema up to date."""
    path = Path(path)
    # The database holds owner emails. Create each missing directory 0700 (mkdir(parents=True, mode=...)
    # only applies the mode to the leaf). Tighten an existing parent only if it is our own data dir;
    # never touch arbitrary user directories.
    created = [d for d in path.parents if not d.exists()]
    for directory in reversed(created):
        directory.mkdir(mode=0o700, exist_ok=True)
    if path.parent.name == "kubedelos":
        path.parent.chmod(0o700)
    if not path.exists():
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    path.chmod(0o600)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    _use_wal(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            sidecar.chmod(0o600)
    try:
        _migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def connect_readonly(path: Path, *, check_same_thread: bool = True) -> sqlite3.Connection:
    """Open an existing database read-only. Never creates, migrates or writes; raises if the file is missing.

    ``check_same_thread=False`` is for a connection one consumer uses from several threads in turn, such as a streamed
    response whose batches are produced on worker threads; it must never be shared by two at once.
    """
    # as_uri() percent-escapes spaces and '#', which would otherwise end the URI path.
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, check_same_thread=check_same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn
