"""Connection setup and schema migrations."""

import os
import sqlite3
from pathlib import Path

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
]


def _migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    for index in range(version, len(MIGRATIONS)):
        try:
            # executescript() commits implicitly, so drive the transaction by hand. user_version is
            # transactional in SQLite, so a failed script leaves the version untouched.
            conn.executescript(f"BEGIN;\n{MIGRATIONS[index]}\nPRAGMA user_version = {index + 1};\nCOMMIT;")
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise


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
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            sidecar.chmod(0o600)
    _migrate(conn)
    return conn
