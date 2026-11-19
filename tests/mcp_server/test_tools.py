import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from kubedelos.config import Settings
from kubedelos.mcp_server import tools
from kubedelos.mcp_server.tools import Db
from kubedelos.store.db import MIGRATIONS, connect
from kubedelos.store.repo import Repo

NOW = datetime(2026, 2, 1, tzinfo=UTC)


class Clock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        self.now += timedelta(minutes=1)
        return self.now


def seed(path, contexts):
    """One finished whole-cluster run per context; ``contexts`` maps a name to the day its run started."""
    conn = connect(path)
    for name, day in contexts.items():
        repo = Repo(conn, clock=Clock(datetime(2026, 1, day, tzinfo=UTC)))
        run_id = repo.start_run(name, "cli", "0.76.1", scan_level="library,os", scope=Settings().scope)
        repo.finish_run(run_id, "ok")
    conn.close()


def test_open_missing_database_says_how_to_create_it(tmp_path):
    path = tmp_path / "kubedelos.db"
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == f'no kubedelos database at {path}; run "kubedelos ui" and start a scan first'
    assert not path.exists()


def test_open_older_schema_is_refused_without_writing(tmp_path):
    path = tmp_path / "kubedelos.db"
    connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {len(MIGRATIONS) - 1}")
    raw.commit()
    raw.close()
    before = path.read_bytes()
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == (
        f'the database at {path} was written by an older kubedelos; open "kubedelos ui" once to update it'
    )
    assert path.read_bytes() == before


def test_open_newer_schema_is_refused(tmp_path):
    path = tmp_path / "kubedelos.db"
    connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {len(MIGRATIONS) + 1}")
    raw.commit()
    raw.close()
    with pytest.raises(ToolError) as exc:
        Db(path, None).open()
    assert str(exc.value) == f"the database at {path} was written by a newer kubedelos; upgrade kubedelos"


def test_clamp():
    assert tools.clamp(0) == 25
    assert tools.clamp(-3) == 25
    assert tools.clamp(500) == 100
    assert tools.clamp(7) == 7


def test_list_clusters_sorted_with_default(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    db = Db(path, None)
    conn = db.open()
    result = tools.list_clusters(conn, db, NOW)
    assert [c["name"] for c in result["clusters"]] == ["alpha", "zeta"]
    assert result["default"] == "alpha"  # the newest finished run
    alpha = result["clusters"][0]
    assert alpha["newest_run"] == 1 and alpha["status"] == "ok" and alpha["last_scan"].startswith("2026-01-09")
    assert alpha["stale"] is True
    conn.close()
    pinned = Db(path, "zeta")
    conn = pinned.open()
    assert tools.list_clusters(conn, pinned, NOW)["default"] == "zeta"
    conn.close()


def test_unknown_cluster_lists_known_ones(tmp_path):
    path = tmp_path / "kubedelos.db"
    seed(path, {"zeta": 5, "alpha": 9})
    db = Db(path, None)
    conn = db.open()
    with pytest.raises(ToolError) as exc:
        tools.resolve_cluster(conn, db, "nope")
    assert str(exc.value) == "unknown cluster nope; known: alpha, zeta"
    assert tools.resolve_cluster(conn, db, "zeta") == "zeta"
    assert tools.resolve_cluster(conn, db, None) == "alpha"
    conn.close()
