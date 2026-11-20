# Threat feeds and the risk score Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rank the fix-first lists by a deterministic, explained risk score built from severity, CISA KEV and EPSS, and
the attack-surface facts PR 1 records, in the UI, the reports and over MCP, without moving any count.

**Architecture:** `kubedelos/risk.py` is the one definition of the score: Python for the factor lists, plus SQL
fragments generated from the same constants for ordering. The workload part is stored per workload row
(`workload.risk_points`, written at scan time, backfilled by migration 13). The per-CVE part is a join on `threat_intel`
when reading, so a new KEV entry re-ranks old runs. `kubedelos/threatintel.py` downloads the two feeds at most once a
day, before a scan and when `ui` starts. Pages never wait on the network.

**Tech Stack:** Python 3.12, SQLite (stdlib), httpx, FastAPI/Jinja, the `mcp` SDK, pytest.

**Spec:** `docs/superpowers/specs/2026-11-19-attack-surface-mcp-risk-design.md`, "Step 3: threat feeds and the risk
score". Refs #63.

## Global Constraints

- AGENTS.md conventions bind every task. In particular: TDD with one test file per module; every module starts with a
  docstring; ruff at line length 120; placeholder names (`example.com`, `my-cluster`); Conventional Commits with
  lowercase subjects and no attribution lines; `CHANGELOG.md` gets a hand-written `## Unreleased` entry.
- **The score moves no count.** KPIs, severity bricks, the namespaces page, the diff, `FixList.total`, `no_fix`,
  `no_fix_images` and `accepted` stay exactly as they are. Only the order of the work lists changes.
- **Unknown never reads as safe.** Unknown exposure and unknown rights each score at least as high as `none` and no
  bindings.
- **The only new outbound traffic** is two plain HTTPS GETs (KEV and EPSS). They carry no query string, no body and
  nothing about the cluster. kubedelos calls no model and stores no key.
- **The MCP server stays read-only and offline.** It reads `threat_intel` and never downloads.
- **300 ms:** every UI page stays under 300 ms on 1,000 images and 100,000 findings, with facts and feeds seeded.
- **Old runs** (no facts, migration < 12) and **no feed copy** are normal inputs, never errors.
- `KUBEDELOS_THREAT_FEEDS` is on by default (for `ui`), and the chart sets it to `"false"`.

## Decisions this plan makes (the spec allows changing starting values)

1. **Unknown severity is 3 points, not 5.** The pinned property "higher severity scores strictly higher" fails between
   Low (5) and Unknown (5). Unknown already sorts below Low everywhere.
2. **Host access uses the MCP definition.** `host_access` moves from `mcp_server/tools.py` to `risk.py`, and both use
   it: privileged, host PID, network or IPC, a writable hostPath, or an added capability in SYS_ADMIN, NET_ADMIN,
   SYS_PTRACE, SYS_MODULE, SYS_RAWIO, DAC_READ_SEARCH, BPF or ALL. It is wider than the spec's list, so it can
   overstate but never understate.
3. **Unknown root counts as root (+3),** the same way "unknown token counts as mounted" does.
4. **No facts:** exposure unknown (+10), host +3 and rights unknown (+5), so `NO_FACTS_POINTS = 18`. An image with no
   workload rows gets the same.
5. **Rights:** status `unknown` or `off` is unknown (+5). `partial` with no flag set is also unknown (+5), because it
   is not a full view. Only `ok` with no flag set is +0.
6. **Feed freshness lives in a `threat_feed` table** (one row per feed), not in a `fetched_at` column on each of the
   roughly 300,000 intel rows.
7. **Migrations may be Python callables,** so migration 13 can backfill `risk_points` through the same `risk.py`
   function instead of a SQL copy of it.
8. **Feeds refresh before a scan and when `ui` starts** (in a background thread), never during a page request.
9. **The CSV `risk` column is appended last,** so scripts that read columns by position keep working.
10. **The findings page also shows a Risk column** while the score is shown. A sort by a value the page doesn't show
    would confuse people.
11. **`find_vulnerability` orders by score while the score is shown,** then by `exposure_key`.

## Review Focus

1. **A broken download:** a truncated gzip, an HTML error page served with status 200, a KEV catalogue with no
   entries, or an EPSS file without the `cve,epss,percentile` header. The feed is refused whole, the last copy stays,
   and nothing is half-written. Pinned in Task 3.
2. **Offline laptop or blocked proxy** at scan time or at `ui` start. The scan runs and finishes as usual with one
   warning per feed, and no page waits on the network. Pinned in Task 3.
3. **A database upgraded from version 12** that has runs with facts, runs without facts, and an image with no workload
   rows. Every unit gets a score (never NULL) and old rows count as unknown. Pinned in Tasks 2 and 4.
4. **Ids that are not CVEs** (`GHSA-…`) and **lowercase CVE ids** score exploit +0 or match the uppercased CVE, without
   errors. Pinned in Tasks 1 and 3.
5. **Two processes refreshing at once** (`ui` start and a scan). One download is stored and the other skips under the
   write lock, with no "database is locked" error. Pinned in Task 3.

---

### Task 1: `risk.py`, the score as a pure function

**Files:**
- Create: `kubedelos/risk.py`
- Modify: `kubedelos/mcp_server/tools.py` (delete `host_access` and `_HOST_CAPABILITIES`, import them from `risk`)
- Modify: `kubedelos/models.py`: move `parse_facts` here from `kubedelos/store/workloads.py`, and keep the name
  importable from `store.workloads`, because migration 13 needs it without importing `store`.
- Test: `tests/test_risk.py`

**Interfaces:**
- Produces, in `kubedelos/risk.py`:
  - `MAX_SCORE = 100`;
  - `SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 3}`;
  - `KEV_POINTS = 25` and `EPSS_STEPS = ((0.5, 15), (0.1, 8))`;
  - `EXPOSURE_POINTS = {"external": 15, "cluster": 5, "none": 0, "unknown": 10}` and `CLUSTER_ISOLATED_POINTS = 2`;
  - `HOST_ACCESS_POINTS = 10` and `ROOT_POINTS = 3`;
  - `RIGHTS_HIGH_POINTS = 10`, `RIGHTS_OTHER_POINTS = 5` and `RIGHTS_UNKNOWN_POINTS = 5`;
  - `NO_FACTS_POINTS = workload_points(None)`, which is 18.
  - `@dataclass(frozen=True) class Intel: kev: bool; kev_added: date | None; epss: float | None;
    percentile: float | None`, and `NO_INTEL = Intel(False, None, None, None)`.
  - `@dataclass(frozen=True) class Factor: name: Literal["severity", "exploited", "exposure", "host", "rights"];
    points: int; detail: str`.
  - `@dataclass(frozen=True) class Score: points: int; factors: tuple[Factor, ...]`. There are always five factors, in
    the order above.
  - `host_access(facts: WorkloadFacts) -> bool`, moved from `mcp_server/tools.py` unchanged.
  - `workload_factors(facts: WorkloadFacts | None) -> tuple[Factor, Factor, Factor]`, giving exposure, host and rights.
  - `workload_points(facts: WorkloadFacts | None) -> int`.
  - `exploit_factor(intel: Intel) -> Factor`.
  - `score(severity: str, intel: Intel, facts: WorkloadFacts | None) -> Score`.
  - `severity_points_sql(rank: str) -> str`: a CASE over a `sev_rank` expression (4 is Critical … 0 is Unknown).
  - `exploit_points_sql(alias: str) -> str`: a CASE over a `threat_intel` row aliased `alias`, which may be NULL from a
    LEFT JOIN.
- Detail strings are short and human, for example "in KEV since 2026-11-18", "EPSS 0.62", "EPSS unknown",
  "cluster, ingress isolated", "privileged", "runs as root", "root unknown", "cluster_admin", "token not mounted",
  "facts not collected". Tests pin only the points and the names.

- [ ] **Step 1: Write the failing tests in `tests/test_risk.py`.** Build facts with the `make_facts` style of
  `tests/mcp_server/conftest.py`, and add a local builder that sets the pod, exposure, network and rights fields one by
  one.
  - `test_points_table`: one assertion per table row, using the values above. Examples:
    - KEV +25 even with EPSS 0.9;
    - EPSS 0.5 → +15, 0.1 → +8, 0.099 → +0, None → +0;
    - a cluster-exposed pod with `ingress_isolated=True` → +2, and with `ingress_isolated` None → +5;
    - privileged → host +10;
    - only `runs_as_root` None → +3;
    - `cluster_admin`, `escalates` or `reads_secrets_scope == "cluster"` → +10;
    - `pod_exec` alone or namespaced `reads_secrets` → +5;
    - `ok` with no flags → +0, `partial` with no flags → +5, `unknown` or `off` → +5;
    - `automount_token=False` with `cluster_admin` → +0, and `automount_token` None with `cluster_admin` → +10.
  - `test_no_facts_counts_as_unknown`: `workload_points(None) == NO_FACTS_POINTS == 18`. The factor details say the
    facts were not collected.
  - `test_unknown_never_below_known_harmless`: over the product of every exposure level × every rights status ×
    `automount_token` in {True, None}, unknown exposure ≥ `none` and unknown rights ≥ `ok` with no flags. No-facts
    points ≥ the points of the harmless facts.
  - `test_exploited_beats_not_exploited`: over every severity and a set of facts, KEV > EPSS 0.49 > EPSS 0.09 = None.
  - `test_exposure_orders_the_score`: with everything else equal, external > cluster > cluster isolated > none.
  - `test_severity_decides_at_equal_exploit_points`: over the adjacent pairs of `SEVERITY_POINTS` (Unknown < Low <
    Medium < High < Critical), at each exploit level, strictly higher. Also pins the deliberate cross case: High with
    EPSS 0.6 > Critical with EPSS 0.01.
  - `test_repeatable`: the same inputs, scored twice, give equal `Score` objects (factors included).
  - `test_score_is_sum_capped`: `score(...).points == min(100, sum(f.points for f in factors))`. The maximum
    (Critical, KEV, external, privileged, cluster_admin) is exactly 100.
  - `test_sql_matches_python`: in an in-memory SQLite, for every rank 0–4 and a list of `(kev, epss)` rows including a
    NULL row, `severity_points_sql` and `exploit_points_sql` equal the Python points.
  - `test_host_access_capabilities_normalised`: `cap_sys_admin` and `CAP_BPF` count; `CHOWN` does not.
- [ ] **Step 2: Run them and see them fail.** Run `.venv/bin/pytest tests/test_risk.py -q`. Expected: ImportError, or
  failures.
- [ ] **Step 3: Implement `kubedelos/risk.py`.**
  - Generate the SQL fragments from the constants, so the numbers exist in one place.
  - Move `host_access` and `_HOST_CAPABILITIES`, and move `parse_facts` into `models.py`, with re-exports where they
    were.
  - The module docstring says why the workload part is stored: a change of weights needs a migration that recomputes
    `risk_points`.
- [ ] **Step 4: Run the tests.** Run `.venv/bin/pytest tests/test_risk.py tests/mcp_server tests/store -q`. Expected:
  all pass.
- [ ] **Step 5: Commit** with the message `feat: add the risk score as a pure, explained function (#63)`.

### Task 2: migration 13, with feed tables and stored workload points

**Files:**
- Modify: `kubedelos/store/db.py`: `MIGRATIONS: list[str | Callable[[sqlite3.Connection], None]]`, and `_migrate` runs
  a callable inside the same `BEGIN IMMEDIATE` and then sets `PRAGMA user_version`.
- Modify: `kubedelos/store/repo.py`: the workload insert also writes `risk_points`.
- Test: `tests/store/test_db.py` (new, for the db module) and `tests/store/test_repo.py`

**Interfaces:**
- Consumes `risk.workload_points` and `models.parse_facts`.
- Produces this schema (version 13):
  - `threat_intel(vuln_id TEXT PRIMARY KEY, kev INTEGER NOT NULL DEFAULT 0, kev_added TEXT, epss REAL,
    epss_percentile REAL) WITHOUT ROWID`;
  - `threat_feed(name TEXT PRIMARY KEY CHECK (name IN ('kev', 'epss')), fetched_at TEXT NOT NULL, version TEXT,
    rows INTEGER NOT NULL)`;
  - `workload.risk_points INTEGER`, backfilled on every existing row. Readers still use
    `COALESCE(risk_points, NO_FACTS_POINTS)`.
- `mcp_server/tools.py Db.open` keeps comparing against `len(MIGRATIONS)`, so a version-12 database gets the "older"
  message.

- [ ] **Step 1: Write the failing tests.**
  - `tests/store/test_db.py::test_migration_13_backfills_risk_points`:
    - build a version-12 database by applying `MIGRATIONS[:12]` by hand;
    - insert three workload rows: one with external, privileged facts; one with NULL facts; one with invalid JSON;
    - `connect()` it;
    - expected: `user_version == 13`, and `risk_points` is `[workload_points(facts), 18, 18]`;
    - `threat_intel` and `threat_feed` exist and are empty.
  - `test_failed_callable_migration_rolls_back`: a callable that raises leaves `user_version` and the data unchanged.
  - `tests/store/test_repo.py::test_add_result_stores_risk_points`: an `InventoryItem` with facts for one workload and
    none for another stores `workload_points(facts)` and 18.
- [ ] **Step 2: Run them and see them fail.** Run `.venv/bin/pytest tests/store -q`.
- [ ] **Step 3: Implement.**
  - The backfill reads `id, facts` in batches of 1,000 and `executemany`s the update. It doesn't use `executescript`
    inside the callable, because that would commit the open transaction.
- [ ] **Step 4: Run the tests.** Run `.venv/bin/pytest tests/store tests/mcp_server tests/test_cli.py -q`. Expected: all
  pass.
- [ ] **Step 5: Commit** with the message `feat: store each workload's risk points and add the threat feed tables
  (#63)`.

### Task 3: threat feeds, downloaded at most once a day

**Files:**
- Create: `kubedelos/threatintel.py` (download, parse, store) and `kubedelos/store/intel.py` (reads)
- Modify:
  - `kubedelos/config.py`: `threat_feeds: bool = True`, with a comment in the style of `attack_surface`;
  - `kubedelos/scan/service.py`: in `run_scan`, before the inventory, emit `Progress(phase="threat-feeds")` and call
    `threatintel.refresh_feeds(settings)`;
  - `kubedelos/cli.py`: `ui` calls `threatintel.refresh_in_background(settings)` before it serves;
  - the scan progress label for the new phase, where `scan_progress.html` names phases;
  - `charts/kubedelos/templates/configmap.yaml`: `KUBEDELOS_THREAT_FEEDS: "false"`;
  - the Settings page: wherever it shows `attack_surface`, show `threat_feeds` and each feed's last fetch.
- Create: `tests/conftest.py`, an autouse fixture that sets `KUBEDELOS_THREAT_FEEDS=false`, so no test touches the
  network.
- Test: `tests/test_threatintel.py`, `tests/store/test_intel.py`, `tests/scan/test_service.py`,
  `tests/chart/test_chart.py`, `tests/test_config.py`

**Interfaces:**
- In `threatintel.py`:
  - `KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"`;
  - `EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"`. EPSS moved from `epss.cyentia.com`
    in 2025, and the old host 301-redirects here. Verified 2026-11-20: the URL 302s to the dated file.
  - `MAX_AGE = timedelta(hours=24)`, `MAX_DOWNLOAD = 32 * 2**20` and `MAX_EPSS_CSV = 256 * 2**20` (decompressed).
  - `class FeedError(Exception)`.
  - `parse_kev(body: bytes) -> tuple[str | None, dict[str, date | None]]` returns `catalogVersion` and
    `{cveID: dateAdded}` from `vulnerabilities[]`.
  - `parse_epss(body: bytes) -> tuple[str | None, dict[str, tuple[float, float]]]`:
    - the gzip is read in chunks under `MAX_EPSS_CSV`;
    - an optional first line `#model_version:…,score_date:…` gives the version (`score_date`);
    - then the header `cve,epss,percentile`.
  - `refresh(conn: sqlite3.Connection, client: httpx.Client, now: datetime) -> dict[str, str]` returns per feed
    `"fresh"` (skipped), `"updated"` or `"failed"`.
  - `refresh_feeds(settings: Settings, *, client: httpx.Client | None = None, now: datetime | None = None)
    -> dict[str, str] | None`. It returns None when `settings.threat_feeds` is off. It owns its connection
    (`db.connect(settings.db_path)`) and its client: `follow_redirects=True`, timeout connect 10 s and read 30 s, and
    `User-Agent: kubedelos/<version>`.
  - `refresh_in_background(settings: Settings) -> threading.Thread | None` starts a daemon thread.
- In `store/intel.py`, read-only:
  - `intel_for(conn, vuln_ids: Iterable[str]) -> dict[str, risk.Intel]` (missing ids are absent);
  - `feeds(conn) -> dict[str, datetime]`: the `fetched_at` of each feed that has a copy;
  - `run_has_facts(conn, run_id: int) -> bool`;
  - `risk_shown(conn, run_id: int) -> bool`, which is `run_has_facts or bool(feeds(conn))`.

Rules:
- An id is stored uppercased and only if it matches `^CVE-\d{4}-\d{4,}$`.
- A row with an EPSS outside [0, 1], or one that isn't a float, is skipped.
- A feed with no valid row, a wrong header, invalid JSON or gzip, an HTTP status ≥ 400, or more than `MAX_DOWNLOAD`
  bytes raises `FeedError`. The old copy is kept.
- Storing a feed is one `BEGIN IMMEDIATE` transaction:
  - first, re-check `threat_feed.fetched_at` under the lock; if the feed is still fresh, the transaction is skipped;
  - otherwise, clear that feed's columns, upsert its rows, delete rows with `kev = 0 AND epss IS NULL`, and upsert its
    `threat_feed` row.
- A failure logs one warning per feed, `threat feed %s not updated: %s`. Neither `refresh_feeds` nor `run_scan` ever
  raises because of a feed.

- [ ] **Step 1: Write the failing tests.** Use `httpx.MockTransport` for the client, with small fixture bodies built in
  the test: a KEV JSON with 3 entries and a gzipped EPSS CSV with a `#model_version` line.
  - `test_refresh_stores_both_feeds`: KEV and EPSS rows are joined on `vuln_id`, `kev_added` is a date, and
    `threat_feed` has both rows with `rows` counts.
  - `test_fresh_feed_is_not_downloaded`: within 24 h, the transport is never called; after 24 h it is.
  - `test_requests_carry_nothing`: every request is a GET to exactly `KEV_URL` or `EPSS_URL` (after redirects, the
    dated EPSS file on the same host), with no query string and no body.
  - `test_broken_download_keeps_the_last_copy` (Review Focus 1), parametrised over:
    - truncated gzip;
    - `<html>` served with status 200;
    - KEV with `vulnerabilities: []`;
    - EPSS with a wrong header;
    - status 503;
    - a body over `MAX_DOWNLOAD`.
    Each case: the previous rows and `fetched_at` are unchanged, the status is `"failed"`, and one warning is logged.
  - `test_invalid_rows_are_skipped`: `GHSA-xxxx`, `cve-2024-1` (too short), an EPSS of `1.5`, and `nan` are skipped;
    `cve-2024-12345` is stored as `CVE-2024-12345` (Review Focus 4).
  - `test_unreachable_host_fails_softly` (Review Focus 2): a transport that raises `httpx.ConnectError` gives
    `{"kev": "failed", "epss": "failed"}` and no exception.
  - `test_concurrent_refresh_stores_once` (Review Focus 5):
    - two connections to one file;
    - the second refresh starts after the first stores;
    - the second sees the fresh feed under the lock and skips;
    - no `sqlite3.OperationalError`.
  - `test_refresh_feeds_off`: with `threat_feeds=False` the result is None and no client is built.
  - `tests/store/test_intel.py`:
    - `intel_for` returns `Intel` for stored ids;
    - `risk_shown` is False with no facts and no feeds, and True with either.
  - `tests/scan/test_service.py::test_run_scan_refreshes_feeds_first_and_survives_failure`:
    - with `refresh_feeds` patched to record and then raise, the scan still finishes `ok`;
    - the `threat-feeds` phase comes before `inventory`.
  - `tests/chart/test_chart.py`: the ConfigMap has `KUBEDELOS_THREAT_FEEDS == "false"`, and the rendered settings give
    `threat_feeds is False`. Same shape as the `attack_surface` tests.
  - `tests/test_config.py`: the default is True, and `KUBEDELOS_THREAT_FEEDS=false` turns it off.
- [ ] **Step 2: Run them and see them fail.** Run `.venv/bin/pytest tests/test_threatintel.py tests/store/test_intel.py
  -q`.
- [ ] **Step 3: Implement.**
  - Stream the download with `client.stream` and stop at `MAX_DOWNLOAD`.
  - Parse EPSS line by line from `gzip.GzipFile` over the bytes.
  - Upsert with `executemany`.
- [ ] **Step 4: Run the tests.** Run `.venv/bin/pytest -q` and
  `KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q`. Expected: all pass, and no test opens a socket.
- [ ] **Step 5: Commit** with the message `feat: download cisa kev and epss at most once a day for the risk score (#63)`.

### Task 4: scored fix lists

**Files:**
- Modify: `kubedelos/store/queries.py` and `kubedelos/store/workloads.py`
- Test: `tests/store/test_queries.py`, `tests/store/test_workloads.py` and `tests/web/test_perf.py` (the plan test)

**Interfaces:**
- Consumes `risk.*_sql`, `risk.NO_FACTS_POINTS`, `risk.score`, `store.intel.intel_for` and `models.parse_facts`.
- Produces:
  - `_WORKLOAD_POINTS_SQL`, the CTE `wp(ref, points)`: `MAX(w.risk_points)` per ref over the run's image rows (keyed by
    `:run`, through `idx_workload_image_result`);
  - `_score_sql(u: str) -> str`: `MIN(100, severity + exploit + COALESCE(wp.points, NO_FACTS_POINTS))` over
    `LEFT JOIN threat_intel ti ON ti.vuln_id = u.vuln_id LEFT JOIN wp ON wp.ref = u.ref`.
  - `fix_by_fix(conn, run_id, limit=25, *, today=None, scored: bool = False) -> FixList[FixRow]`:
    - when `scored`, the group's `score` is the `MAX` of its units' scores;
    - the order is `score DESC, sev_rank DESC, images DESC, namespaces DESC, vuln_id, pkg_name, fixed_version`;
    - the samples are ordered by the unit's score DESC, then ref, so the first sample is the top unit.
  - `fix_by_image(..., scored: bool = False) -> FixList[ImageFixRow]`, ordered by `score DESC, critical DESC, high DESC,
    ref`. The image's score and factors come from its top unit (highest score, then `sev_rank`, then `vuln_id`).
  - `FixRow` and `ImageFixRow` gain `score: int | None = None` and `factors: tuple[risk.Factor, ...] = ()`, both set
    only when `scored`.
  - In `store/workloads.py`: `top_workload_facts(conn, run_id: int, refs: list[str]) -> dict[str, WorkloadFacts |
    None]`, the facts of each ref's workload row with the highest `risk_points` (ties: namespace, kind, name,
    container).
  - With `scored=False`, the order and results are exactly as today.

- [ ] **Step 1: Write the failing tests** in `tests/store/test_queries.py`, using the repo helpers the file already uses.
  - `test_scored_fix_first_puts_the_exposed_critical_first`: two Critical fixable CVEs. CVE-A is in more images, in a
    batch job (`none` exposure, no rights). CVE-B is in one image, in an external, privileged pod. Unscored order: A, B.
    Scored order: B, A, with B's score equal to `risk.score("CRITICAL", NO_INTEL, facts_b).points` and its five
    factors.
  - `test_kev_reranks_an_old_run`: insert a KEV row for the second CVE after the run is stored; the scored order flips.
  - `test_scoring_moves_no_count` (constraint):
    - `total`, `no_fix`, `no_fix_images` and `accepted` are equal for `scored` True and False;
    - with feeds loaded, `kpis()` and `namespace_counts()` are unchanged.
  - `test_unit_without_workload_rows_scores_as_unknown` (Review Focus 3): an image result with findings and no workload
    row gets `severity + exploit + 18`, never NULL.
  - `test_fix_by_image_scored_uses_the_top_unit`.
  - `tests/store/test_workloads.py::test_top_workload_facts_takes_the_riskiest_row`.
  - In `test_query_plans_use_indexes`, add `"fix_by_fix scored"` and `"fix_by_image scored"` with `threat_intel`
    seeded. `threat_intel` must be searched by its primary key, never scanned.
- [ ] **Step 2: Run them and see them fail.** Run `.venv/bin/pytest tests/store -q` and
  `.venv/bin/pytest tests/web/test_perf.py -q -k plans`.
- [ ] **Step 3: Implement.**
  - Add `score` to the materialized `every` units only when `scored`.
  - Compute factors in Python for the page's rows only: one `intel_for` call and one `top_workload_facts` call per list.
- [ ] **Step 4: Run the tests.** Run `.venv/bin/pytest tests/store tests/web tests/mcp_server -q`. Expected: all pass.
- [ ] **Step 5: Commit** with the message `feat: order the fix-first lists by risk score when there is one (#63)`.

### Task 5: the findings `risk` sort and the export column

**Files:**
- Modify: `kubedelos/store/queries.py`
- Test: `tests/store/test_queries.py` and `tests/web/test_perf.py` (the plan test)

**Interfaces:**
- `FindingFilter` gains `scored: bool = False`, and `sort` gains `"risk"`.
- `_SORT_TERMS["risk"] = (("{p}score IS NULL", False), ("{p}score", True))`.
- `kept` carries `score`: `_score_sql('u')` when `scored`, else `NULL AS score`. So `findings_page` rows and
  `findings_export` rows always have a `score` key.
- `sort="risk"` with `scored=False` orders like `"severity"`.

- [ ] **Step 1: Write the failing tests.**
  - `test_findings_risk_sort`: descending and ascending; paging through the far end (a page past the middle) gives the
    same order as a forward read. Copy the existing far-end test's shape.
  - `test_findings_risk_without_score_is_severity_order`.
  - `test_export_always_has_score`: NULL when not scored, an int when scored.
  - In the plan test, add `"findings_page risk"`: `FindingFilter(sort="risk", scored=True)` on page 2.
- [ ] **Step 2: Run them and see them fail,** then **Step 3: implement,** then **Step 4: run** `.venv/bin/pytest
  tests/store tests/web -q`. Expected: all pass.
- [ ] **Step 5: Commit** with the message `feat: sort findings by risk and carry the score into the export (#63)`.

### Task 6: the score in the UI and the reports

**Files:**
- Modify:
  - `kubedelos/web/routes/dashboard.py`, `findings.py` and `reports.py`;
  - the templates `dashboard.html`, `findings.html` and `report.html`, and `static/app.css`.
- Test: `tests/web/test_dashboard.py`, `test_findings.py` and `test_reports.py`

**Interfaces:**
- Consumes `store.intel.risk_shown`, `store.intel.run_has_facts`, `store.intel.feeds`, and the `scored=` queries.
- Each route calls `risk_shown(conn, run.id)` once and passes `scored=shown`.
- The Jinja context gets `risk_shown: bool` and `risk_note: str | None`.
- The findings `Sort` Literal (both places in `findings.py`) gains `"risk"`.
- The CSV `COLUMNS` gets `"risk"` appended last. It is empty when not scored.

The notes use this exact copy. Exactly one shows, or none.
- **Hidden:** "Risk scores are hidden for this run: no attack-surface facts were collected and no threat feed has been
  downloaded, so a score would only restate severity."
- **Facts missing:** "Attack-surface facts were not collected for this run, so exposure, host access and API rights
  count as unknown."
- **Feeds missing:** "No threat feed has been downloaded yet, so known exploitation (KEV, EPSS) adds nothing."

The factor chips:
- Use `<details><summary>` holding the score, with a list of the factors that have points.
- Each chip reads `<detail> +<points>`.
- No inline script or style, because of the CSP.

- [ ] **Step 1: Write the failing tests.**
  - Dashboard, both views:
    - with facts and feeds seeded, a "Risk" column shows, rows come in score order, and the chips list the factors;
    - with neither, there is no "Risk" column, the order is as today, and the hidden note shows;
    - with facts but no feeds, the feeds note shows.
  - Findings:
    - `?sort=risk` orders by score and the Risk column shows;
    - when hidden, `?sort=risk` still answers 200 in severity order and the column is absent.
  - Reports:
    - the HTML fixes table has a Risk column when shown;
    - the CSV header ends with `risk` in both cases; the cells are empty when hidden and ints when shown.
  - Existing: every current web test passes unchanged, because seeded web tests have no facts and no feeds.
- [ ] **Step 2: Run them and see them fail.** Run `.venv/bin/pytest tests/web -q`.
- [ ] **Step 3: Implement,** in the existing table and chip style (`static/app.css`).
- [ ] **Step 4: Run the tests.** Run `.venv/bin/pytest tests/web -q`. Expected: all pass.
- [ ] **Step 5: Commit** with the message `feat: show the risk score and its factors in the dashboard, findings and
  reports (#63)`.

### Task 7: the score over MCP

**Files:**
- Modify: `kubedelos/mcp_server/tools.py`, `kubedelos/mcp_server/prompts.py` and `docs/mcp.md`
- Test: `tests/mcp_server/test_tools.py` and `test_prompts.py`

**Interfaces:**
- `fix_first`:
  - each item gains `score` (int or null) and `factors` (`[{"factor", "points", "detail"}]`, empty when hidden);
  - the result gains `risk: {"shown": bool, "facts": bool, "feeds": {"kev": iso | null, "epss": iso | null}}`.
- `find_vulnerability`:
  - the result gains `kev`, `kev_added`, `epss` and `epss_percentile` (null when unknown);
  - each workload item gains `score` and `factors`: `risk.score` for that CVE's highest severity in that workload's
    image, with that workload's facts;
  - while the score is shown, the order is `score DESC`, then `exposure_key`;
  - it also gains the same `risk` object.
- `FIX_FIRST` prompt text:
  - explain each fix's place from its `factors`;
  - say plainly when `risk.shown` is false or facts were not collected;
  - never present the score as a CVE severity.
- Tools stay read-only, and the never-touch-cluster test covers the new reads.

- [ ] **Step 1: Write the failing tests.**
  - `fix_first` with facts and KEV seeded returns score order, `factors`, and `risk.shown` true; without either,
    `risk.shown` is false and items have `score: null`.
  - `find_vulnerability` for a KEV CVE returns `kev: true` and `kev_added`, with the external workload first.
  - The prompt text mentions `factors`.
  - The read-only test shows the database bytes are unchanged after every tool call.
- [ ] **Step 2: Run them and see them fail,** then **Step 3: implement,** then **Step 4: run** `.venv/bin/pytest
  tests/mcp_server -q`. Expected: all pass.
- [ ] **Step 5: Commit** with the message `feat: return the risk score and its factors from the mcp tools (#63)`.

### Task 8: docs and the perf test with facts and feeds

**Files:**
- Create: `docs/risk-score.md`. It covers:
  - every factor and its points;
  - the decisions above;
  - when the score is hidden;
  - the two feed URLs, the once-a-day rule, what the requests carry (nothing about the cluster), and the switch.
- Modify:
  - `README.md` (a short "What to fix first" paragraph);
  - `CHANGELOG.md` (Unreleased);
  - `docs/in-cluster.md` (the chart sets `KUBEDELOS_THREAT_FEEDS=false`; turn it on if the pod has egress to cisa.gov
    and empiricalsecurity.com);
  - `docs/attack-surface.md` (a link);
  - `docs/mcp.md` (the new fields, if not done in Task 7);
  - `AGENTS.md`: add under Conventions "**Threat feeds.** The only outbound calls besides Trivy and registries are the
    CISA KEV and EPSS downloads in `kubedelos/threatintel.py`: plain GETs that carry nothing about the cluster."
- Modify: `tests/web/test_perf.py` and `tests/web/seed.py`.
  - `seed_large` gets an option to also write facts and `risk_points` on every workload row: a mix of exposure levels.
  - Add `seed_intel(conn, filler=250_000)`: KEV for 1% of the seeded CVEs, EPSS for all of them, plus `filler` other
    CVE rows, so the table has the real feed's size.
  - `SORTS` gains `"risk"`.
  - `test_pages_under_300ms` seeds facts and intel, so `/`, `/?by=image`, `/report`, every findings sort (with
    `risk`), and the CSV-free pages are timed with the score shown.

- [ ] **Step 1: Update the perf seed and tests.** Run `.venv/bin/pytest tests/web/test_perf.py -q -m perf` and see
  whether any page is over budget. If one is, fix the query (for example, materialize `wp` before the join) and record
  the before and after times in the commit message, as earlier perf commits did.
- [ ] **Step 2: Write the docs.**
- [ ] **Step 3: Verify the whole tree.**
  - `.venv/bin/pytest -q`;
  - `.venv/bin/pytest tests/web/test_perf.py -m perf -q`;
  - `KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q`;
  - `.venv/bin/ruff check . && .venv/bin/ruff format --check .`;
  - `.venv/bin/pre-commit run --all-files`.
  Expected: all pass.
- [ ] **Step 4: Run a real refresh once** (manual, network). Run `.venv/bin/python -c "from kubedelos.config import
  Settings; from kubedelos import threatintel; print(threatintel.refresh_feeds(Settings(data_dir='<scratch dir>')))"`.
  Expected: `{'kev': 'updated', 'epss': 'updated'}`, and about 300,000 `threat_intel` rows. Note the time it took in
  the PR.
- [ ] **Step 5: Commit** with the message `docs: document the risk score and threat feeds; time pages with them (#63)`.
