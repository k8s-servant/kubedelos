# kubedelos ui, PR 1: the app, the dashboard and findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kubedelos ui` opens a local, loopback-only web UI with a dashboard (overall cluster status and what to fix first) and a findings page, both reading the runs `kubedelos scan` stored.

**Architecture:**
- Storage: a FastAPI app (`kubedelos/web/`) reads SQLite through a new read-only query module (`kubedelos/store/queries.py`). Pure labelling and comparison logic lives in `kubedelos/analytics.py`. `Repo` stays the only write path.
- Security: one middleware stack handles Host check, session, CSRF and headers, and is always on.
- Coverage gaps: inventory warnings are now stored per run (`run_warning`), so the UI can tell an incomplete run from a whole one.
- Rendering: Jinja2 templates, one hand-written stylesheet, no JavaScript in PR 1.

**Tech Stack:** Python 3.12+, FastAPI, Starlette `TestClient` (httpx), Jinja2, uvicorn, SQLite JSON1, pytest.

**Spec:** `docs/superpowers/specs/2026-11-14-kubedelos-ui-design.md` (section "PR 1"). Run-selection background: issue #24.

## Global Constraints

- AGENTS.md rules: read-only cluster access, Trivy pinned, credentials never on disk or in logs, TDD with one test file per module, Python 3.12+, Ruff at 120, a docstring per module, placeholders (`example.com`, `my-cluster`) in examples and tests.
- No code, markup, CSS or SQL from `../k8s-trivy-reporter`; feature reference only.
- New core dependencies: `"fastapi>=0.162,<1"`, `"jinja2>=3.1,<4"`, `"uvicorn>=0.54,<1"` (plain, no `[standard]`). No `python-multipart`: PR 1 parses no forms (see Task 3).
- Loopback only: `--host` accepts `127.0.0.1`, `::1` or `localhost`; anything else exits 2. Default port 9370. No `--allow-remote`.
- Only runs of the UI's context with status `ok` or `partial` are ever shown as results.
- Counting units everywhere: an image is a distinct `image_result.ref` within a run; a finding is a distinct (ref, `vuln_id`, `pkg_name`, `installed_version`).
- Caps, each with the real total stated: 25 rows per dashboard list, 20 images per fix-row expander, 100 rows per findings page.
- Stale: a run whose `finished_at` is more than 24 hours old.
- Every page renders in under 300 ms on a seeded DB of about 1,000 images and 100,000 findings.
- Conventional Commits, lowercase subjects, no attribution lines. Branch `feat/ui-dashboard`, cut from `docs/ui-design`, so the spec, this plan and the code go in one PR.

## Review Focus

1. **Hostile strings from the cluster.** Image refs, CVE titles, package names and warning texts come from pod specs and Trivy. A `<script>` in any of them must render as text, and a `javascript:` or `data:` `primary_url` must not become a link. (Task 6: `test_hostile_strings_are_escaped`)
2. **Host header variants.** `127.0.0.1:9370.example.com`, `localhost` without the port, a wrong port and a missing Host header all get 400. `LOCALHOST:9370` is accepted, because hosts are case-insensitive. (Task 3: `test_host_header_variants`)
3. **Token on a deep link.** `/findings?severity=HIGH&token=…` sets the cookie and redirects to `/findings?severity=HIGH`, keeping the other parameters and their order. (Task 3: `test_token_on_deep_link_keeps_other_params`)
4. **A CLI scan writing while the UI reads.** A writer holding an open transaction with a new `running` run must not block or break a page, and the `running` run never shows. (Task 4: `test_page_renders_while_a_scan_is_writing`)
5. **`q` containing `%` or `_`.** The substring filter matches those characters literally, never as wildcards. (Task 7: `test_q_matches_wildcards_literally`)

---

### Task 1: Store coverage warnings and open the DB read-only

**Files:**
- Modify: `kubedelos/store/db.py`, `kubedelos/store/repo.py`, `kubedelos/scan/service.py`
- Test: `tests/store/test_repo.py`, `tests/scan/test_service.py`

**Interfaces:**
- Produces:
  - Migration 4 in `MIGRATIONS`: `CREATE TABLE run_warning (id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES scan_run(id), text TEXT NOT NULL, coverage INTEGER NOT NULL CHECK (coverage IN (0, 1))); CREATE INDEX idx_run_warning_run ON run_warning(run_id);`
  - `Repo.add_warnings(run_id: int, warnings: Sequence[InventoryWarning]) -> None`, a single transaction.
  - `Repo.run_warnings(run_id: int) -> list[sqlite3.Row]`, with columns `text, coverage`, ordered by `id`.
  - `db.connect_readonly(path: Path) -> sqlite3.Connection`. It opens `file:<path>?mode=ro` with `uri=True`, sets `row_factory = sqlite3.Row` and `busy_timeout = 5000`, never creates or migrates anything, and raises `sqlite3.OperationalError` when the file is missing. Build the URI with `path.resolve().as_uri()` plus `?mode=ro`, so spaces and `#` in the path are escaped.
  - `run_scan` calls `repo.add_warnings(run_id, warnings)` right after `start_run`. Nothing else about its behaviour or the CLI changes.

- [ ] **Step 1: Write the failing tests:**
  - `test_repo.py::test_add_and_read_warnings`: two warnings, one with coverage and one without, come back in order with `coverage` 1 and 0.
  - `test_repo.py::test_connect_readonly_cannot_write`: after `connect()` created the DB, an `INSERT` through `connect_readonly()` raises `sqlite3.OperationalError` matching `readonly`.
  - `test_repo.py::test_connect_readonly_missing_file_raises`: it raises and creates no file.
  - `test_repo.py::test_connect_readonly_path_with_space_and_hash` (directory `a b#c`).
  - `test_service.py::test_service_stores_inventory_warnings`: a fake API where namespace `missing` doesn't exist (`Settings(namespaces=["default", "missing"])`) stores `namespace missing not found` with coverage 1.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_repo.py tests/scan/test_service.py -q`. Expected: the 5 new tests fail (`AttributeError`, or no `run_warning` table).
- [ ] **Step 3:** Implement the interfaces above. `test_migrations_idempotent` already asserts `user_version == len(MIGRATIONS)`, so it covers the new migration.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit `feat: store inventory coverage warnings with each scan run`.

### Task 2: Run selection and run labels

**Files:**
- Create: `kubedelos/store/queries.py`, `kubedelos/analytics.py`
- Test: `tests/store/test_queries.py`, `tests/test_analytics.py`

**Interfaces:**
- Consumes: the Task 1 schema.
- Produces in `queries.py`:
  - A frozen dataclass `Run`:
    - stored fields: `id: int`, `context: str | None`, `status: str`, `finished_at: datetime | None`, `pkg_types: str | None`, `scope: dict | None` (parsed JSON)
    - counted fields: `images: int` (distinct refs), `images_failed: int` (distinct refs with at least one `error` row), `gaps: list[str]` (the coverage-warning texts)
  - `RESULT_STATUSES = ("ok", "partial")`.
  - `CLUSTER_SCOPE_SQL`: a SQL predicate on `scan_run`: `scope IS NOT NULL AND json_array_length(scope, '$.namespaces') = 0 AND json_extract(scope, '$.namespace_selector') IS NULL AND json_extract(scope, '$.selector') IS NULL`.
  - `newest_run(conn, context: str, *, cluster_scope: bool) -> Run | None`: the highest `id` among result-status runs of `context`. With `cluster_scope`, it also requires the predicate.
  - `get_run(conn, context: str, run_id: int) -> Run`. It raises `RunNotShown(reason: str)` with one of these reasons:
    - `"no run {id}"`
    - `"run {id} belongs to context {other}, not {context}"`
    - `"run {id} is {status}, so it has no results to show"`
  - `previous_comparable(conn, run: Run) -> Run | None`:
    - the highest `id` below `run.id`
    - same context, status in `RESULT_STATUSES`
    - same `scope` text and same `pkg_types`
    - both runs have non-NULL `scope`; a run with NULL scope is never comparable
- Produces in `analytics.py` (pure, no SQL):
  - `is_cluster_scope(scope: dict | None) -> bool`: the same rule as `CLUSTER_SCOPE_SQL`. `None` gives False.
  - `describe_scope(scope: dict | None) -> str`:
    - `None` → `"scope not recorded"`
    - cluster scope → `"whole cluster"`
    - otherwise the parts, joined with `", "`: `"namespace web"` or `"namespaces a, b"`, `"namespaces matching team=x"`, `"pods matching app=web"`
    - exclusions are appended as `", excluding namespaces kube-system"` and `", excluding images busybox:*"`
  - `describe_pkg_types(pkg_types: str | None) -> str`: `"library,os"` → `"os + library packages"`, `"os"` → `"OS packages only"`, `"library"` → `"library packages only"`, `None` → `"package types not recorded"`.
  - `ago(then: datetime, now: datetime) -> str`: `"just now"` (under 1 min), `"N min ago"`, `"N h ago"` (under 48 h), otherwise `"N days ago"`.
  - `is_stale(finished_at: datetime | None, now: datetime) -> bool`: True when it's more than 24 h old, or None.
  - `delta(current: int, previous: int | None) -> int | None`.

- [ ] **Step 1: Write the failing tests:**
  - `test_queries.py` seeds runs through `Repo` with a fixed clock (helpers like `tests/store/test_repo.py`, scope strings from `Settings(...).scope`). The tests:
    - `test_newest_run_none`: an empty DB gives None.
    - `test_newest_cluster_run_skips_narrower`: cluster run 1, then `namespaces=["web"]` run 2. With `cluster_scope=True` it returns 1; with False it returns 2.
    - `test_newest_run_skips_failed_cancelled_running_and_other_context`
    - `test_exclusions_still_cluster_scope`: a run with `exclude_images=["busybox:*"]` is returned for `cluster_scope=True`.
    - `test_null_scope_never_cluster`: a run inserted with `scope=None` isn't returned for `cluster_scope=True`.
    - `test_get_run_reasons`: one test per reason string, matched exactly.
    - `test_run_counts_distinct_refs`: one ref on two platforms with one platform failed gives `images == 1` and `images_failed == 1`.
    - `test_run_gaps`: only coverage warnings, in order.
    - `test_previous_comparable`: picks the older run with an equal scope and level. It skips a different scope, a different `pkg_types`, a failed run and NULL scope, and returns None for the first run.
  - `test_analytics.py`: one test per function, with the exact strings above. `is_stale` is False at 23 h 59 m and True at 24 h 1 m.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_queries.py tests/test_analytics.py -q`. Expected: collection fails (`ModuleNotFoundError`).
- [ ] **Step 3:** Implement. `finished_at` is stored as ISO 8601 text, so parse it with `datetime.fromisoformat`.
- [ ] **Step 4:** Run the same command. Expected: all pass.
- [ ] **Step 5:** Commit `feat: add run selection queries and run labels for the ui`.

### Task 3: App factory and security middleware

**Files:**
- Modify: `pyproject.toml` (the three dependencies, plus `[tool.setuptools.package-data] kubedelos = ["web/templates/**/*", "web/static/**/*"]`)
- Create: `kubedelos/web/__init__.py`, `kubedelos/web/app.py`, `kubedelos/web/security.py`, `kubedelos/web/templates/base.html`, `kubedelos/web/templates/error.html`, `kubedelos/web/static/app.css`
- Test: `tests/web/test_security.py`, `tests/web/test_app.py`, `tests/web/conftest.py`

**Interfaces:**
- `security.py` produces:
  - `Guard(token: str, port: int)`:
    - holds the session ids in a set, a random `csrf_secret` (32 bytes) and `allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}`, all lowercase
    - `new_session() -> str` uses `secrets.token_urlsafe(32)`
    - `valid_session(sid: str | None) -> bool`
    - `csrf_token(sid: str) -> str` is the hex HMAC-SHA256 of `sid`
    - `check_csrf(sid: str, sent: str | None) -> bool` uses `hmac.compare_digest`
  - `SESSION_COOKIE = "kubedelos_session"`.
  - `install(app: FastAPI, guard: Guard) -> None` adds one `@app.middleware("http")`. In order:
    1. **Host:** the lowercased `Host` header must be in `allowed_hosts`. Otherwise 400 with plain text `invalid Host header`.
    2. **Nonce:** `request.state.csp_nonce = secrets.token_urlsafe(16)`.
    3. **Token:** the query param `token`, compared with `compare_digest`. If valid, it creates a session and answers 303 to the same path and query without `token`, setting the cookie with `httponly=True`, `samesite="strict"` and `path="/"`. If invalid, it answers 403.
    4. **Session:** paths under `/static/` pass without one. Any other request without a valid cookie gets 403, rendered from `error.html` with the text "Open the URL printed in the terminal where you started `kubedelos ui`."
    5. **CSRF:** any method other than GET or HEAD needs `Origin` (or else `Referer`) whose host is in `allowed_hosts`. It also needs a valid token, sent as the `X-CSRF-Token` header or as the `csrf_token` field of an `application/x-www-form-urlencoded` body. Parse that body with `urllib.parse.parse_qs`. Any other content type, or a failure, gets 403.
    6. **Headers:** on every response, the exact CSP from the spec with the nonce, plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin`. HTML responses also get `Cache-Control: no-store`.
    7. **Access log:** one line per request, `logger "kubedelos.web"`, INFO, formatted `"%s %s %d"` (method, `request.url.path` without the query, status).
- `app.py` produces:
  - `create_app(settings: Settings, *, context: str, token: str, port: int, clock: Callable[[], datetime] = _utcnow) -> FastAPI`.
    - `port` is a Ruling: the spec's signature omits it, but the Host check needs it.
    - It turns off the docs, redoc and openapi routes (`docs_url=None, redoc_url=None, openapi_url=None`).
    - It mounts `/static`, and stores `settings`, `context` and `clock` on `app.state`.
    - It registers `templates` (Jinja2 autoescape on) with a global `csrf_token(request)` and a filter `safe_url(url) -> str | None` (http or https only).
    - It handles `RequestValidationError` by rendering `error.html` with 400 and "invalid parameter: <name>".
  - `open_db(request: Request) -> contextlib.closing[sqlite3.Connection]`, which wraps `connect_readonly(settings.db_path)`. Call it inside each sync endpoint body, so the connection stays on one thread.
  - `render(request, name: str, ctx: dict, status: int = 200) -> HTMLResponse`, which adds `request`, `context`, `nonce` and `nav` to the context.
- `base.html`:
  - a header with the wordmark, the nav (Dashboard `/`, Findings `/findings`), the context label and `{% block run_line %}`
  - `<link rel="stylesheet" href="/static/app.css">`
  - no inline scripts or styles, and no event-handler attributes
- `app.css`:
  - light and dark via `prefers-color-scheme`, with a severity class per level, always next to the word
  - `.table-wrap { overflow-x: auto }` and a layout readable at 360 px
  - `@media print` hides the nav
- `tests/web/conftest.py`:
  - a `client` fixture: `TestClient(create_app(...), base_url="http://127.0.0.1:9370")`, already logged in by fetching `/?token=T` with `follow_redirects=False` (the cookie jar keeps the cookie)
  - a `seed` fixture: a `Repo` on `tmp_path / "data" / "kubedelos.db"` with a fixed clock, `Settings(data_dir=tmp_path / "data")` and the context `my-cluster`
  - Tasks 4–7 reuse both fixtures.
- Ruling for `test_app.py`: a test-only route exists until Task 4 adds `/`. Register a temporary `GET /` that renders `base.html`, and Task 4 replaces it.

- [ ] **Step 1: Write the failing tests in `test_security.py`:**
  - `test_host_header_variants`:
    - 400 for `127.0.0.1:9370.example.com`, `localhost`, `127.0.0.1:9371`, `evil.example.com` and a missing header (send `headers={"host": ""}`)
    - 200 for `127.0.0.1:9370`, `localhost:9370`, `[::1]:9370` and `LOCALHOST:9370`
  - `test_no_session_is_403_with_hint`: the hint text appears in the body.
  - `test_wrong_token_is_403`
  - `test_token_sets_strict_httponly_cookie_and_redirects_without_token`: 303, `location == "/"`, and the `set-cookie` contains `HttpOnly` and `SameSite=strict` (case-insensitive).
  - `test_token_on_deep_link_keeps_other_params`: `/findings?severity=HIGH&token=T&page=2` redirects to `/findings?severity=HIGH&page=2`.
  - `test_static_needs_no_session`: `/static/app.css` is 200 with no cookie.
  - `test_csp_nonce_differs_per_response`: the CSP equals the spec string with the nonce substituted, and two responses carry different nonces.
  - `test_security_headers_present`: all four headers on HTML, plus `cache-control: no-store`.
  - `test_csrf`, on a test-only `POST /_echo` route:
    - 403 without a token, with a bad token, with a good token but a foreign `Origin`, and with `multipart/form-data`
    - 200 with the header, with an urlencoded field, and with no `Origin` but a same-host `Referer`
  - `test_access_log_has_no_query_string`: with `caplog` at INFO, `/?token=T` and `/findings?q=x` are logged, and neither `T` nor `q=x` appears in any record.
- [ ] **Step 2: Write the failing tests in `test_app.py`:**
  - `test_docs_routes_disabled`: `/docs` and `/openapi.json` are 404.
  - `test_safe_url_filter`: http and https pass; `javascript:alert(1)`, `data:x`, `//example.com` and `None` give None.
  - `test_validation_error_renders_400_page`
- [ ] **Step 3:** Run `.venv/bin/pip install -e '.[dev]' && .venv/bin/pytest tests/web -q`. Expected: the install succeeds and the tests fail with `ModuleNotFoundError: kubedelos.web`.
- [ ] **Step 4:** Implement the interfaces above.
- [ ] **Step 5:** Run `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check .`. Expected: all pass and the code is clean.
- [ ] **Step 6:** Commit `feat: add the ui app factory with host, session, csrf and csp protection`.

### Task 4: Dashboard: the run line, KPI tiles and severity bricks

**Files:**
- Create: `kubedelos/web/routes/__init__.py`, `kubedelos/web/routes/dashboard.py`, `kubedelos/web/templates/dashboard.html`, `kubedelos/web/templates/partials/run_line.html`
- Modify: `kubedelos/store/queries.py`, `kubedelos/web/app.py` (include the router and drop the temporary `/`)
- Test: `tests/web/test_dashboard.py`, `tests/store/test_queries.py`

**Interfaces:**
- Consumes: Task 2 (`Run`, `newest_run`, `get_run`, `previous_comparable`, the analytics labels) and Task 3 (`render`, `open_db`, the fixtures).
- Produces in `queries.py`:
  - A frozen dataclass `Kpis`: `critical: int`, `high: int`, `images_with_critical: int`, `images: int`, `findings: int`, `images_failed: int`, `by_severity: dict[str, int]` (all five keys, zeros included).
  - `kpis(conn, run_id: int) -> Kpis`. Every count uses the counting units from Global Constraints. When duplicates of one finding disagree, its severity is the highest rank among them.
  - `FINDING_UNITS_SQL`: a reusable CTE body, keyed on the parameter `:run`. It has one row per finding unit, with these columns:
    - `ref, repo, tag, digest`
    - `vuln_id, pkg_name, installed_version`
    - `fixed_version`: MAX
    - `sev_rank`: MAX, using the rank mapping from `repo._RUN_FINDINGS_SQL`
    - `severity`: derived from `sev_rank`
    - `pkg_class`: MAX
    - `title, primary_url`: MAX
    - `targets`: `group_concat(DISTINCT target)`

    Tasks 5 and 7 build on it.
- `routes/dashboard.py` produces `GET /` with an optional `run_id: int | None = Query(None, ge=1)`. In order:
  1. **Select the run:**
     - With `run_id`, `get_run`; a `RunNotShown` renders `error.html` with 404 and its reason.
     - Otherwise `newest_run(cluster_scope=True)`.
  2. **No cluster run:** if there's none but `newest_run(cluster_scope=False)` exists, render the "no cluster-wide run" state, linking to `/findings?run_id=N`.
  3. **No run at all:** if no run exists, show "No scans of `<context>` yet. Run `kubedelos scan` and reload."
  4. **A newer, narrower run:** if `newest_run(cluster_scope=False)` is newer than the shown run and the page isn't pinned, show the notice from the spec ("a newer run of namespace web exists, from 10 min ago: see its findings"), with `describe_scope` and `ago`.
  5. **KPI tiles:** compute them with `kpis` for the run and for `previous_comparable`. Tiles appear in spec order. The failed tile shows only when `images_failed > 0`.
     - Each delta reads `+N`, `−N` or `±0`. Without a previous run it reads "no earlier comparable run".
     - A delta gets the caution mark (`⚠` plus the text "either run had failed images or skipped namespaces") when either run has `images_failed` or `gaps`.
     - When the shown run has `gaps`, every tile gets the caution mark too.
  6. **Bricks:** Critical, High, Medium and Low always; Unknown only when non-zero. Each links to `/findings?run_id=N&severity=<SEV>`.
- `partials/run_line.html` renders this sentence:

  `Run {id} · {describe_scope} · {describe_pkg_types} · finished {ago} · {images} images, {images_failed} failed`

  - **Pinned:** append "· pinned".
  - **Stale:** add a "stale" badge when `is_stale`.
  - **Gaps:** add "incomplete: N namespaces or resources could not be listed" with the texts in `<details>`.

  Every page uses it.

- [ ] **Step 1: Write the failing tests:**
  - `test_queries.py::test_kpis_counting_units`, on a run with these images:
    - `a` on two platforms, both carrying `CVE-1` openssl 1 (Critical)
    - `a` with `CVE-1` reported twice in one platform (two targets)
    - `b` with `CVE-2` (High) and `CVE-3` (Low)

    Expected: `critical == 1`, `high == 1`, `images == 2`, `images_with_critical == 1`, `findings == 3`, `by_severity["LOW"] == 1`.
  - `test_dashboard.py`:
    - `test_no_runs_empty_state`: the text contains `my-cluster` and `kubedelos scan`.
    - `test_only_narrower_runs`: the page links `/findings?run_id=1`.
    - `test_uses_newest_cluster_run_and_mentions_newer_narrower`: run 1 is cluster scope, run 2 is namespace `web`. The run line shows "Run 1", and the notice links run 2.
    - `test_pinned_run_and_404_reasons`: `?run_id=2` says pinned. A foreign context, a failed run and a missing run each give 404 with their reason text. `?run_id=abc` gives 400.
    - `test_run_line_stale_and_scope_text`: the clock is 25 h after `finished_at`, so the "stale" badge shows. The text includes "whole cluster, excluding images busybox:*" and "os + library packages".
    - `test_gaps_mark_incomplete`: the run line shows "incomplete: 1 namespaces or resources could not be listed", and every tile carries the caution mark.
    - `test_kpi_deltas_against_previous_comparable`: Critical goes 3 → 5, so the tile shows `+2`. A run with a different scope between them is ignored.
    - `test_no_comparable_run_text`
    - `test_failed_tile_only_when_failures`
    - `test_bricks_link_and_unknown_hidden_when_zero`
    - `test_page_renders_while_a_scan_is_writing` (Review Focus 4): a second `connect()` connection does `BEGIN IMMEDIATE`, inserts a `running` run of `my-cluster` and stays open. Requests to `/` still return 200 within 2 s and show the previous run.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_dashboard.py tests/store/test_queries.py -q`. Expected: the new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit `feat: add the ui dashboard run line, kpi tiles and severity bricks`.

### Task 5: Dashboard: the fix-first list

**Files:**
- Modify: `kubedelos/store/queries.py`, `kubedelos/web/routes/dashboard.py`, `kubedelos/web/templates/dashboard.html`
- Test: `tests/store/test_queries.py`, `tests/web/test_dashboard.py`

**Interfaces:**
- Consumes: `FINDING_UNITS_SQL` and the dashboard route.
- Produces in `queries.py`:
  - `FixRow`:
    - the group: `vuln_id`, `pkg_name`, `fixed_version`, `severity: str`
    - `installed: list[str]` (sorted, distinct), `primary_url: str | None`
    - counts: `images: int`, `namespaces: int`
    - `sample: list[tuple[str, list[str]]]`: up to 20 (ref, sorted namespaces) pairs, sorted by ref
  - `ImageFixRow`: `ref`, `namespaces: list[str]`, `critical: int`, `high: int`, `fixable: int`.
  - `fix_by_fix(conn, run_id: int, limit: int = 25) -> tuple[list[FixRow], int]`:
    - **Scope:** Critical and High units with a non-empty `fixed_version`, grouped in SQL by (`vuln_id`, `pkg_name`, `fixed_version`).
    - **Sort:** `sev_rank` DESC, images DESC, namespaces DESC, `vuln_id`.
    - **Returns:** the first `limit` groups and the total number of groups.
    - **Samples:** fetched for the page's groups in one more query, using `ROW_NUMBER() OVER (PARTITION BY ...) <= 20`.
  - `fix_by_image(conn, run_id: int, limit: int = 25) -> tuple[list[ImageFixRow], int]`:
    - **Scope:** images with at least one fixable Critical or High unit.
    - **Counts:** `critical` and `high` count every unit of that severity; `fixable` counts the Critical and High units that have a fix.
    - **Sort:** critical DESC, high DESC, ref.
  - `no_fix_summary(conn, run_id: int) -> tuple[int, int]`: the Critical and High units without a fix, and their distinct images.
- The dashboard handles `by: Literal["fix", "image"] = "fix"`, and it renders the list and the summary as the spec describes:
  - **Expanders:** each fix row is a `<details>`. Below the sample, if `images > 20`, it reads "and N more" and links to `/findings?run_id=N&cve=<vuln_id>&package=<pkg_name>`.
  - **Overflow:** "showing 25 of N" links to `/findings?run_id=N&severity=CRITICAL&severity=HIGH&has_fix=yes`.
  - **No-fix line:** links to `/findings?run_id=N&severity=CRITICAL&severity=HIGH&has_fix=no`.
  - **Links:** the CVE links only through `safe_url`, with `rel="noopener noreferrer"`. All query strings are built with `urllib.parse.urlencode`.

- [ ] **Step 1: Write the failing tests:**
  - `test_queries.py::test_fix_by_fix_groups_one_base_image_rebuild`: 30 images share `CVE-9` openssl `1.1 → 1.2`, and one image has `CVE-8`. Expected: 2 rows, with the `CVE-9` row first, `images == 30` and a sample of 20.
  - `test_queries.py::test_fix_by_fix_sort_and_total`: severity before image count, and namespaces break ties. 30 groups with `limit=25` return 25 rows and a total of 30.
  - `test_queries.py::test_fix_lists_skip_unfixed_medium_and_low`
  - `test_queries.py::test_installed_versions_distinct_sorted`
  - `test_queries.py::test_fix_by_image_counts_and_sort`
  - `test_queries.py::test_no_fix_summary`
  - `test_dashboard.py::test_fix_list_default_and_by_image`: `?by=image` shows image rows; `?by=bogus` gives 400.
  - `test_dashboard.py::test_fix_list_overflow_and_more_links`: "showing 25 of 30" appears, and "and 10 more" links to `cve=CVE-9&package=openssl`.
  - `test_dashboard.py::test_dashboard_links_carry_run_id`: every `/findings` link on the page has `run_id=`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_queries.py tests/web/test_dashboard.py -q`. Expected: the new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit `feat: add the fix-first list to the ui dashboard`.

### Task 6: Dashboard: failed images, login hints and the zero-findings state

**Files:**
- Create: `kubedelos/hints.py`, `tests/test_hints.py`
- Modify: `kubedelos/cli.py` (import `login_hint` and delete `_login_hint`; the existing CLI hint tests in `tests/test_cli.py` stay as they are and must keep passing), `kubedelos/store/queries.py`, `kubedelos/web/routes/dashboard.py`, `kubedelos/web/templates/dashboard.html`
- Test: `tests/test_hints.py`, `tests/store/test_queries.py`, `tests/web/test_dashboard.py`

**Interfaces:**
- Produces:
  - `hints.login_hint(host: str) -> str`: today's `cli._login_hint`, moved with the same body. The CLI output doesn't change.
  - `queries.failed_images(conn, run_id: int, limit: int = 25) -> tuple[list[sqlite3.Row], int]`: rows of (ref, platform, error_kind, error) ordered by ref and platform, plus the total number of failed rows.
  - On the dashboard:
    - **Failed images:** a section that shows only when some images failed. It renders `trivy.runner.error_cause(error)` per row, then one `login_hint` per distinct registry host among the `auth` rows, using `registry_host(parse_image_id(ref, ""))` as the CLI does. Over the cap it says "showing 25 of N".
    - **Zero findings:** when `kpis.findings == 0`, the page reads "No vulnerabilities found in N images." when no image failed, and otherwise "No vulnerabilities found in the N images that scanned; M failed to scan."

- [ ] **Step 1: Write the failing tests:**
  - `test_hints.py`: one case per branch: ACR (`myreg.azurecr.io` → `az acr login --name myreg`), GCR and Artifact Registry (`gcloud auth configure-docker`), ECR (`--region eu-west-1`), and the `docker login` default.
  - `test_queries.py::test_failed_images_cap_and_total`
  - `test_dashboard.py::test_failed_images_show_cause_and_one_hint_per_host`: two `auth` failures on `registry.example.com` and one `not_found`. The page shows the Trivy cause (stored error: a real-shaped `FATAL` line with `* MANIFEST_UNKNOWN` cause bullets) and exactly one `docker login registry.example.com` hint.
  - `test_dashboard.py::test_zero_findings_clean_vs_broken`: both wordings.
  - `test_dashboard.py::test_hostile_strings_are_escaped` (Review Focus 1): these are seeded:
    - ref `reg.example.com/<script>x</script>:1`; the ref is stored as given, because `Repo` doesn't validate
    - title `<img src=x onerror=alert(1)>`
    - `primary_url` `javascript:alert(1)`
    - warning text `<b>ns</b>`

    The raw `<script>`, `<img` and `<b>ns` never appear unescaped, and no `href="javascript:` appears.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_hints.py tests/test_cli.py tests/store/test_queries.py tests/web/test_dashboard.py -q`. Expected: the new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit `feat: show failed images with their cause and login hints on the dashboard`.

### Task 7: Findings page

**Files:**
- Create: `kubedelos/web/routes/findings.py`, `kubedelos/web/templates/findings.html`
- Modify: `kubedelos/store/queries.py`, `kubedelos/web/app.py`
- Test: `tests/web/test_findings.py`, `tests/store/test_queries.py`

**Interfaces:**
- Consumes: `FINDING_UNITS_SQL`, `newest_run(cluster_scope=False)`, `get_run`, the run-line partial and `output._table_image`. Rename it to `output.short_image` and update its one caller.
- Produces in `queries.py`:
  - A frozen dataclass `FindingFilter`:
    - `severities: tuple[str, ...] = ()`
    - `namespace: str | None = None`, `cve: str | None = None`, `package: str | None = None`
    - `has_fix: Literal["any", "yes", "no"] = "any"`
    - `pkg: Literal["all", "os", "library"] = "all"`
    - `q: str | None = None`
    - `sort: Literal["severity", "cve", "package", "image", "namespace", "fixed"] = "severity"`, `desc: bool = True`
  - `findings_page(conn, run_id: int, f: FindingFilter, page: int, per_page: int = 100) -> tuple[list[sqlite3.Row], int]`:
    - **Columns:** the unit columns plus `namespaces`, the run's distinct namespaces for that ref.
    - **One set:** one CTE applies the filters, and both the `COUNT(*)` and the `LIMIT/OFFSET` read it.
    - **Namespace filter:** an `EXISTS` on a workload of that ref in the run.
    - **`q`:** matches `ref`, `vuln_id` or `pkg_name` with `LIKE ? ESCAPE '\'`, after escaping `\`, `%` and `_`.
    - **`pkg`:** `os` and `library` match `pkg_class`, so NULL classes match only `all`.
    - **Sort keys:**
      - `severity`: `sev_rank`
      - `namespace`: the smallest namespace
      - `fixed`: `fixed_version`, NULLs last
    - **Tie-breaks:** `vuln_id`, then `ref`.
    - **Default order:** severity worst first, then CVE, then image.
  - `run_namespaces(conn, run_id: int) -> list[str]`, sorted.
- `GET /findings`:
  - **Parameters:** `run_id`, `severity: list[Severity] = Query([])`, `namespace`, `cve`, `package`, `has_fix`, `pkg`, `q`, `sort`, `dir: Literal["asc", "desc"] | None`, `page: int = Query(1, ge=1)`. A bad value gives 400 through the Task 3 handler.
  - **Run:** the pinned run, or else `newest_run(cluster_scope=False)`. With no run at all, it shows the dashboard's empty-state text.
  - **Filter form:** a plain GET form with a "clear filters" link to `/findings?run_id=N`.
  - **Headings:** a column heading links to the same URL with `sort=<col>`. The active column flips `dir`.
  - **Paging:** "X–Y of N", plus previous and next links that keep every filter. A page past the end shows "page P is past the end (N findings)" and links to the last page.
  - **OS-only note:** when the run's `pkg_types == "os"`, show "this run scanned OS packages only; library findings were not collected".
  - **No matches:** "No findings match these filters", with the clear link.
  - **Columns:**
    - severity word, CVE (linked through `safe_url`), package, installed, fixed in, package class
    - the image as `short_image`, with the full ref in `title`
    - namespaces: the first 3, then "+N"

- [ ] **Step 1: Write the failing tests:**
  - `test_queries.py`:
    - `test_findings_page_units_and_total`: the Task 4 dataset gives a total of 3, with the duplicate targets merged into one row.
    - `test_findings_filters` (one assertion per filter): severity; namespace; cve; package; has_fix yes and no; pkg os, library and all, with NULL `pkg_class` appearing only under all.
    - `test_findings_sort_each_key_and_direction`
    - `test_findings_paging_total_matches_rows`: 250 units give 100, 100 and 50 rows, with a total of 250 each time.
    - `test_q_matches_wildcards_literally` (Review Focus 5): packages `lib_a`, `libxa` and `100%`. `q="_a"` matches only `lib_a`, and `q="%"` matches only `100%`.
  - `test_findings.py`:
    - `test_default_run_is_newest_any_scope`: run 2 (namespace `web`) is shown.
    - `test_filters_round_trip_in_links`: on page 1 of 250 with `severity=HIGH&q=lib`, the next link holds `severity=HIGH`, `q=lib` and `page=2`.
    - `test_sort_header_toggles_dir`
    - `test_invalid_params_400`: `severity=BAD`, `page=0`, `sort=x`, `pkg=jar`.
    - `test_os_only_note`
    - `test_empty_and_past_end_states`
    - `test_namespaces_cell_truncates`: 5 namespaces render as 3 plus "+2".
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_queries.py tests/web/test_findings.py tests/test_output.py -q`. Expected: the new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Commit `feat: add the ui findings page with url filters, sorting and paging`.

### Task 8: The `kubedelos ui` command and packaging

**Files:**
- Create: `kubedelos/web/server.py`, `tests/web/test_server.py`
- Modify: `kubedelos/cli.py`, `tests/test_cli.py`
- Create: `tests/test_packaging.py`

**Interfaces:**
- `server.py` produces:
  - `LOOPBACK = {"127.0.0.1": "127.0.0.1", "::1": "::1", "localhost": "127.0.0.1"}`, mapping each `--host` value to its bind address.
  - `bind(host: str, port: int) -> socket.socket`:
    - `AF_INET6` for `::1`, `AF_INET` otherwise, with `SO_REUSEADDR` and `listen()`
    - an `EADDRINUSE` raises `PortInUse(port)`; any other `OSError` propagates
  - `url(host: str, port: int, token: str) -> str`: `http://127.0.0.1:9370/?token=…`; `::1` becomes `http://[::1]:9370/…`, and `localhost` stays as is.
  - `serve(app: FastAPI, sock: socket.socket) -> None`: `uvicorn.Server(uvicorn.Config(app, workers=1, access_log=False, log_level="warning", lifespan="off")).run(sockets=[sock])`. uvicorn handles Ctrl-C.
- `cli.ui(port: int = 9370, host: str = "127.0.0.1", no_browser: bool = False, context: str | None = None, kubeconfig: Path | None = None)`:
  1. `host` not in `LOOPBACK` → `error: --host must be 127.0.0.1, ::1 or localhost`, exit 2.
  2. `settings = _load_settings(context=..., kubeconfig=...)`.
  3. Context: `kube_client.load(settings).current_context()`. An exception gives `error: {_flat(exc)}`, exit 2.
  4. `connect(settings.db_path).close()` creates the database and runs the migrations.
  5. Generate `token = secrets.token_urlsafe(32)`, then `sock = bind(...)`. `PortInUse` gives `error: port {port} is in use; pass --port`, exit 2.
  6. Echo `kubedelos ui for context {context}: {url}` on stdout, and say Ctrl-C stops it. Open the browser with `webbrowser.open(url)` unless `--no-browser`. Then `serve(create_app(settings, context=context, token=token, port=port), sock)`.
- Logging: `kubedelos.web` access lines go to stderr only with `KUBEDELOS_LOG_LEVEL=info`. This is a Ruling: the spec is silent, and a quiet terminal keeps the printed URL visible. The variable is read in `cli.ui` and not added to `Settings`.

- [ ] **Step 1: Write the failing tests:**
  - `test_server.py`:
    - `test_bind_port_in_use_raises`: bind once, then again on the same port.
    - `test_url_forms`: all three hosts.
    - `test_bind_ipv6_loopback`: skipped when `socket.has_ipv6` is False.
  - `test_cli.py`, with `monkeypatch` on `kube_client.load`, `server.serve` (records its arguments), `server.bind` and `webbrowser.open`:
    - `test_ui_rejects_non_loopback_host`: `--host 0.0.0.0` exits 2.
    - `test_ui_port_in_use_exits_2`: the message is matched exactly.
    - `test_ui_bad_context_exits_2`
    - `test_ui_prints_url_and_opens_browser`: the token in the printed URL equals the one passed to `create_app`, and `--no-browser` suppresses `webbrowser.open`.
    - `test_ui_creates_and_migrates_db`: after the command, `user_version == len(MIGRATIONS)`.
  - `test_packaging.py::test_wheel_contains_templates_and_static`:
    - build with `subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", tmp, repo_root], check=True)`
    - the zip contains `kubedelos/web/templates/base.html`, `kubedelos/web/templates/partials/run_line.html` and `kubedelos/web/static/app.css`
    - it needs network for the isolated build, like CI's install step
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_server.py tests/test_cli.py tests/test_packaging.py -q`. Expected: the new tests fail.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5:** Smoke test. Run `KUBEDELOS_DATA_DIR=$(mktemp -d) .venv/bin/kubedelos ui --no-browser --port 9371` in the background, then `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9371/`. Expected: `403`. Opening the printed URL with `curl -i` gives `303` and a `set-cookie`. Stop the server.
- [ ] **Step 6:** Commit `feat: add kubedelos ui to serve the local web ui on loopback`.

### Task 9: Indexes measured against 100,000 findings

**Files:**
- Modify: `kubedelos/store/db.py` (migration 5), `pyproject.toml` (marker `perf`, which `addopts` excludes like `e2e`)
- Create: `tests/web/test_perf.py`, `tests/web/seed.py` (a seeder that writes rows with `executemany`, not `Repo`, for speed)

**Interfaces:**
- `seed.seed_large(conn, *, images: int = 1000, findings: int = 100_000, namespaces: int = 50) -> int`:
  - writes one `ok` cluster-scope run and returns its id
  - the data is deterministic: severities in a fixed rotation, 40% with a fix, 10 platforms duplicated, 2% failed images
- Migration 5 starts with `CREATE INDEX idx_scan_run_context ON scan_run(context, status, id); CREATE INDEX idx_finding_vuln ON finding(vuln_id);`. Add to it whatever `EXPLAIN QUERY PLAN` shows the Task 4–7 queries need: no full `SCAN finding` and no `SCAN image_result` without an index.

- [ ] **Step 1: Write the tests:**
  - `test_query_plans_use_indexes` runs by default. It captures `EXPLAIN QUERY PLAN` for `newest_run`, `kpis`, `fix_by_fix`, `findings_page` (the default filter and `q`) and `failed_images`. It asserts no detail line matches `^SCAN (finding|image_result|workload)\b`; `q` may scan the run's own rows, which is reached via the index.
  - `test_pages_under_300ms`, marked `perf`: seed, warm one request per page, then time `/`, `/?by=image`, `/findings`, `/findings?q=lib&sort=package` and the last findings page. Each takes under 0.3 s, as the median of 3.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_perf.py -q -m 'perf or not perf'`. Expected: the plan test fails on at least one full `SCAN`, unless Tasks 4–7 already used only indexed paths; record what the run shows.
- [ ] **Step 3:** Add migration 5 with the indexes the plans need, then re-run until both tests pass. Record the final timings in the commit body.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all pass, with perf deselected.
- [ ] **Step 5:** Commit `perf: index the ui queries and pin page time on a 100k-finding db`.

### Task 10: Docs, changelog and the real check

**Files:**
- Modify: `README.md` (a "Local web UI" section: the command, the loopback-only rule, `ssh -L 9370:127.0.0.1:9370 host`, what each page shows), `CHANGELOG.md` (`## Unreleased`, Features), `AGENTS.md` ("the local UI will be `kubedelos ui` (Phase 2)" becomes "`kubedelos ui` serves the local UI")

- [ ] **Step 1:** Write the docs. Example names stay as placeholders: `my-cluster` and `registry.example.com`.
- [ ] **Step 2: Real check:**
  1. Run `scripts/e2e-kind.sh` up to its scan, or scan an existing kind cluster with `.venv/bin/kubedelos scan --context kind-…`, then a second, `-n web` scan.
  2. Run `.venv/bin/kubedelos ui --context kind-…` and open the printed URL.
  3. Check that the dashboard shows the cluster run and the notice about the newer `web` run, that the fix list and expanders work, and that each findings filter, sort and page link works.
  4. Take screenshots in light and dark at 1280 px and 390 px width, and save them to the scratchpad. They aren't committed.
- [ ] **Step 3:** Run `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pre-commit run --all-files`. Expected: all pass and the code is clean.
- [ ] **Step 4:** Commit `docs: document kubedelos ui`.
- [ ] **Step 5:** Run `/security-review` on the branch and fix what it confirms, each fix with a failing test first.
