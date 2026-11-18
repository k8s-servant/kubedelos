# kubedelos serve, scheduler, scan queue and retention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `kubedelos serve`, a view-only UI for a pod that also sweeps the cluster on a cron schedule through a SQLite scan queue and prunes old runs. This is PR 1 of the in-cluster design.

**Architecture:** `serve` runs uvicorn on a non-loopback address with a serve-specific security middleware (Host allow-list, security headers, every write refused). The same process runs an APScheduler `BackgroundScheduler`, which only enqueues `schedule` requests into a new `scan_request` table, and a queue worker thread. The worker feeds requests one at a time to the existing `ScanRunner` and prunes old runs after each finished sweep. An exclusive `flock` on `<data dir>/serve.lock` keeps a second `serve` off the same volume.

**Tech Stack:** Python 3.12+, FastAPI, Jinja2, SQLite, APScheduler 3.11.

**Spec:** `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md`, sections 1–3, plus "Delivery" item 1. Identity, CSRF in `serve` and the scope narrowing rule are PR 2 and are out of scope here.

## Global Constraints

- Read-only cluster access: no code path may change cluster objects or read Secrets.
- Trivy stays pinned (v0.76.1) with `--scanners vuln` only. Nothing here touches the runner's argv.
- Credentials never touch disk or logs.
- Python 3.12+. The new dependency is `apscheduler>=3.11,<4` (comment: `# serve: the sweep schedule`).
- TDD: write each test first and watch it fail. One test file per module (`kubedelos/x/y.py` → `tests/x/test_y.py`).
- Ruff line length 120; `ruff check` and `ruff format --check` stay clean. Every new module starts with a docstring
  saying what and why.
- Placeholders only: `my-cluster`, `example.com`.
- Conventional Commits with lowercase subjects and no co-author or attribution lines. Work on branch `feat/serve`.
- `CHANGELOG.md` gets entries under `## Unreleased`; the README gets a `kubedelos serve` section.
- `kubedelos ui` behaviour does not change. Every existing test keeps passing.
- Spec values:
  - `KUBEDELOS_SWEEP_SCHEDULE`: default `0 3 * * *`.
  - `KUBEDELOS_SWEEP_TIMEZONE`: default `UTC`.
  - `KUBEDELOS_SWEEP_ENABLED`: default `true`.
  - `KUBEDELOS_RETENTION_DAYS`: default `180`; `0` keeps everything.
  - `KUBEDELOS_CLUSTER_NAME`: required by `serve`.
  - `KUBEDELOS_ALLOWED_HOSTS`: comma or JSON list.
  - Scheduler job options: `coalesce=True`, `max_instances=1`, `misfire_grace_time=3600`.
  - Queue: at most 10 queued requests.
  - Bind: `serve` listens on `0.0.0.0:8080` by default.

## Rulings this plan makes on top of the spec

These are the builder's calls; the spec leaves them open.

- **Writes in `serve`.** PR 1's `serve` refuses every non-GET/HEAD request with 403 and a "view-only" page, because
  identity arrives in PR 2. The forms still render, and PR 2 hides them.
- **Host allow-list.** `KUBEDELOS_ALLOWED_HOSTS` arrives here rather than in PR 2, because `serve` can't answer any
  request without it.
  - The default is `localhost,127.0.0.1`.
  - Hosts are matched on the hostname, with any port dropped, ignoring case. `[::1]` matches `::1`.
- **Liveness.** `/healthz` skips the Host check, because kubelet probes use the pod IP.
- **Lifecycle.** The scheduler and the worker are started and stopped by `cli.serve` around `server.serve`, not by a
  FastAPI lifespan. `server.serve` already runs with `lifespan="off"` and already stops the runner.
- **Requests left `started`.** Requests left `started` with no run by a dead process become `cancelled` when `serve`
  starts.
- **Context and cluster name.** `Settings.context` stays the kubeconfig context (normally unset in a pod), and
  `Settings.cluster_name` is only the name runs are stored and shown under.

## Review Focus

1. **Restart mid-sweep.** A pod restart in the middle of a sweep leaves a `started` request and a `running` run. The
   next `serve` must close both and then run the next queued request, not hang or rerun the started one. *Pinned in
   Task 2 (`abandon_started`) and Task 7 (startup order).*
2. **Retention must never delete:**
   - a `running` run;
   - the newest `ok`/`partial` run of a (context, scope, scan level);
   - a run a queued request still points at.

   Nor may it fail on the foreign keys from `scan_request`. *Pinned in Task 3.*
3. **Bad settings.** A bad cron expression or time zone in the ConfigMap must exit 2 with one clear line, not a
   traceback and not a silent "never sweeps". *Pinned in Task 1 (time zone) and Task 5 (cron).*
4. **Host header forms.** The Host header arrives as `example.com:8080`, `EXAMPLE.com`, `[::1]:8080`, a pod IP on
   `/healthz`, or missing. Allowed names must pass with or without a port, and everything else must get a 400.
   *Pinned in Task 6.*
5. **Sweep coalescing.** A sweep that fires while another sweep is running (started, not queued) must still be
   queued once. Two firings while one sweep is queued must leave exactly one queued. *Pinned in Task 2.*

---

### Task 1: Settings, migration 10 and the requester on runs

**Files:**
- Modify: `kubedelos/config.py`, `kubedelos/store/db.py` (append migration 10), `kubedelos/store/repo.py:49-66`,
  `kubedelos/scan/service.py:50-92`
- Test: `tests/test_config.py`, `tests/store/test_repo.py`, `tests/scan/test_service.py`

**Interfaces:**
- Produces:
  - `Settings` fields:
    - `cluster_name: str | None = None`
    - `sweep_schedule: str = "0 3 * * *"`
    - `sweep_timezone: str = "UTC"`
    - `sweep_enabled: bool = True`
    - `retention_days: int = Field(180, ge=0)`
    - `allowed_hosts: list[str] = ["localhost", "127.0.0.1"]`, lowercased and with any brackets stripped.
  - `Repo.start_run(..., requested_by: str | None = None)` stores it in `scan_run.requested_by`.
  - `run_scan(..., requested_by: str | None = None)` stores runs under `settings.cluster_name` when set, otherwise
    `api.current_context()`.
  - Table `scan_request` with columns `id, kind, trigger, requested_by, requested_at, target_run_id, overrides, state,
    run_id`, exactly as in spec section 2. Add the index `idx_scan_request_state ON scan_request(state, id)`.

- [ ] **Step 1: Write failing tests**
  - `test_sweep_timezone_must_be_a_known_zone`: `Settings(sweep_timezone="Mars/Olympus")` raises `ValidationError`
    naming `sweep_timezone`; `"Europe/Vilnius"` is accepted.
  - `test_allowed_hosts_normalised`:
    `Settings(allowed_hosts=["Example.COM", "[::1]"]).allowed_hosts == ["example.com", "::1"]`.
  - `test_retention_days_not_negative`: `-1` raises.
  - `test_start_run_stores_requested_by` (test_repo):
    `repo.get_run(repo.start_run("my-cluster", "ui", "0.76.1", scan_level="os", requested_by="a@example.com"))["requested_by"] == "a@example.com"`.
  - `test_migration_10_adds_scan_request` (test_repo): on a fresh DB, `PRAGMA user_version == 10`. Inserting a
    `scan_request` row with `state='done'` raises `sqlite3.IntegrityError`.
  - `test_run_scan_stores_the_cluster_name` (test_service): with the fake API whose context is `kind-x`,
    `run_scan(settings.model_copy(update={"cluster_name": "my-cluster"}), ...)` records context `my-cluster`. Without
    `cluster_name`, it records `kind-x`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_config.py tests/store/test_repo.py tests/scan/test_service.py -q`.
  Expected: the new tests FAIL.
- [ ] **Step 3: Implement.**
  - The time zone validator uses `zoneinfo.ZoneInfo` and turns `ZoneInfoNotFoundError` and `ValueError` into a
    `ValueError`.
  - Migration 10 is one script: `ALTER TABLE scan_run ADD COLUMN requested_by TEXT;`, plus the `scan_request` table
    and its index, under a comment `# 10: ...` in the style of the others.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: add the serve settings and the scan request table`.

### Task 2: The scan queue (`kubedelos/store/queue.py`)

**Files:**
- Create: `kubedelos/store/queue.py`
- Test: `tests/store/test_queue.py`

**Interfaces:**
- Consumes: the `scan_request` table (Task 1).
- Produces:
  ```python
  MAX_QUEUED = 10
  class QueueFull(Exception): ...
  @dataclass(frozen=True)
  class Request:
      id: int; kind: str; trigger: str; requested_by: str | None; requested_at: str
      target_run_id: int | None; overrides: dict; state: str; run_id: int | None
  @dataclass(frozen=True)
  class Enqueued:
      id: int; added: bool  # added False: an equal request was already queued and its id is returned
  def canonical(overrides: dict) -> str  # json.dumps(sort_keys=True, separators=(",", ":"), default=list)
  def enqueue(conn, *, kind: str, trigger: str, overrides: dict, requested_by: str | None = None,
              target_run_id: int | None = None, now: datetime) -> Enqueued
  def claim_next(conn) -> Request | None     # oldest queued -> started, atomically
  def attach_run(conn, request_id: int, run_id: int | None) -> None
  def cancel(conn, request_id: int) -> bool  # only a queued request; True when it was cancelled
  def queued(conn) -> list[Request]          # oldest first
  def abandon_started(conn) -> int           # started with run_id NULL -> cancelled; returns the count
  ```
- Coalescing rules (spec section 2):
  - a `schedule` request matches any queued `schedule` request;
  - a `ui` `scan` request matches a queued `ui` `scan` request with equal `canonical(overrides)`;
  - a `retry` request matches a queued `retry` request with the same `target_run_id`.

  Coalescing is checked before the bound. `enqueue` and `claim_next` each run in one `BEGIN IMMEDIATE` transaction, so
  two threads can never both add or both claim.

- [ ] **Step 1: Write failing tests**
  - `test_schedule_requests_coalesce_while_queued`: two schedule enqueues → the second has `added is False` and the same
    id; `len(queued(conn)) == 1`.
  - `test_schedule_is_queued_again_once_the_first_started`: enqueue, `claim_next`, enqueue → `added is True`.
  - `test_ui_requests_coalesce_on_equal_overrides`: `{"namespaces": ["a", "b"]}` and the same dict with its keys in
    another order coalesce; `{"namespaces": ["a"]}` does not.
  - `test_retries_coalesce_per_run`.
  - `test_queue_is_bounded`: after 10 distinct queued requests, the 11th raises `QueueFull`. A coalescing 11th still
    returns `added=False` without raising.
  - `test_claim_next_is_fifo_and_skips_cancelled`.
  - `test_claim_from_two_threads_never_returns_the_same_request`: 2 threads, each with its own connection, 20 requests
    queued in batches under the bound. The union of the claimed ids has no duplicates.
  - `test_cancel_only_queued`: `cancel` on a started request returns False and leaves its state.
  - `test_abandon_started_cancels_orphans_only`: a started request with `run_id` NULL becomes `cancelled`; one with a
    run stays `started`.
  - `test_overrides_round_trip`: `claim_next(...).overrides == {"pkg_types": ["os"], "rescan": True}` for the tuple
    `("os",)` passed in.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_queue.py -q`. Expected: FAIL (module missing).
- [ ] **Step 3:** Implement `kubedelos/store/queue.py`. Write `requested_at` with `now.isoformat()`, as `Repo._now` does.
- [ ] **Step 4:** Run `.venv/bin/pytest tests/store/test_queue.py -q`. Expected: PASS.
- [ ] **Step 5:** Commit `feat: add the sqlite scan queue`.

### Task 3: Retention (`kubedelos/store/retention.py`)

**Files:**
- Create: `kubedelos/store/retention.py`
- Test: `tests/store/test_retention.py`

**Interfaces:**
- Consumes: the schema through migration 10.
- Produces: `prune(conn, *, now: datetime, retention_days: int, cache_max_age: timedelta = timedelta(hours=24)) -> list[int]`,
  which returns the deleted run ids.
  - `retention_days == 0` deletes no runs but still prunes the cache.
- What is deleted, in one transaction:
  - runs with `started_at < now - retention_days` (ISO text comparison, the same format `Repo._now` writes) and status
    not `running`;
  - except the newest `ok`/`partial` run per `(context, scope, pkg_types)`;
  - except any run that a `queued` request names as `target_run_id`.

  For each deleted run, delete its `finding`, `workload`, `image_result` and `run_warning` rows, and set `run_id` /
  `target_run_id` to NULL on non-queued `scan_request` rows that point at it.

  Also delete `scan_request` rows that are not `queued` and whose `requested_at` is before the cutoff, and
  `image_cache` rows whose `scanned_at` is before `now - cache_max_age`. Never touch `acceptance`.

- [ ] **Step 1: Write failing tests**. Seed with `Repo` and a fixed clock, as `tests/store/test_repo.py` does.
  - `test_old_runs_and_their_rows_are_deleted`: a 200-day-old `ok` run with a newer comparable `ok` run → the old
    run's id is returned and no `finding`, `workload` or `image_result` row of it remains.
  - `test_newest_result_run_of_each_scope_is_kept_however_old`: the only run of a scope, 400 days old, stays.
  - `test_running_runs_are_never_deleted`.
  - `test_run_named_by_a_queued_retry_is_kept`.
  - `test_finished_requests_pointing_at_deleted_runs_are_detached`: no `IntegrityError`; `run_id` is NULL afterwards.
  - `test_zero_keeps_every_run_but_prunes_the_cache`.
  - `test_acceptances_are_untouched`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_retention.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement `prune`.
- [ ] **Step 4:** Run `.venv/bin/pytest tests/store/test_retention.py -q`. Expected: PASS.
- [ ] **Step 5:** Commit `feat: prune runs past the retention period`.

### Task 4: The serve lock

**Files:**
- Modify: `kubedelos/store/runlock.py`
- Test: `tests/store/test_runlock.py`

**Interfaces:**
- Produces: `class AlreadyServing(Exception)` and `@contextlib.contextmanager def hold_serve(data_dir: Path) -> Iterator[None]`.
  - It takes an exclusive non-blocking lock on `<data_dir>/serve.lock` (created 0600 if missing, never deleted) using
    the module's `_try_lock` and `_unlock`.
  - When another holder has it, it raises `AlreadyServing(f"another kubedelos serve uses {data_dir}")`.
  - Extend the module docstring by one sentence.

- [ ] **Step 1: Write failing tests**
  - `test_second_serve_lock_is_refused`: nested `hold_serve(tmp_path)` raises `AlreadyServing`.
  - `test_serve_lock_is_released_on_exit`: a second `hold_serve` after the first block exits succeeds.
  - `test_serve_lock_held_by_another_process`: a `subprocess` Python holds it and prints "held". The parent then gets
    `AlreadyServing`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/store/test_runlock.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest tests/store/test_runlock.py -q`. Expected: PASS.
- [ ] **Step 5:** Commit `feat: let one kubedelos serve own a data directory`.

### Task 5: ScanRunner for a fixed cluster, the sweep scheduler and the queue worker

**Files:**
- Modify: `kubedelos/web/jobs.py`
- Create: `kubedelos/scheduler.py`, `kubedelos/web/worker.py`
- Modify: `pyproject.toml` (add `"apscheduler>=3.11,<4",  # serve: the sweep schedule`)
- Test: `tests/web/test_jobs.py`, `tests/test_scheduler.py`, `tests/web/test_worker.py`

**Interfaces:**
- Consumes: `queue.enqueue`, `claim_next`, `attach_run` and `abandon_started` (Task 2); `retention.prune` (Task 3);
  `run_scan(..., requested_by=)` (Task 1).
- Produces:
  - `ScanRunner.__init__(..., fixed_cluster: bool = False)`.
    - When true, `context` is only the display name. `start()` and `retry()` raise `ValueError` for any other
      `context` argument and do not put `context` into the scan settings, so `Settings.context` (the kubeconfig
      context, normally None in a pod) is kept.
    - When false, behaviour is unchanged.
  - `ScanRunner.start(overrides, context=None, *, rescan=False, trigger: str = "ui", requested_by: str | None = None)`,
    which passes `trigger` and `requested_by` to the scan callable.
  - `kubedelos/scheduler.py`:
    - `def cron_error(expr: str, timezone: str) -> str | None` returns None when valid, else one line naming the
      setting.
    - `class Sweeper`:
      - `__init__(self, settings: Settings, on_fire: Callable[[], None])`;
      - `start() -> None`, `stop() -> None`;
      - `next_run() -> datetime | None`, None when `sweep_enabled` is false or the scheduler is stopped.

      It uses `BackgroundScheduler(timezone=ZoneInfo(tz))` and `CronTrigger.from_crontab(expr,
      timezone=ZoneInfo(tz))`, with job id `sweep` and the spec's three job options. `start()` with
      `sweep_enabled=False` schedules nothing.
  - `kubedelos/web/worker.py`: `class QueueWorker`:
    - `__init__(self, settings: Settings, runner: ScanRunner, *, clock, poll_s: float = 2.0)`;
    - `enqueue_sweep() -> None`, which adds `kind="scan", trigger="schedule", overrides={}` and calls `wake()`;
    - `wake() -> None`, `start() -> None`, `stop() -> None`;
    - `alive() -> bool`.

    Each connection is opened with `db.connect(settings.db_path)` on the thread that uses it.
- Worker loop: wait on a `threading.Event` with timeout `poll_s`, until stopped. Each pass does this:
  ```
  view = runner.view()
  if view is active: continue
  if current is not None:                       # the request the worker last started has ended
      attach_run(conn, current.id, view.run_id)  # None when the scan raised
      if current.trigger == "schedule" and view.status in ("ok", "partial"):
          retention.prune(conn, now=clock(), retention_days=settings.retention_days)
      current = None
  req = claim_next(conn)
  if req is None: continue
  validate: Settings.model_validate({**settings.model_dump(), **overrides without "rescan"/"kinds"})  -> on
      ValidationError: attach_run(conn, req.id, None), log at debug, continue
  scan:  runner.start(<validated FIELDS of jobs/scans>, rescan=overrides.get("rescan", False),
                      trigger=req.trigger, requested_by=req.requested_by)
  retry: runner.retry(req.target_run_id, <time limit and parallelism>, kinds=overrides.get("kinds"))
  current = req;  on ScanBusy (runner shut down): stop the loop
  ```
  Reuse the `FIELDS` tuple that `web/routes/scans.py` already uses for what a scan override may set. Import it, or move
  it to `kubedelos/web/jobs.py` if the import would be circular.

- [ ] **Step 1: Write failing tests**
  - test_jobs:
    - `test_fixed_cluster_keeps_the_kubeconfig_context`: `ScanRunner(settings(context=None), "my-cluster",
      fixed_cluster=True, scan=fake)`. Then `.start({})` → the fake receives `settings.context is None`.
    - `test_fixed_cluster_refuses_another_context`: `.start({}, context="other")` raises `ValueError`.
    - `test_start_passes_trigger_and_requester`.
  - test_scheduler:
    - `test_cron_error_names_the_setting`: `cron_error("61 * * * *", "UTC")` contains `KUBEDELOS_SWEEP_SCHEDULE`;
      `cron_error("0 3 * * *", "UTC") is None`.
    - `test_next_run_in_the_configured_zone`: schedule `0 3 * * *` with zone `Europe/Vilnius` → `next_run().hour == 3`
      and its `tzinfo` key is `Europe/Vilnius`.
    - `test_disabled_sweeps_schedule_nothing`: `next_run() is None` after `start()`.
    - `test_job_options`: the `sweep` job has `coalesce is True`, `max_instances == 1` and
      `misfire_grace_time == 3600`.
  - test_worker. Use a fake scan callable that records its calls and returns a `ScanOutcome`, and `poll_s=0.01`. Wait
    on conditions, never with a bare sleep.
    - `test_sweep_runs_and_records_its_run`: `enqueue_sweep()` → the fake is called with `trigger="schedule"`, and the
      request ends `started` with the run id set.
    - `test_requests_run_one_at_a_time_in_order`.
    - `test_finished_sweep_prunes` (monkeypatch `retention.prune` to record its calls) and
      `test_ui_scan_does_not_prune`.
    - `test_invalid_overrides_are_skipped_not_fatal`: a queued `ui` request with `{"parallelism": 999}` → no scan, run id
      NULL, and the next request still runs.
    - `test_stop_ends_the_thread`: `alive()` is False within 2 s.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_jobs.py tests/test_scheduler.py tests/web/test_worker.py -q`.
  Expected: the new tests FAIL.
- [ ] **Step 3:** Run `.venv/bin/pip install -e '.[dev]'` after editing `pyproject.toml`, then implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: sweep on a cron schedule through the scan queue`.

### Task 6: The serve app (security, health, Scans page queue)

**Files:**
- Modify: `kubedelos/web/security.py`, `kubedelos/web/app.py`, `kubedelos/web/server.py`,
  `kubedelos/web/routes/scans.py`, `kubedelos/web/templates/scans.html`
- Create: `kubedelos/web/routes/health.py`, `kubedelos/web/templates/partials/scan_queue.html`
- Test: `tests/web/test_security.py`, `tests/web/test_app.py`, `tests/web/test_server.py`, `tests/web/test_scans.py`,
  `tests/web/test_health.py`

**Interfaces:**
- Consumes:
  - `ScanRunner(..., fixed_cluster=True)`;
  - `QueueWorker` and `Sweeper` (Task 5), passed in already built;
  - `queue.queued` and `scan_run.requested_by`.
- Produces:
  - `security.install_serve(app: FastAPI, allowed_hosts: Collection[str]) -> None`.
    - Every response gets the existing security headers. Rename `_set_headers` to `set_headers` and keep the CSP nonce
      on `request.state.csp_nonce`.
    - `/healthz` skips the Host check. Other paths compare the Host hostname (port dropped, brackets stripped,
      lowercased) with `allowed_hosts`; a mismatch or a missing Host gets `400 invalid Host header`.
    - Any method outside GET/HEAD gets 403 through `error.html`, with title `View-only` and message
      `This kubedelos is view-only. Signing in to start scans comes with KUBEDELOS_TRUST_PROXY_HEADERS.`.
    - The access line is the same as `install`'s.
  - `app.create_serve_app(settings: Settings, *, runner: ScanRunner, worker: QueueWorker, sweeper: Sweeper, clock=...) -> FastAPI`.
    - Share one private builder with `create_app`, so the routers, the templates and the exception handlers are
      registered once.
    - `app.state.context = settings.cluster_name` and `app.state.list_contexts = lambda: [settings.cluster_name]`.
    - `app.state.serve = True` (False in `create_app`).
    - The template `csrf_token` returns `""`.
    - `app.state.scans = runner`, `app.state.worker = worker` and `app.state.sweeper = sweeper`.
  - `GET /healthz`: 200 `ok` (text/plain) when `worker.alive()` and the DB opens read-only; else 503 `unhealthy`.
    In `create_app` it returns 404, so the route checks `app.state.serve`.
  - `server.bind(host, port, *, public: bool = False)`: with `public`, binds `host` literally (an IPv6 literal picks
    `AF_INET6`), so `0.0.0.0` and `::` work. Without it, nothing changes.
  - `server.serve` also stops `app.state.worker` and `app.state.sweeper` (sweeper first, then worker, then runner)
    when present.
  - The Scans page in `serve`:
    - a "Queue" card listing the queued requests (trigger, requester or `schedule`, requested time with `ago`), with no
      cancel button yet (that is PR 2);
    - the next sweep time from `sweeper.next_run()`, or `sweeps are off`;
    - a history column `By`: `requested_by`, else `schedule` for trigger `schedule`, else `–`.

    The laptop page keeps exactly its current markup; `tests/web/test_scans.py`'s existing tests prove it.

- [ ] **Step 1: Write failing tests**
  - test_security, using a `serve_client` fixture: `create_serve_app` with fakes for the worker and the sweeper,
    `allowed_hosts=["example.com"]`, and `TestClient(base_url="http://example.com")`.
    - `test_serve_host_check`, parametrized over Host values: `example.com`, `EXAMPLE.com:8080` → 200;
      `evil.example.org`, missing → 400.
    - `test_serve_allows_ipv6_literal`: `allowed_hosts=["::1"]` with Host `[::1]:8080` → 200.
    - `test_serve_refuses_writes`: `POST /scans` → 403, and the body contains `view-only`.
    - `test_serve_sets_security_headers`: CSP present on a 200 and on the 403.
  - test_health:
    - `test_healthz_ok_with_any_host`: Host `10.0.0.7:8080` → 200 `ok`.
    - `test_healthz_unhealthy_when_worker_dead` → 503.
    - `test_healthz_absent_on_laptop` → 404 through the logged-in laptop client.
  - test_server:
    - `test_public_bind_any_ipv4`: `bind("0.0.0.0", 0, public=True)` → `getsockname()[0] == "0.0.0.0"`.
    - `test_loopback_bind_unchanged`.
  - test_scans:
    - `test_serve_scans_page_lists_the_queue_and_next_sweep`: one queued schedule request; the page shows `schedule` and
      the formatted next sweep time.
    - `test_serve_history_shows_requester`: a run with `requested_by="a@example.com"`.
    - `test_laptop_scans_page_has_no_queue`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Keep the queue markup in `partials/scan_queue.html`, included only when `serve` is true, and
  reuse the existing `card`, `history` and `chip` classes.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: serve a view-only ui with the scan queue`.

### Task 7: `kubedelos serve` and docs

**Files:**
- Modify: `kubedelos/cli.py`, `README.md`, `CHANGELOG.md`, `AGENTS.md` (the Project paragraph mentions `serve`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `kubedelos serve [--host 0.0.0.0] [--port 8080] [--kubeconfig PATH]`, which does this, in order:
  1. Load settings. Missing `cluster_name` → `error: KUBEDELOS_CLUSTER_NAME is required for kubedelos serve`, exit 2.
     Then `cron_error(...)` → `error: <line>`, exit 2.
  2. `with runlock.hold_serve(settings.data_dir)`; `AlreadyServing` → `error: <message>`, exit 2.
  3. Run `kube_client.load(settings)` once, so a bad config fails at start. Errors go through `_flat`, exit 2.
  4. `connect` (migrations), `close_stale_runs`, `queue.abandon_started`; print `note: closed N interrupted runs` as
     `ui` does.
  5. `server.bind(host, port, public=True)`. `PortInUse` → `error: port N is in use; pass --port`, exit 2.
  6. Build the `ScanRunner` (`fixed_cluster=True`), the `QueueWorker`, and the `Sweeper` with `on_fire=worker.enqueue_sweep`.
     Start the worker, then the sweeper.
  7. Print `kubedelos serve for cluster <name> on http://<host>:<port>` and the next sweep line
     (`next sweep: <iso time>` or `sweeps are off`).
  8. Run `server.serve(create_serve_app(...), sock)`.

  It sets up the same `KUBEDELOS_LOG_LEVEL=info` access logging as `ui`, never opens a browser, and prints no token.

- [ ] **Step 1: Write failing tests**. Use typer's `CliRunner` and monkeypatch `server.serve`, `kube_client.load`, the
  `Sweeper` and the `QueueWorker`, as the existing `ui` tests do.
  - `test_serve_requires_cluster_name` → exit 2, and the message names `KUBEDELOS_CLUSTER_NAME`.
  - `test_serve_rejects_bad_cron` with `KUBEDELOS_SWEEP_SCHEDULE="every day"` → exit 2, naming the setting.
  - `test_serve_rejects_bad_timezone` → exit 2.
  - `test_serve_refuses_a_second_instance`: hold `hold_serve(data_dir)` in the test → exit 2 with `another kubedelos
    serve`.
  - `test_serve_startup_closes_stale_state`: a `running` run with no owner and a `started` request with no run → after
    start, the run is `failed` and the request is `cancelled`. The order is checked by the patched `server.serve`
    seeing both already closed.
  - `test_serve_prints_address_and_next_sweep`.
  - `test_serve_binds_public_by_default`: the patched `bind` receives `("0.0.0.0", 8080, public=True)`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_cli.py -q`. Expected: FAIL.
- [ ] **Step 3:** Implement `serve` in `cli.py`, next to `ui`.
  - README: a "kubedelos serve (in-cluster)" section covering what it does, the six `KUBEDELOS_*` settings with
    defaults, that it is view-only until sign-in lands, and how to try it on a laptop:
    `KUBEDELOS_CLUSTER_NAME=my-cluster KUBEDELOS_CONTEXT=kind-lab KUBEDELOS_SWEEP_SCHEDULE='*/5 * * * *' kubedelos serve --host 127.0.0.1 --port 9371`.
  - CHANGELOG: Features entries for `serve`, scheduled sweeps through the queue, retention and migration 10.
- [ ] **Step 4:** Run `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . &&
  .venv/bin/pre-commit run --all-files`. Expected: all clean.
- [ ] **Step 5: Manual check against kind-lab only.** Use a scratch data dir (`KUBEDELOS_DATA_DIR=<scratchpad>/serve-data`)
  and a `*/2 * * * *` schedule. Within about 3 minutes a run with trigger `schedule` appears on
  `http://127.0.0.1:9371/scans`. `curl -X POST` gets 403, and `curl -H 'Host: 10.1.2.3' /healthz` gets 200. Never point
  it at a work cluster.
- [ ] **Step 6:** Commit `feat: add kubedelos serve`, then push `feat/serve` and open the PR with `Refs #12, #24`.
