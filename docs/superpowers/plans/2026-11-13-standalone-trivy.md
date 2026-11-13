# Standalone Trivy (drop the local Trivy server) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kubedelos scan` runs each image through its own standalone `trivy image` process. There is no local `trivy server`, no port and no token, and parallelism and cancel behave as they do today.

**Architecture:** A new `TrivyCache` context manager owns `<cache_dir>/trivy-cache`. On entry it takes an exclusive `flock` and downloads or updates the vulnerability DB and the Java DB, then holds a shared `flock` while the scans read them. Each scan runs `trivy image --cache-backend memory`, which keeps the image-layer cache (`fanal.db`, the BoltDB file that parallel processes lock on) in memory, and reads both DBs from the shared cache dir with `--skip-db-update --skip-java-db-update`.

**Tech Stack:** Python 3.12+, `fcntl.flock` (Linux and macOS only, the same platforms `kubedelos/trivy/binary.py` supports), Trivy v0.76.1, pytest with `tests/trivy/fake_trivy.py`.

**Spec:** `docs/superpowers/specs/2026-11-13-kubedelos-design.md` (the "Trivy concurrency" decision, which this plan replaces).

**Evidence (spike on 2026-11-13, Trivy 0.76.1, one shared cache dir):**
- 6 parallel standalone scans with the default fs cache: 4 failed with `unable to initialize fs cache: cache may be in use by another process: timeout`.
- 10 parallel scans with `--cache-backend memory`: all 10 passed in 41s. The set included tomcat:9.0, jenkins/jenkins:2.400 and elasticsearch:7.17.10, which have JAR results, so the Java DB was read too.
- Findings were identical to server mode for nginx:1.19, jenkins/jenkins:2.400 and python:3.11-slim (423, 1302 and 218 vulnerabilities, compared by ID, package and version).

## Global Constraints

- Trivy stays pinned at v0.76.1 and scans with `--scanners vuln` only. Never resolve "latest".
- `--` stays immediately before the image ref, so a ref can never be read as a flag.
- Credentials are never written to disk or logs. `DOCKER_CONFIG` is still passed only through the environment.
- One test file per module; write the failing test first.
- Ruff line length 120, and `ruff check` and `ruff format --check` stay clean. Every module starts with a docstring explaining what and why.
- Coverage stays at or above the CI floor of 80%.

## Review Focus

1. **A second run starts while a first run is scanning.** It must not block for the whole first scan waiting for an exclusive lock, and it must not update the DB under the first run. Expected: it skips the update and scans with the current DB. (Task 1: `test_busy_cache_skips_update_and_shares`)
2. **A second run starts while the first is still downloading the DB, for example on first use.** It must wait for the download, never scan against a missing DB. (Task 1: `test_waits_while_another_process_downloads`)
3. **Ctrl-C or SIGTERM while waiting for the lock.** The run exits with 130 and leaves nothing running. (Task 1: `test_sigterm_while_waiting_for_lock_exits`)
4. **The DB download fails.** The lock is released so the next run can retry, and the error says which download failed. (Task 1: `test_download_failure_releases_lock`)
5. **SIGTERM during parallel scans.** Every `trivy image` process group, including children, is killed. This used to be tested against the server. (Task 2: `test_sigterm_stops_running_scans`)

---

### Task 1: `TrivyCache`, the locked DB download

**Files:**
- Create: `kubedelos/trivy/cache.py`
- Create: `tests/trivy/test_cache.py`
- Modify: `tests/trivy/fake_trivy.py` (the download mode only: add `FAKE_TRIVY_DOWNLOAD_SLEEP`)

**Interfaces:**
- Consumes: `_run_group(argv, env, timeout_s)` and `_short(text)` from `kubedelos/trivy/runner.py`. Move both into `cache.py` if importing from runner would create a cycle; runner then imports them from `cache.py`.
- Produces:
  - `class TrivyCache` with `__init__(self, trivy: Path, cache_dir: Path) -> None`
  - attribute `dir: Path`, equal to `cache_dir / "trivy-cache"`
  - `__enter__(self) -> Self` and `__exit__(...) -> None`
  - attribute `updated: bool`, True when this run downloaded or checked for updates

Behavior of `__enter__`:
1. `mkdir(parents=True, exist_ok=True)` on `dir`, then open `dir / ".kubedelos.lock"` with `os.open(..., O_RDWR | O_CREAT, 0o600)`.
2. Try `flock(LOCK_EX | LOCK_NB)`.
   - **If it is acquired:** run `trivy image --download-db-only --cache-dir <dir>`, then the same with `--download-java-db-only`, each through `_run_group` with the existing `_DB_DOWNLOAD_TIMEOUT_S` (1800). Then `flock(LOCK_SH)` on the same fd and set `updated = True`.
   - **If it is busy (`BlockingIOError`):** another run holds the lock. Blocking `flock(LOCK_SH)` waits only while that run holds `LOCK_EX`, that is, while it downloads. Set `updated = False`.
3. Any exception, including `KeyboardInterrupt`, closes the fd, which releases the lock, and re-raises.

`__exit__` closes the fd. The kernel also releases a `flock` when the process dies, so a SIGKILL never leaves a stale lock. Say this in the module docstring, along with why the cache uses locks (see Architecture).

The download error messages stay as they are: `RuntimeError(f"trivy image {flag} failed with exit code {code}: {stderr}")` and `RuntimeError(f"trivy image {flag} did not finish within {_DB_DOWNLOAD_TIMEOUT_S}s")`.

- [ ] **Step 1: Write the failing tests** in `tests/trivy/test_cache.py`, using `FAKE_TRIVY` and `FAKE_TRIVY_DOWNLOAD_LOG`:
  - `test_downloads_both_dbs_into_trivy_cache`: after `with TrivyCache(FAKE_TRIVY, tmp_path) as c:`, the log has exactly two argv lines, `["image", "--download-db-only", "--cache-dir", str(tmp_path / "trivy-cache")]` and the `--download-java-db-only` equivalent. Also `c.dir == tmp_path / "trivy-cache"` and `c.updated is True`.
  - `test_lock_file_is_private`: `stat.S_IMODE((tmp_path / "trivy-cache" / ".kubedelos.lock").stat().st_mode) == 0o600`.
  - `test_busy_cache_skips_update_and_shares`: hold `flock(LOCK_SH)` on the lock file from a separate `open()` in the test. Entering a `TrivyCache` then returns within 2s with `updated is False`, and the download log stays empty.
  - `test_waits_while_another_process_downloads`: hold `flock(LOCK_EX)` from the test, enter `TrivyCache` in a thread, and check it hasn't entered after 0.3s. Release the lock and check it enters within 2s with `updated is False`.
  - `test_download_failure_releases_lock`: `FAKE_TRIVY_DOWNLOAD_FAIL="FATAL db download failed"` raises `RuntimeError` matching that text. Afterwards `flock(LOCK_EX | LOCK_NB)` from the test succeeds.
  - `test_releases_lock_on_exit`: after the `with` block, `flock(LOCK_EX | LOCK_NB)` from the test succeeds.
  - `test_sigterm_while_waiting_for_lock_exits`: in the same style as `tests/test_cli_scan.py::_SIGTERM_SCRIPT`, a subprocess script holds `LOCK_EX` from a second fd and runs `cli._signals_as_interrupt()` around `TrivyCache(...)`. It sends itself SIGTERM from a `threading.Timer(0.3, ...)` and must exit 130 within 10s.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/trivy/test_cache.py -q`. Expected: it fails with `ModuleNotFoundError: kubedelos.trivy.cache`.
- [ ] **Step 3: Implement** `TrivyCache` in `kubedelos/trivy/cache.py` as described above.
- [ ] **Step 4: Run** `.venv/bin/pytest tests/trivy -q`. Expected: all pass, including the existing runner tests.
- [ ] **Step 5: Commit** `feat: add a locked trivy db cache for standalone scans`

### Task 2: Scan standalone and remove `TrivyServer`

**Files:**
- Modify: `kubedelos/trivy/runner.py`
- Modify: `kubedelos/scan/service.py`
- Modify: `kubedelos/cli.py`, in the `_signals_as_interrupt` docstring: "leave the server and its clients running" becomes "leave Trivy scans running"
- Modify: `tests/trivy/fake_trivy.py`, `tests/trivy/test_runner.py`, `tests/scan/test_service.py`, `tests/test_cli_scan.py`

**Interfaces:**
- Consumes: `TrivyCache` from Task 1.
- Produces:
  - `scan_image(trivy: Path, item_ref: ImageRef, platform: str, timeout_s: int, docker_config: Path | None = None, *, cache_dir: Path | None = None, _groups: _ClientGroups | None = None) -> ImageResult`
  - `scan_many(items, *, cache_dir: Path, trivy: Path, settings: Settings, on_result, cancel) -> None`
  - `_short(text: str) -> str`, which no longer takes a token

`scan_image` builds exactly this argv:
```
[trivy, "image", "--format", "json", "--scanners", "vuln", "--image-src", "remote",
 "--platform", platform, "--quiet", "--timeout", f"{timeout_s}s", "--cache-backend", "memory",
 ("--cache-dir", str(cache_dir) when given), "--skip-db-update", "--skip-java-db-update", "--", ref]
```

Remove from `runner.py`: `TrivyServer`, `_free_port`, `_tail`, `_READY_TIMEOUT_S`, `_STOP_GRACE_S`, the `TRIVY_TOKEN` handling, and the `httpx`, `secrets`, `socket` and `tempfile` imports. httpx stays a dependency because `binary.py` uses it. Rewrite the module docstring: each image gets its own standalone `trivy image` in its own process group, the layer cache stays in memory to avoid the BoltDB lock, and `TrivyCache` guards the shared DBs.

In `service.py`:
- `with TrivyCache(trivy, settings.cache_dir) as cache: scan_many(todo, cache_dir=cache.dir, ...)`
- update the module docstring and the "no Trivy server needed" comment

In `fake_trivy.py`:
- remove the `server` mode and `_Health`
- move `FAKE_TRIVY_PID_FILE` and `FAKE_TRIVY_CHILD_PID_FILE` to the scan mode, which writes them before its sleep
- `FakeEnv` echoes only `DOCKER_CONFIG`
- update the docstring

- [ ] **Step 1: Update the tests first:**
  - `test_runner_builds_expected_args`: assert the new argv above with `cache_dir=tmp_path / "trivy-cache"`, and `echoed["FakeEnv"] == {"DOCKER_CONFIG": None}`.
  - `test_runner_error_is_truncated_and_hides_token` becomes `test_runner_error_is_truncated` (`len(result.error) <= 2000`).
  - Delete the four `test_trivy_server_*` tests. Task 1 tests the download behavior.
  - The `scan_many` tests pass `cache_dir=tmp_path / "trivy-cache"` instead of `server=`. `test_scan_many_reports_every_item` asserts that the echoed argv contains `"--cache-backend", "memory"` and the cache dir, and that `"--server"` is not in it.
  - `tests/scan/test_service.py`: `FakeServer` becomes `FakeCache` (it sets `dir = cache_dir / "trivy-cache"`) and patches `service.TrivyCache`. The fake `scan_many` takes `cache_dir`. Rename `test_service_skips_server_when_only_invalid_refs` to `test_service_skips_trivy_when_only_invalid_refs`.
  - `tests/test_cli_scan.py`: `test_sigterm_stops_the_trivy_server` becomes `test_sigterm_stops_running_scans`. The script runs `cli._signals_as_interrupt()` around `scan_many` over 2 items with `FAKE_TRIVY_SLEEP=30`, `FAKE_TRIVY_PID_FILE` and `FAKE_TRIVY_CHILD_PID_FILE` set and `parallelism=1`. It sends itself SIGTERM once the PID file exists. It must exit 130, and the scan process and its child must both be gone.
- [ ] **Step 2: Run** `.venv/bin/pytest -q`. Expected: the updated tests fail (for example on an argv mismatch, or a `TypeError` for the `cache_dir` keyword).
- [ ] **Step 3: Implement** the runner, service, fake and cli changes above.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`, `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`. Expected: all pass with coverage of at least 80%, and `grep -rn "TrivyServer\|--server\|TRIVY_TOKEN" kubedelos tests` prints nothing.
- [ ] **Step 5: Commit** `refactor: scan with standalone trivy instead of a local server`

### Task 3: Docs, and verification against real Trivy

**Files:**
- Modify: `README.md` and `README.pypi.md`:
  - "in server mode" becomes "as one standalone process per image, sharing one locked DB cache"
  - exit code 130 row: "The Trivy server is stopped" becomes "Running Trivy scans are stopped"
- Modify: `CHANGELOG.md`, under Unreleased:
  - line 8: "runs it in server mode and stops it on exit…" becomes "runs one standalone Trivy per image and stops them on exit…"
  - line 22: "leave the Trivy server running" becomes "leave Trivy scans running"
  - add a Features bullet: "Parallel scans and concurrent `kubedelos scan` runs share one Trivy DB cache safely; no local Trivy server or port is used."
- Modify: `docs/superpowers/specs/2026-11-13-kubedelos-design.md`, the "Trivy concurrency" bullet: replace it with the standalone design and the spike evidence above, dated 2026-11-13.

- [ ] **Step 1: Edit the docs** as listed above.
- [ ] **Step 2: Verify against real Trivy.** Run this Python snippet against the pinned binary:
  `TrivyCache(ensure_trivy(settings), settings.cache_dir)` + `scan_many` over `nginx:1.19`, `jenkins/jenkins:2.400`, `tomcat:9.0`, `python:3.11-slim` and `alpine:3.18` on `linux/amd64`, with `parallelism=5`. Use `KUBEDELOS_CACHE_DIR` in the scratchpad.
  Expected: all `status == "ok"`, nginx 423, jenkins 1302 and python 218 findings, and no `fanal.db` lock errors. Then run two copies at once. Expected: both `ok`, and the second reports `updated is False`.
- [ ] **Step 3: If `kind` and Docker are available, run** `scripts/e2e-kind.sh`. Expected: `kubedelos exited 1 as expected`. If they're not available, say so in the PR.
- [ ] **Step 4: Run** `.venv/bin/pre-commit run --all-files`. Expected: all hooks pass.
- [ ] **Step 5: Commit** `docs: describe standalone trivy scans`, then open the PR `refactor: scan with standalone trivy instead of a local server`.
