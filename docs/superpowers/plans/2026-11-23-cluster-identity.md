# Cluster Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every kube-context that points at the same API server shares one history (runs, numbers, comparisons,
retention, accepted risks), and each run still records the context it was scanned through (issue #92).

**Architecture:** A new `scan_run.cluster` column holds the cluster key: the normalised `server` of the context's
kubeconfig cluster entry (laptop) or `clusterName` (serve). Every per-cluster query keys on it; `scan_run.context` stays
as provenance. The web layer resolves the shown context to its key once per request. `kubedelos ui` merges the
history of each kubeconfig context into its key on start.

**Tech Stack:** Python 3.12+, SQLite migrations (`kubedelos/store/db.py`), FastAPI/Jinja, the MCP server, pytest.

**Spec:** `docs/superpowers/specs/2026-11-23-cluster-identity-design.md`

## Global Constraints

- Read-only: the key comes from parsing the kubeconfig file as YAML, like `list_contexts`; no credentials are loaded,
  no login plugin runs, the cluster is not called.
- A context whose cluster entry has no usable `server` uses its own name as its key.
- `kubedelos serve` keys on `clusterName` and stores `clusterName` as the run's context, exactly as today.
- History that can't be matched to the current kubeconfig keeps its context name as its key; nothing is deleted.
- Run numbers stay unique per cluster and ordered by id.
- TDD, one test file per module, every module starts with a docstring, ruff line length 120.
- Conventional Commits with lowercase subjects; no attribution lines; CHANGELOG is written by release-please.

## Review Focus

1. Two contexts whose servers differ only in case, a trailing `/` or an explicit `:443` must get one key (Task 1).
2. A kubeconfig split over several `KUBECONFIG` files that defines the same context or cluster name twice: the first
   definition wins, as kubectl does (Task 1).
3. Merging a context that has old runs into a key that already has newer runs: numbers end up 1..n by id with no
   unique-index error, and a second start changes nothing (Task 4).
4. A context removed from the kubeconfig after its runs were keyed by URL must still open its history from the switcher
   (Task 6).
5. An accepted risk created while viewing one context applies when viewing the other context of the same cluster
   (Task 3).

---

### Task 1: Cluster keys from the kubeconfig

**Files:**
- Modify: `kubedelos/kube/client.py` (next to `list_contexts`)
- Test: `tests/kube/test_client.py`

**Interfaces:**
- Produces: `normalise_server(url: str) -> str` and `cluster_keys(settings: Settings) -> dict[str, str]` (context
  name → cluster key, every context in the kubeconfig).

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.parametrize("raw", ["https://AKS.example.com", "https://aks.example.com/", "https://aks.example.com:443"])
def test_normalise_server_folds_case_slash_and_default_port(raw):
    assert normalise_server(raw) == "https://aks.example.com"

def test_normalise_server_keeps_other_ports_and_ipv6():
    assert normalise_server("https://10.0.0.1:6443") == "https://10.0.0.1:6443"
    assert normalise_server("https://[fd00::1]:443/") == "https://[fd00::1]"

def test_cluster_keys_group_contexts_of_one_server(tmp_path):
    # contexts "prod" and "prod-admin" name clusters "prod" and "prod-admin", both https://prod.example.com
    assert cluster_keys(settings_for(kubeconfig)) == {
        "prod": "https://prod.example.com", "prod-admin": "https://prod.example.com", "dev": "https://dev.example.com"}

def test_cluster_keys_fall_back_to_the_context_name():
    # a context naming a missing cluster entry, and one whose cluster has no server
    assert cluster_keys(...) == {"broken": "broken", "no-server": "no-server"}

def test_cluster_keys_first_file_wins_like_kubectl(tmp_path):
    # KUBECONFIG=a:b, both define cluster "prod" with different servers -> a's server

def test_cluster_keys_skip_an_unreadable_file(tmp_path):
    # same tolerance as list_contexts: a half-written file is skipped
```

- [ ] **Step 2: Run them and see them fail**

Run: `.venv/bin/pytest tests/kube/test_client.py -k "normalise or cluster_keys" -v` — Expected: ImportError.

- [ ] **Step 3: Implement both in `kubedelos/kube/client.py`**

`normalise_server` uses `urllib.parse.urlsplit`: lower-case scheme and host, drop `:443` for https and `:80` for
http, drop a trailing `/` from the path, keep any other path. `cluster_keys` reads the same paths as `list_contexts`
(share a private `_kubeconfig_docs(settings)` generator so both parse files the same way), collects `clusters` and
`contexts` with first-definition-wins, and maps each context to `normalise_server(server)` or to its own name.
`list_contexts` keeps its behaviour.

- [ ] **Step 4: Run the tests** — `.venv/bin/pytest tests/kube/test_client.py -v` — all pass.

- [ ] **Step 5: Commit** — `git commit -m "feat: work out each kube-context's cluster from its api server"`

### Task 2: Store runs under a cluster key

**Files:**
- Modify: `kubedelos/store/db.py` (migration 14), `kubedelos/store/repo.py` (`start_run`), `kubedelos/store/queries.py`,
  `kubedelos/store/retention.py`, `tests/web/seed.py` (raw INSERT gains `cluster`)
- Test: `tests/store/test_db.py`, `tests/store/test_repo.py`, `tests/store/test_queries.py`, `tests/store/test_retention.py`

**Interfaces:**
- Produces:
  - `Repo.start_run(self, cluster: str, context: str | None, trigger, trivy_version, *, scan_level, scope=None,
    owner=None, requested_by=None) -> int`: numbers per `cluster`.
  - `Run.cluster: str` (new field after `number`; `context` stays, meaning "scanned through").
  - Every per-cluster query takes `cluster: str` instead of `context: str` and filters `scan_run.cluster`:
    `newest_run`, `run_by_number`, `get_run`, `result_runs`, `run_label`, `run_history`, `previous_comparable` (uses
    `run.cluster`). `RunNotShown` text: `"that run belongs to another cluster"`.
  - `HistoryRow.context: str | None` (new field) for the "via" note.
  - `ClusterScan(cluster: str, name: str, finished_at: datetime | None, contexts: tuple[str, ...])` and
    `cluster_scans(conn) -> list[ClusterScan]` replacing `context_scans`: `name` is the context of the cluster's
    newest run, `contexts` every context seen for it, sorted.
  - `RunLabel.cluster: str`.

- [ ] **Step 1: Write the failing tests**

```python
def test_migration_14_keys_existing_runs_by_their_context(tmp_path):
    # apply MIGRATIONS[:13], insert runs for "a" (2) and "b" (1), migrate
    assert rows("SELECT cluster, context, number FROM scan_run ORDER BY id") == [("a","a",1),("a","a",2),("b","b",1)]

def test_runs_are_numbered_per_cluster_not_per_context(repo):
    repo.start_run("https://k.example.com", "prod", ...)
    repo.start_run("https://k.example.com", "prod-admin", ...)
    assert numbers == [1, 2]

def test_newest_run_is_shared_by_contexts_of_one_cluster(repo, conn):
    # run via "prod-admin" is the newest run of cluster K, whichever context asks
    assert newest_run(conn, K, cluster_scope=False).context == "prod-admin"

def test_get_run_refuses_a_run_of_another_cluster(...): ...
def test_previous_comparable_crosses_contexts_of_one_cluster(...): ...
def test_cluster_scans_name_each_cluster_after_its_newest_run(...):
    assert cluster_scans(conn) == [ClusterScan(K, "prod-admin", t2, ("prod", "prod-admin"))]
def test_retention_keeps_the_newest_result_per_cluster_scope_and_level(...): ...
```

Update `tests/store/test_db.py` (`len(MIGRATIONS) == 14`, the broken-migration test uses `MIGRATIONS[:13]` and
expects 13) and the existing per-context tests to the new signatures.

- [ ] **Step 2: Run and see them fail** — `.venv/bin/pytest tests/store -q`

- [ ] **Step 3: Implement**

Migration 14 (SQL script, with a `# 14:` comment saying why):
`ALTER TABLE scan_run ADD COLUMN cluster TEXT; UPDATE scan_run SET cluster = context;`, drop
`idx_scan_run_number`, `idx_scan_run_number_no_context` and `idx_scan_run_context`, create
`idx_scan_run_number ON scan_run(cluster, number)` (unique), `idx_scan_run_number_no_cluster ON scan_run(number) WHERE
cluster IS NULL` (unique), `idx_scan_run_cluster ON scan_run(cluster, status, id)`; and
`ALTER TABLE acceptance ADD COLUMN cluster TEXT; UPDATE acceptance SET cluster = context;` (used by Task 3).
Retention groups by `cluster, scope, pkg_types`; fix its docstring. Fix the "within its context" comments.

- [ ] **Step 4: Run** — `.venv/bin/pytest tests/store -q` — all pass; `test_query_plans_use_indexes` still passes.

- [ ] **Step 5: Commit** — `git commit -m "feat: store each run under its cluster and keep the context it went through"`

### Task 3: Accepted risks per cluster

**Files:**
- Modify: `kubedelos/store/accepted.py`, `kubedelos/store/queries.py` (`ACCEPTED_CTES`), `tests/web/seed.py`
  (`seed_acceptances`)
- Test: `tests/store/test_accepted.py`

**Interfaces:**
- Consumes: `acceptance.cluster` from Task 2.
- Produces: `add(conn, *, ..., cluster: str | None, context: str | None, ...)` stores both (`cluster` None means all
  clusters; `context` is the context shown when it was created, for display). `register(conn, cluster: str, ...)`.
  `Entry.cluster: str | None` and `Entry.context` kept. `ACCEPTED_CTES` compares `a.cluster` with the run's `cluster`.

- [ ] **Step 1: Failing tests**

```python
def test_an_acceptance_made_via_one_context_covers_the_other(conn, repo):
    run = repo.start_run(K, "prod-admin", ...)       # findings for CVE-1
    add(conn, vuln_id="CVE-1", cluster=K, context="prod", ...)
    assert ("img", "CVE-1", ...) in accepted_keys(conn, run, today)
def test_register_lists_entries_of_the_cluster_and_all_clusters(...): ...
```

- [ ] **Step 2–4:** run, implement, run `.venv/bin/pytest tests/store/test_accepted.py tests/store/test_queries.py -q`.

- [ ] **Step 5: Commit** — `git commit -m "feat: scope accepted risks to a cluster, whichever context made them"`

### Task 4: Merge a context's history into its cluster

**Files:**
- Create: `kubedelos/store/clusters.py`
- Test: `tests/store/test_clusters.py`

**Interfaces:**
- Consumes: Task 2's columns, Task 1's `dict[str, str]`.
- Produces: `merge_contexts(conn: sqlite3.Connection, keys: dict[str, str]) -> list[tuple[str, str]]`: for each
  `(context, key)` with `key != context` and rows where `scan_run.cluster = context`, moves those runs and
  `acceptance` rows to `key`, renumbers each touched cluster 1..n by id, all in one transaction; returns the
  `(context, key)` pairs it merged.

- [ ] **Step 1: Failing tests**

```python
def test_merge_moves_old_runs_and_renumbers_by_id(conn):
    # cluster "prod" runs 1,2 (ids 1,3); cluster K run 1 (id 2, via prod-admin)
    assert merge_contexts(conn, {"prod": K, "prod-admin": K}) == [("prod", K)]
    assert rows("SELECT id, cluster, number ...") == [(1, K, 1), (2, K, 2), (3, K, 3)]
def test_merge_is_idempotent(conn): assert merge_contexts(conn, keys) == [] the second time
def test_merge_leaves_contexts_missing_from_the_kubeconfig(conn): ...
def test_merge_moves_acceptances_scoped_to_the_context(conn): ...
```

- [ ] **Step 2–4:** run, implement (renumber with a two-pass `number = -id` then `ROW_NUMBER() OVER (PARTITION BY
  cluster ORDER BY id)` so the unique index never trips), run `.venv/bin/pytest tests/store/test_clusters.py -q`.

- [ ] **Step 5: Commit** — `git commit -m "feat: merge each kube-context's earlier runs into its cluster"`

### Task 5: Scans record cluster and context

**Files:**
- Modify: `kubedelos/scan/service.py` (`run_scan`), `kubedelos/web/jobs.py` (`ScanRunner`)
- Test: `tests/scan/test_service.py`, `tests/web/test_jobs.py`

**Interfaces:**
- Consumes: `Repo.start_run(cluster, context, ...)`.
- Produces: in `run_scan`, `context = settings.context or settings.cluster_name or api.current_context()` and
  `cluster = settings.cluster_name or context`. `ScanRunner.__init__(..., cluster_of: Callable[[str], str] = lambda c:
  c)`; a laptop `_target` sets `cluster_name` to `cluster_of(target)` (it was `None`); a fixed (serve) runner is
  unchanged.

- [ ] **Step 1: Failing tests**

```python
def test_a_laptop_scan_stores_the_cluster_key_and_the_context(...):
    runner = ScanRunner(settings, "prod", cluster_of={"prod-admin": K}.get ...)
    runner.start({}, context="prod-admin")
    assert stored (cluster, context) == (K, "prod-admin")
def test_a_serve_scan_stores_the_cluster_name_as_both(...): assert == ("my-cluster", "my-cluster")
```

- [ ] **Step 2–4:** run, implement, run `.venv/bin/pytest tests/scan tests/web/test_jobs.py -q`.

- [ ] **Step 5: Commit** — `git commit -m "feat: scan through a context and store the run under its cluster"`

### Task 6: The UI shows one history per cluster

**Files:**
- Modify: `kubedelos/web/app.py` (`_build`, `create_app`, `create_serve_app`), `kubedelos/web/pages.py`, every route
  that passes the context to a query (dashboard, findings, namespaces, diff, reports, accepted, failed, times, scans,
  settings, about), `kubedelos/cli.py` (`ui`), `kubedelos/web/templates/partials/run_line.html`,
  `kubedelos/web/templates/scans.html`, `docs/ui.md`
- Test: `tests/web/test_pages.py`, `tests/web/test_scans.py`, `tests/web/test_dashboard.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  - `create_app(..., cluster_keys: Callable[[], dict[str, str]] | None = None)`, default
    `lambda: kube_client.cluster_keys(settings)`; `create_serve_app` uses `lambda: {name: name}`;
    `app.state.cluster_keys`.
  - `pages.shown_context` also sets `request.state.cluster` (kubeconfig key, else the cluster of the newest run made
    through that context, else the name). Routes pass `request.state.cluster` to the store.
  - Switcher: one `ContextEntry` per kubeconfig context with its cluster's `finished_at`; one per history-only cluster
    (no kubeconfig context maps to it), named by `ClusterScan.name`.
  - `ScanRunner` gets `cluster_of` built from `app.state.cluster_keys`.
  - `cli.ui` calls `merge_contexts(conn, kube_client.cluster_keys(settings))` before serving and logs one line per
    merged pair: `merged the runs of context <c> into its cluster <key>`.
  - Run line and Scans history show `via <context>` when the run's context differs from the shown context.

- [ ] **Step 1: Failing tests**

```python
def test_two_contexts_of_one_cluster_show_the_same_newest_run(client):   # dashboard via prod and prod-admin
def test_the_switcher_shows_each_context_with_its_clusters_last_scan(client):
def test_a_history_only_cluster_opens_by_its_newest_context(client):     # context gone from the kubeconfig
def test_the_run_line_says_via_the_other_context(client):                # "via prod-admin"
def test_ui_merges_existing_runs_into_their_cluster_on_start(tmp_path):  # tests/test_cli.py
```

- [ ] **Step 2–4:** run, implement, run `.venv/bin/pytest tests/web tests/test_cli.py -q` (and the perf marker once:
  `.venv/bin/pytest -m perf tests/web/test_perf.py -q`).

- [ ] **Step 5: Commit** — `git commit -m "feat: show one history for every context of a cluster in the ui"`

### Task 7: MCP lists clusters, not contexts

**Files:**
- Modify: `kubedelos/mcp_server/tools.py`, `kubedelos/mcp_server/server.py` (descriptions), `docs/mcp.md`
- Test: `tests/mcp_server/test_tools.py`

**Interfaces:**
- Consumes: `cluster_scans`, the `cluster` query parameters.
- Produces: `resolve_cluster(conn, db, cluster) -> str` returns a key and accepts a key, a context name (the cluster of
  that context's newest run) or `ClusterScan.name`; `list_clusters` items gain `"contexts"` and keep `"name"` (the
  newest run's context); payloads' `"cluster"` is the cluster's name; `accepted_risks` entries carry `cluster` and
  `context`. Tool argument text: "Cluster: a kube-context name or a cluster from list_clusters".

- [ ] **Step 1: Failing tests**

```python
def test_list_clusters_lists_a_cluster_once_with_its_contexts(...):
def test_a_tool_resolves_either_context_of_a_cluster(...):
```

- [ ] **Step 2–4:** run, implement, run `.venv/bin/pytest tests/mcp_server -q`.

- [ ] **Step 5: Commit** — `git commit -m "feat: list clusters in the mcp server, whichever context scanned them"`

### Task 8: Finish

- [ ] Commit the spec and this plan; full suite `.venv/bin/pytest -q`, `ruff check . && ruff format --check .`,
  `pre-commit run --all-files`.
- [ ] Manual check on kind: two contexts for one kind cluster (`kind export kubeconfig` plus a copied context with
  another user), scan through each, confirm one history and the "via" note.
- [ ] Open the PR with `Closes #92`.
