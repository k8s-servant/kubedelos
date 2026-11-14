# Scan scope: label selectors and image exclusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** narrow a scan by namespace labels (`--namespace-selector`, #8) and by pod or workload labels (`-l/--selector`, #9), and skip images by glob (`--exclude-image`, #10). Every run records its scope, so later views (#24) only compare like with like.

**Architecture:**
- Selectors are passed to the API server as `label_selector` on the existing list calls. Kubernetes parses kubectl selector syntax, and kubedelos never reimplements it.
- Image exclusion happens in `collect()` before scanning. Excluded images never reach Trivy, are not errors, and are counted in one informational warning.
- The run's scope is stored as canonical JSON in a new `scan_run.scope` column (migration 3).

**Tech Stack:** Python 3.12+, kubernetes client, `fnmatch.fnmatchcase`, SQLite migrations, pytest with `tests/kube/fakes.py`.

**Spec:** `docs/superpowers/specs/2026-11-13-kubedelos-design.md`, plus issues #8, #9, #10 and the scope record #24 asks for.

## Global Constraints

- Read-only: the same `list` calls, now with a `label_selector`. No new verbs and no new resources.
- Fail closed. A selector that can't be applied must never silently scan more or fewer namespaces than asked; the run errors (exit 2) instead.
- Every `KubeApi` list call keeps `_request_timeout=REQUEST_TIMEOUT`.
- One test file per module, failing test first. Ruff line length 120. Module docstrings stay accurate.

## Review Focus

1. **`--namespace-selector` when namespace list is forbidden.** Today kubedelos falls back to the `--namespace` names. With a selector it can't evaluate the labels, so it must exit 2 rather than scan namespaces the selector would have dropped. (Task 1: `test_namespace_selector_with_forbidden_namespace_list_fails_closed`)
2. **`--namespace` plus `--namespace-selector`.** The result is the intersection. A named namespace that doesn't match the selector is reported as not scanned and is not silently dropped. (Task 1: `test_named_namespace_outside_selector_warns`)
3. **An invalid selector** (`app in (`) returns HTTP 400 from the API server. It must surface as `error: invalid label selector ...` with exit 2, not as a raw ApiException dump. (Task 1: `test_invalid_selector_is_a_clear_error`)
4. **Docker Hub spellings in `--exclude-image`.** `nginx:*`, `library/nginx:*` and `docker.io/library/nginx:*` must all exclude a pod that wrote `nginx:1.19`, and one written as `docker.io/library/nginx:1.19`. Matching uses the normalised image, so it doesn't depend on how a pod spelled it. (Task 2: `test_exclude_image_matches_any_docker_hub_spelling`)
5. **A digest-pinned image** (`repo@sha256:...` with no tag) is matched by `repo` patterns such as `registry.example/team/*`, and a tag pattern like `*:1.19` doesn't crash on it. (Task 2: `test_exclude_image_digest_only_ref`)

---

### Task 1: Namespace and pod/workload label selectors

**Files:**
- Modify: `kubedelos/config.py`, `kubedelos/kube/client.py`, `kubedelos/kube/inventory.py`
- Modify: `tests/kube/fakes.py`, `tests/kube/test_client.py`, `tests/kube/test_inventory.py`, `tests/test_config.py`

**Interfaces:**
- Produces:
  - `Settings.namespace_selector: str | None = None` and `Settings.selector: str | None = None`. Empty or whitespace-only becomes `None`.
  - `KubeApi.list_namespaces(label_selector: str | None = None)`, and `list_pods`, `list_deployments`, `list_statefulsets`, `list_cronjobs` each gain `(ns: str, label_selector: str | None = None)`. `_RealKubeApi` passes `label_selector` only when it isn't None.
  - `FakeKubeApi` records every `label_selector` it receives in `self.selectors: list[tuple[str, str | None]]`, as (method, selector). It filters by simple `k=v` equality, comma-ANDed, which is enough for tests. A selector containing `(` without `)` raises `ApiException(status=400, reason="unable to parse requirement")`.

Behavior in `_select_namespaces`:
- Pass `settings.namespace_selector` to `list_namespaces`.
- If the list is forbidden and a selector is set, raise `RuntimeError("cannot list namespaces: forbidden; --namespace-selector needs list rights on namespaces")`. Otherwise keep today's fallback.
- For each name in `settings.namespaces` that exists but isn't returned by the selector, add `InventoryWarning(f"namespace {name} does not match --namespace-selector; not scanned", coverage=False)`. That needs one extra unfiltered list, done only when both `--namespace` and the selector are set.

In `collect`, pass `settings.selector` to the four namespaced list calls.

A 400 from any list call that has a selector raises `ValueError(f"invalid label selector {selector!r}: {exc.reason}")`. Wrap the calls in `_select_namespaces` and `collect` with a small helper `_with_selector(fn, selector, *args)`.

- [ ] **Step 1: Write the failing tests:**
  - `tests/test_config.py::test_selectors_default_none_and_blank_is_none`: `Settings(selector="  ").selector is None`.
  - `tests/kube/test_client.py::test_real_api_passes_label_selector_only_when_set`: extend the `Recorder` to capture kwargs. `list_pods("ns", label_selector="app=web")` passes it, and `list_pods("ns")` has no `label_selector` key. All six calls still carry the timeout.
  - `tests/kube/test_inventory.py`:
    - `test_namespace_selector_filters_namespaces`: namespaces `a{team=x}` and `b{team=y}` with `namespace_selector="team=x"` give images from `a` only, and the fake recorded `("list_namespaces", "team=x")`.
    - `test_selector_passed_to_every_namespaced_list`: `selector="app=web"` is recorded for pods, deployments, statefulsets and cronjobs, and only the labelled pod's image is in the inventory.
    - `test_namespace_selector_with_forbidden_namespace_list_fails_closed`: `namespaces_forbidden=True` with `namespace_selector="team=x"` raises `RuntimeError` matching `--namespace-selector`.
    - `test_named_namespace_outside_selector_warns`: `namespaces=["a","b"]` with the selector matching only `a` scans `a`, and the warning names `b` with `coverage=False`.
    - `test_invalid_selector_is_a_clear_error`: `selector="app in ("` raises `ValueError` matching `invalid label selector 'app in ('`.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/kube tests/test_config.py -q`. Expected: the new tests fail.
- [ ] **Step 3: Implement** them as specified.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `feat: select namespaces and workloads by label`, with `Refs #8 #9` in the body.

### Task 2: `--exclude-image`

**Files:**
- Modify: `kubedelos/config.py`, `kubedelos/kube/inventory.py`, `tests/kube/test_inventory.py`, `tests/test_config.py`

**Interfaces:**
- Produces:
  - `Settings.exclude_images: list[str] = []`. The env var takes a JSON list, like `KUBEDELOS_NAMESPACES`.
  - `image_names(image: ImageRef) -> set[str]` in `inventory.py`. It returns every name a pattern may match:
    - `repo`, then `repo:tag` when there is a tag, and `repo@digest` when there is a digest
    - for `docker.io/library/<x>`, the same set with `docker.io/library/` and with `docker.io/` stripped
    - for other `docker.io/<x>`, the same set with `docker.io/` stripped
  - `is_excluded(image: ImageRef, patterns: list[str]) -> bool`, which is `any(fnmatchcase(name, p) for name in image_names(image) for p in patterns)`.

In `collect`, after grouping, drop the items where `is_excluded(item.image, settings.exclude_images)`. If any were dropped, append `InventoryWarning(f"excluded {n} image(s) matching --exclude-image", coverage=False)`.

- [ ] **Step 1: Write the failing tests** in `tests/kube/test_inventory.py`:
  - `test_exclude_image_matches_any_docker_hub_spelling`: pods using `nginx:1.19` and `docker.io/library/nginx:1.19`. Each of the patterns `nginx:*`, `library/nginx:*` and `docker.io/library/nginx:*` leaves zero nginx items.
  - `test_exclude_image_keeps_others_and_warns`: `registry.k8s.io/*` drops `registry.k8s.io/pause:3.9`, keeps `nginx`, and gives the warning `excluded 1 image(s) matching --exclude-image` with `coverage=False`.
  - `test_exclude_image_digest_only_ref`: a pod with `registry.example/team/app@sha256:<64 hex>` is excluded by `registry.example/team/*`, and `*:1.19` neither excludes it nor raises.
  - `test_no_exclusion_no_warning`: with an empty list, no exclusion warning appears.
  - `tests/test_config.py::test_exclude_images_from_env_json`: `KUBEDELOS_EXCLUDE_IMAGES='["a/*","b:*"]'` gives the list.
- [ ] **Step 2: Run** `.venv/bin/pytest tests/kube/test_inventory.py -q`. Expected: the new tests fail.
- [ ] **Step 3: Implement** them as specified.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `feat: exclude images by glob before scanning`, with `Refs #10` in the body.

### Task 3: Record the scope on each run, and the CLI flags

**Files:**
- Modify: `kubedelos/store/db.py` (migration 3: `ALTER TABLE scan_run ADD COLUMN scope TEXT;`), `kubedelos/store/repo.py`, `kubedelos/scan/service.py`, `kubedelos/cli.py`
- Test: `tests/store/test_repo.py`, `tests/scan/test_service.py`, `tests/test_cli_scan.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: the Task 1 and Task 2 settings.
- Produces:
  - `Settings.scope -> str`: canonical JSON with `json.dumps(..., sort_keys=True, separators=(",", ":"))` of `{"namespaces": sorted, "exclude_namespaces": sorted, "namespace_selector": str|None, "selector": str|None, "exclude_images": sorted}`. Context and cluster aren't part of it, because they're already on the run.
  - `Repo.start_run(..., *, scan_level: str, scope: str | None = None)`, which stores `scope`. A default of None is fine here: unlike the scan level, the scope doesn't key the cache.
  - The service passes `scope=settings.scope`.
  - CLI on `scan`:
    - `--namespace-selector TEXT`: `Only scan namespaces matching this label selector, e.g. team=payments,env!=dev.`
    - `-l` / `--selector TEXT`: `Only scan pods and workloads matching this label selector, e.g. app=web.`
    - `--exclude-image TEXT`, repeatable: `Skip images matching this glob, e.g. registry.k8s.io/* or nginx:* (repeatable).`
  - A `ValueError` or `RuntimeError` from the inventory already prints `error: ...` and exits 2. A test confirms the selector message reaches stderr.

- [ ] **Step 1: Write the failing tests:**
  - `tests/test_config.py::test_scope_is_canonical`: two Settings whose lists are in different orders give an identical `scope`, and `json.loads(scope)["selector"] == "app=web"`.
  - `tests/store/test_repo.py::test_run_records_scope`: `start_run(..., scan_level="os", scope='{"x":1}')` and `get_run(...)["scope"] == '{"x":1}'`. Update `test_migrations_idempotent` to `len(MIGRATIONS)`, which already holds, and `test_migration_from_v1...` to `user_version == len(MIGRATIONS)`.
  - `tests/scan/test_service.py::test_service_records_scope`: `run_scan(settings with selector="app=web")` gives a run whose `scope` has that selector.
  - `tests/test_cli_scan.py`:
    - `test_cli_scan_scope_flags`: `--namespace-selector team=x -l app=web --exclude-image 'a/*' --exclude-image 'b:*'` gives `seen["settings"]` with those values.
    - `test_cli_scan_invalid_selector_exits_2`: `make_run(raises=ValueError("invalid label selector 'x(': bad"))` exits 2 and stderr contains `invalid label selector`.
- [ ] **Step 2: Run** `.venv/bin/pytest -q`. Expected: the new tests fail.
- [ ] **Step 3: Implement** the migration, the repo and service changes, and the CLI options.
- [ ] **Step 4: Run** `.venv/bin/pytest -q`, `.venv/bin/ruff check .` and `.venv/bin/ruff format --check .`. Expected: all pass.
- [ ] **Step 5: Commit** `feat: record each run's scan scope and add the scope flags`, with `Refs #8 #9 #10` in the body.

### Task 4: Docs, and a real check on kind

**Files:**
- Modify: `README.md` and `README.pypi.md`:
  - Quickstart: one sentence and one example for each new flag
  - configuration table rows for `KUBEDELOS_NAMESPACE_SELECTOR`, `KUBEDELOS_SELECTOR` and `KUBEDELOS_EXCLUDE_IMAGES`
  - a note that Deployments, StatefulSets and CronJobs scanned as templates match on their *own* labels
- Modify: `CHANGELOG.md`, with a Features bullet.

- [ ] **Step 1: Edit the docs.**
- [ ] **Step 2: Real check.** Create a throwaway kind cluster `kubedelos-scope`, with its kubeconfig in the scratchpad, and delete it afterwards. Set up:
  - namespace `web` labelled `team=web`, with Deployment `nginx:1.19` (pod label `app=web`) and a pod `busybox:1.36` (label `app=tools`)
  - namespace `other`, unlabelled, with `alpine:3.18`

  Run `kubedelos scan --pkg-types os -o json` with each of these, using the scratch `KUBEDELOS_CACHE_DIR`/`DATA_DIR`:
  - `--namespace-selector team=web`: only images from `web`
  - `-l app=web`: only nginx
  - `--exclude-image 'busybox:*'`: no busybox, and stderr says `excluded 1 image(s)`
  - `-l 'app in ('`: exit 2 with `invalid label selector`

  Expected: all four behave as described, and the stored runs carry their `scope` JSON.
- [ ] **Step 3: Run** `.venv/bin/pre-commit run --all-files`. Expected: all hooks pass.
- [ ] **Step 4: Commit** `docs: document scan scope flags`, then open the PR `feat: add label selectors and image exclusion to scan` with `Closes #8`, `Closes #9` and `Closes #10`.
