# kubedelos serve: writes through the queue, the user header and read-only mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Open writes in `kubedelos serve`, as on the laptop: scan, retry, cancel, and accept or revoke risks.
- Every scan goes through the queue and stays within the configured scope.
- The user's name comes from a trusted proxy header when there is one.
- An optional read-only mode turns all writes off.

**Architecture:**
- **Middleware.** The serve middleware refuses writes only when `KUBEDELOS_READ_ONLY` is on. Every other write needs
  an Origin naming an allowed host and a CSRF token.
- **CSRF token.** It is an HMAC of a per-browser cookie plus the identity, keyed by a secret made at start-up.
- **Identity.** It is read from the header only when `KUBEDELOS_TRUST_PROXY_HEADERS` is on, and is cleaned before use.
- **Routes.** In `serve`, the POST routes enqueue instead of calling the runner, so the queue worker stays the only
  scan starter. A pure function rejects scans that reach outside the configured scope.
- **Laptop.** `kubedelos ui` is unchanged.

**Tech Stack:** Python 3.12+, FastAPI, Jinja2, SQLite.

**Spec:** `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md`:
- section 2: "Scope is narrow-only", "Coalesced", "Bounded", "Cancellable", "Retries are queued too";
- section 4: Writes, identity and read-only mode;
- "Delivery" item 2.

The chart (`readOnly` value, NetworkPolicy guard, `NOTES.txt` warnings) is PR 3. Registry login and the "Test an image"
box are PR 4.

## Global Constraints

- Read-only cluster access: no code path may change cluster objects or read Secrets.
- Credentials never touch disk or logs. The identity value is untrusted text and is cleaned before any use.
- TDD; one test file per module; ruff line length 120; a docstring at the top of every new module saying what and why.
- Placeholders only: `my-cluster`, `my-context`, `example.com`, `a@example.com`.
- Conventional Commits with lowercase subjects, no co-author or attribution lines. Branch `feat/serve-identity`.
- `CHANGELOG.md` entries go under `## Unreleased`. The README's `kubedelos serve` section is updated.
- `kubedelos ui` behaviour does not change, and it is never read-only. Every existing test keeps passing.
- Spec values:
  - `KUBEDELOS_READ_ONLY`: default `false`.
  - `KUBEDELOS_TRUST_PROXY_HEADERS`: default `false`.
  - `KUBEDELOS_IDENTITY_HEADER`: default `X-Auth-Request-Email`.
  - The identity value has control characters stripped and is capped at **256** characters. An empty result means no
    identity.
  - Read-only notice: `View-only: this kubedelos is read-only.`
  - The CSRF cookie is `kubedelos_csrf`: random, `HttpOnly`, `SameSite=Strict`, path `/`, set on the first response
    that lacks it.
  - The CSRF token is the hex HMAC-SHA256, keyed by the start-up secret, of `<cookie>\n<identity or empty>`.
  - The queue holds at most 10 requests (`queue.MAX_QUEUED`). A full queue gives `the queue is full`. A coalesced
    request gives `already queued`.
  - A UI scan with no identity has `requested_by` NULL and shows `anonymous` in the By column.
  - Accepting a risk:
    - with an identity, the owner field is prefilled with it, and an empty owner becomes the identity;
    - without one, the owner field is required, as on the laptop.

## Rulings this plan makes on top of the spec

- **Selector narrowing.** A configured namespace or label selector is narrowed only by sending exactly the same
  selector. A selector cannot be safely ANDed by splitting on commas (`env in (a,b)`). When none is configured, any
  selector narrows.
- **Origin check.** In `serve` the Origin (or the Referer, if no Origin) must use `http` or `https` and name an allowed
  host; the port is ignored, as in the Host check. Behind a TLS-terminating proxy the browser sends `https`.
- **Read-only first.** In read-only mode a write gets the 403 read-only page before Origin and CSRF are checked.
- **Cancels.** Cancelling the running scan stays `POST /scans/cancel`. Cancelling a queued request is a new
  `POST /scans/queue/{request_id}/cancel`.
- **`FIELDS` moves.** `FIELDS` and `ACTIVE` move from `web/routes/scans.py` to `web/jobs.py`. The final review of PR 1
  asked for this.
- **Access log.** In `serve` the access line ends with the identity, or `-` when there is none.
- **No cookie yet.** A browser that has no CSRF cookie gets one on its first GET. Its first POST therefore always has a
  cookie when it came from a page kubedelos rendered. A POST with no cookie fails the CSRF check.

## Review Focus

1. **Forged or odd headers.**
   - With trust off, a header must be ignored: the scan is `anonymous`.
   - A header that is only whitespace or control characters means no identity.
   - A 10,000-character value is cut to 256.

   *Pinned in Task 1 and Task 2.*
2. **CSRF without a session.** Each of these must get 403:
   - a POST with no cookie;
   - a POST whose token is for another cookie;
   - a POST whose token is for the same cookie but another identity;
   - a POST with an Origin of `https://evil.example.org`.

   A form posted back with its own cookie and an Origin of `https://kubedelos.example.com:443` must pass.
   *Pinned in Task 2.*
3. **Scope escapes.** These must be rejected with a message naming what was outside, and nothing may be queued:
   - a namespace outside the configured list;
   - with "all namespaces" configured, a namespace the configuration excludes;
   - dropping a configured image exclusion;
   - a different selector;
   - a package type the configuration does not scan.

   *Pinned in Task 3 and Task 4.*
4. **Queue edge cases from the UI:**
   - The same scan twice queues one request and shows `already queued`.
   - The 11th distinct request gets 409 `the queue is full` and queues nothing.
   - Cancelling a request that already started changes nothing.

   *Pinned in Task 4.*
5. **Read-only and the laptop.**
   - Read-only mode must refuse every write route, including a new one added later, and hide every form.
   - The laptop must keep its token, session and CSRF flow and its direct runner start.

   *Pinned in Tasks 2, 4 and 5, and by the existing suite.*

---

### Task 1: Settings and the identity cleaner

**Files:**
- Modify: `kubedelos/config.py`
- Create: `kubedelos/web/identity.py`
- Test: `tests/test_config.py`, `tests/web/test_identity.py`

**Interfaces:**
- Produces:
  - `Settings` fields:
    - `read_only: bool = False`;
    - `trust_proxy_headers: bool = False`;
    - `identity_header: str = "X-Auth-Request-Email"`, stripped; an empty value or one with a character outside
      `[A-Za-z0-9-]` raises `ValueError`.
  - `kubedelos/web/identity.py`:
    - `MAX_IDENTITY = 256`;
    - `def clean_identity(raw: str | None) -> str | None` removes Unicode category `Cc`/`Cf` characters, strips
      whitespace, cuts to `MAX_IDENTITY`, and returns `None` for an empty result or `None` input;
    - `def identity(request: Request) -> str | None` returns `getattr(request.state, "identity", None)`.

- [ ] **Step 1: Write failing tests**
  - `test_serve_write_settings_default` (test_config): `read_only is False`, `trust_proxy_headers is False`,
    `identity_header == "X-Auth-Request-Email"`.
  - `test_identity_header_must_be_a_header_name`: `"X Auth"` and `""` raise `ValidationError`; `"Remote-User"` passes.
  - test_identity:
    - `test_clean_identity_strips_control_characters`:
      `clean_identity("a@example.com\r\nX-Evil: 1") == "a@example.comX-Evil: 1"`.
    - `test_clean_identity_caps_length`: `len(clean_identity("a" * 10_000)) == 256`.
    - `test_clean_identity_blank_means_none`, parametrized: `None`, `""`, `"   "`, `"\x00\x1b"` → `None`.
    - `test_clean_identity_keeps_unicode_names`: `clean_identity("  Jūratė@example.com ") == "Jūratė@example.com"`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_config.py tests/web/test_identity.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Use `unicodedata.category`.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: add the serve write settings and clean the identity value`.

### Task 2: Writes, CSRF and identity in the serve middleware

**Files:**
- Modify: `kubedelos/web/security.py` (`install_serve`; `_origin_ok` stays laptop-only), `kubedelos/web/app.py`
  (`create_serve_app`, the template globals), `kubedelos/web/templates/scans.html`,
  `kubedelos/web/templates/partials/scan_progress.html`
- Test: `tests/web/test_security.py`, `tests/web/test_app.py`, `tests/web/conftest.py`

**Interfaces:**
- Consumes: `clean_identity` and `identity` (Task 1); the three settings.
- Produces:
  - `security.ServeGuard`: `__init__(self, *, read_only: bool, trust_proxy_headers: bool, identity_header: str)`. It
    holds `csrf_secret = secrets.token_bytes(32)` and has these members:
    - `CSRF_COOKIE = "kubedelos_csrf"`;
    - `identity_of(request) -> str | None`: the cleaned header when trust is on, else `None`;
    - `csrf_token(cookie: str, identity: str | None) -> str`: the HMAC described in Global Constraints;
    - `check_csrf(cookie: str | None, identity: str | None, sent: str | None) -> bool`: constant-time, and False
      when the cookie is missing.
  - `install_serve(app, allowed_hosts, guard: ServeGuard)`. Per request, in this order:
    1. the Host check, as today;
    2. `request.state.identity = guard.identity_of(request)`;
    3. `request.state.csrf_cookie` = the request's cookie, or a new `secrets.token_urlsafe(32)` that is also set on the
       response with the attributes in Global Constraints;
    4. for a non-GET/HEAD request:
       - `guard.read_only` → the 403 read-only page (title `Read-only`, the notice text as its message);
       - otherwise the Origin/Referer check (scheme `http`/`https`, `host_name(netloc)` in `allowed_hosts`) and
         `check_csrf` with the token from header `x-csrf-token` or form field `csrf_token` (read with the existing
         `_sent_csrf`); a failure → `403 CSRF check failed`.

    The access line ends with ` <identity or ->`.
  - `create_serve_app` builds the guard from settings and keeps it as `app.state.serve_guard`. The template global
    `csrf_token(request)` returns `guard.csrf_token(request.state.csrf_cookie, identity(request))` in `serve`.
  - Template global `can_write(request) -> bool`: True on the laptop; `not read_only` in `serve`.
  - `scans.html` and `scan_progress.html` change their `{% if serve %}` / `not serve` hiding of the start form and the
    Cancel button to `can_write(request)`. The laptop markup is unchanged.

- [ ] **Step 1: Write failing tests** (test_security), with a `serve_client` fixture factory taking `read_only` and
  `trust_proxy_headers` and `allowed_hosts=["kubedelos.example.com"]`. A helper `signed_post(client, path, data,
  identity=None, origin="https://kubedelos.example.com")` GETs `/scans` first, reads the cookie and posts with the
  right token.
  - `test_first_get_sets_the_csrf_cookie`: `Set-Cookie` holds `kubedelos_csrf`, `HttpOnly` and `SameSite=Strict`. A
    second GET with it sets none.
  - `test_anonymous_write_reaches_the_route`: `POST /scans/cancel` via `signed_post` → 303.
  - `test_read_only_refuses_writes`: with `read_only=True`, `signed_post` → 403, and the body contains
    `this kubedelos is read-only`.
  - `test_post_without_cookie_is_refused` → 403 `CSRF check failed`.
  - `test_token_for_another_cookie_is_refused`.
  - `test_token_for_another_identity_is_refused`: with trust on, the token made for `a@example.com` is posted with
    header `b@example.com` → 403.
  - `test_foreign_origin_is_refused`: Origin `https://evil.example.org` → 403.
  - `test_https_origin_with_port_passes`: Origin `https://kubedelos.example.com:443` → 303.
  - `test_header_ignored_without_trust`: trust off, header `a@example.com` → the access log ends in ` -`.
  - `test_access_log_names_the_identity`: trust on → `POST /scans/cancel 303 a@example.com`.
  - `test_identity_is_cleaned_before_use`: header `a@example.com\x1b[31m` → the log holds `a@example.com[31m` and no
    ESC.
  - test_app:
    - `test_serve_forms_carry_the_token`: the Scans page HTML contains the expected token for its cookie.
    - `test_read_only_hides_the_scan_form_and_cancel`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_security.py tests/web/test_app.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: open writes in kubedelos serve with csrf and an optional read-only mode`.

### Task 3: The narrow-only scope rule (`kubedelos/scope.py`)

**Files:**
- Create: `kubedelos/scope.py`
- Test: `tests/test_scope.py`

**Interfaces:**
- Produces: `def outside_scope(configured: Settings, requested: Settings) -> str | None`. It returns `None` when the
  requested scan is the configured scope or a subset of it. Otherwise it returns the first problem as one line, in
  this order of checks:
  1. **Namespace list.** When `configured.namespaces` is non-empty, every requested namespace must be in it:
     `namespace kube-system is outside the configured scope`. An empty requested list means "the configured ones" and
     is fine.
  2. **Excluded namespaces.** When `configured.namespaces` is empty, no requested namespace may be one the
     configuration excludes (same message). Every configured exclusion must stay excluded:
     `namespace kube-system is excluded by the configured scope`.
  3. **Image exclusions.** Every configured `exclude_images` entry must still be there:
     `image exclusion registry.example.com/* is part of the configured scope`.
  4. **Selectors.** For `namespace_selector` and `selector`: when the configured value is not None, the requested
     value must be equal: `namespace selector must stay team=payments`, `label selector must stay app=web`.
  5. **Package types.** Each requested package type must be among the configured ones:
     `package type library is not in the configured scope`.

- [ ] **Step 1: Write failing tests**, one per rule plus the passing cases:
  - `test_same_scope_is_inside`;
  - `test_fewer_namespaces_is_inside`;
  - `test_namespace_outside_the_list`;
  - `test_all_namespaces_cannot_reach_an_excluded_one`;
  - `test_configured_exclusion_must_stay`;
  - `test_extra_exclusions_are_inside`;
  - `test_image_exclusion_must_stay`;
  - `test_selector_must_stay_when_configured`;
  - `test_any_selector_when_none_configured`;
  - `test_package_type_outside`;
  - `test_os_only_from_os_and_library_is_inside`.

  Each asserts the exact message above, or `None`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_scope.py -q`. Expected: FAIL (module missing).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest tests/test_scope.py -q`. Expected: PASS.
- [ ] **Step 5:** Commit `feat: limit ui scans in serve to the configured scope`.

### Task 4: UI scans, retries and cancels through the queue in `serve`

**Files:**
- Modify: `kubedelos/web/jobs.py` (gains `FIELDS` and `ACTIVE`), `kubedelos/web/worker.py` (imports them from jobs),
  `kubedelos/web/routes/scans.py`, `kubedelos/web/routes/failed.py`,
  `kubedelos/web/templates/partials/scan_queue.html`, `kubedelos/web/templates/scans.html`
- Test: `tests/web/test_scans.py`, `tests/web/test_failed.py`, `tests/web/test_worker.py`

**Interfaces:**
- Consumes:
  - `identity(request)` and `can_write(request)` (Tasks 1–2);
  - `outside_scope` (Task 3);
  - `queue.enqueue`, `queue.cancel`, `queue.QueueFull`, `queue.queued`;
  - `app.state.worker.wake()`;
  - `app.state.serve`.
- Produces, in `serve` only; the laptop branches are untouched:
  - **`POST /scans`**, after today's validation:
    - `outside_scope(app.state.settings, valid)`: a problem → 400 with that message on the page.
    - Then `queue.enqueue(conn, kind="scan", trigger="ui", overrides={**{n: getattr(valid, n) for n in FIELDS},
      "rescan": rescan}, requested_by=identity(request), now=clock())`, followed by `worker.wake()`.
    - Results:
      - `added` → 303 to `/scans`;
      - not `added` → 303 to `/scans?notice=queued`, where the page shows `already queued`;
      - `QueueFull` → 409 with `the queue is full`.
  - **`POST /scans/{run_id}/retry`**, after today's checks: enqueue `kind="retry", trigger="ui", target_run_id=run.id,
    overrides={"scan_timeout_s": timeout, "parallelism": valid.parallelism, "kinds": sorted(chosen)},
    requested_by=identity(request)`, then `wake()`. The redirects and the 409 are the same as for `POST /scans`.
  - **`POST /scans/queue/{request_id}/cancel`** (new; path int `ge=1`): `queue.cancel(conn, id)`, then 303 to
    `/scans` whatever the result.
  - **`POST /scans/cancel`** stays `runner.cancel()`.
  - **`partials/scan_queue.html`** gains a Cancel button per queued request when `can_write(request)`. It is a form
    posting to the new route with the CSRF token.
  - **By column.** The history and queue show `requested_by`, else `schedule` for trigger `schedule`, else
    `anonymous` for trigger `ui`.
  - **`?notice=queued`** shows `already queued` in the queue card; any other value is ignored.

- [ ] **Step 1: Write failing tests**, with the Task 2 `signed_post` helper; the worker fake records `wake()`.
  - test_scans:
    - `test_serve_scan_is_queued`: one `queued` request with `trigger == "ui"`, `requested_by is None` and the form's
      namespaces in its overrides; `wake` called; the runner was not started.
    - `test_serve_scan_records_the_trusted_identity`: trust on, identity `a@example.com` → `requested_by` set.
    - `test_anonymous_ui_run_shows_anonymous`: a history row with trigger `ui` and no requester shows `anonymous`.
    - `test_serve_same_scan_twice_says_already_queued`: the second POST lands on `/scans?notice=queued`, the page
      contains `already queued`, and there is still one request.
    - `test_serve_full_queue_is_409`: with 10 distinct requests queued, the 11th → 409 `the queue is full`, still 10.
    - `test_serve_scan_outside_scope_is_rejected`: configured `namespaces=["web"]`, form `kube-system` → 400 with
      `namespace kube-system is outside the configured scope`, and nothing queued.
    - `test_serve_cancel_queued_request`: the request becomes `cancelled`.
    - `test_serve_cancel_started_request_changes_nothing`: still `started`, 303.
    - `test_read_only_queue_card_has_no_cancel`.
    - `test_laptop_scan_still_starts_the_runner`: the laptop client POST starts the fake runner, and no
      `scan_request` row is written.
  - test_failed:
    - `test_serve_retry_is_queued`: `kind == "retry"`, `target_run_id == run.id`, `overrides["kinds"]` sorted.
    - `test_serve_retry_twice_says_already_queued`.
  - test_worker: the existing tests still pass with the new import path.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Move `FIELDS` and `ACTIVE` into `jobs.py`.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: queue ui scans, retries and cancels in kubedelos serve`.

### Task 5: Read-only pages and the acceptance owner

**Files:**
- Modify: `kubedelos/web/templates/failed.html`, `kubedelos/web/templates/accept_form.html`,
  `kubedelos/web/templates/accepted.html`, `kubedelos/web/templates/base.html` (the read-only notice),
  `kubedelos/web/routes/accepted.py`
- Test: `tests/web/test_failed.py`, `tests/web/test_accepted_pages.py`, `tests/web/test_app.py`

**Interfaces:**
- Consumes: `can_write(request)` and `identity(request)` (Tasks 1–2).
- Produces:
  - **Hidden forms.** When `can_write(request)` is false (read-only `serve`):
    - the retry form on the failures page is not rendered;
    - the accept form is replaced by its page text plus the notice;
    - revoke buttons are not rendered.
  - **Read-only notice.** In read-only `serve`, `base.html` shows the notice `View-only: this kubedelos is read-only.`
    (class `notice`) under the page head. The laptop and a writable `serve` never show it.
  - **Acceptance owner in `serve` with an identity:**
    - The owner field is prefilled with the identity.
    - `POST /accepted` with an empty owner records the identity.
    - A typed owner is kept as typed; it can name a team.
  - **Without an identity**, and on the laptop, the owner field stays required, as today.

- [ ] **Step 1: Write failing tests**
  - `test_read_only_pages_show_the_notice`: `/`, `/findings`, `/scans` and `/accepted` contain the notice. A writable
    serve `/` and the laptop `/` do not.
  - `test_read_only_failures_page_has_no_retry_form`, and `test_writable_failures_page_has_it`.
  - `test_read_only_accepted_page_has_no_revoke`.
  - `test_accept_form_prefills_the_trusted_identity`: `value="a@example.com"`.
  - `test_empty_owner_becomes_the_identity`: the stored acceptance's owner is `a@example.com`.
  - `test_typed_owner_is_kept`: `team-payments` is stored.
  - `test_empty_owner_without_identity_is_refused`: 400, as on the laptop.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: hide write forms in read-only serve and own acceptances by identity`.

### Task 6: Docs and a manual check

**Files:**
- Modify: `README.md` (the `kubedelos serve` section), `CHANGELOG.md`, `AGENTS.md` (the Project paragraph no longer
  calls serve view-only)
- Test: none new. The full suite and the manual check are the evidence.

- [ ] **Step 1: README.** Rewrite the serve section's writes paragraph:
  - writes are open by default, so anyone who reaches the UI can scan within the configured scope, retry, cancel, and
    accept or revoke risks;
  - `KUBEDELOS_READ_ONLY=true` turns writes off;
  - `KUBEDELOS_TRUST_PROXY_HEADERS` and `KUBEDELOS_IDENTITY_HEADER` (with their defaults) put the user's name on scans
    and acceptances; turn trust on only when the proxy overwrites the header and nothing else can reach the pod;
  - the narrow-only rule in one sentence;
  - keep the existing warning about who can reach the UI, and widen it to cover writes.
- [ ] **Step 2: CHANGELOG** under `## Unreleased` Features:
  - writes in `kubedelos serve` (UI scans, retries and cancels through the queue, within the configured scope);
  - optional read-only mode;
  - the user's name from a trusted proxy header;
  - acceptances default their owner to that name.
- [ ] **Step 3:** Run `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . &&
  .venv/bin/pre-commit run --all-files`. Expected: all clean.
- [ ] **Step 4: Manual check against a disposable test cluster.** Use a scratch data dir and run `serve` on
  `127.0.0.1:9371`.
  - With a `curl` cookie jar: GET `/scans`, then POST `/scans` with the cookie, `Origin: http://127.0.0.1:9371` and the
    page's token. A scan is queued, runs, and shows `anonymous` in the By column.
  - Again with `KUBEDELOS_TRUST_PROXY_HEADERS=true` and `-H 'X-Auth-Request-Email: a@example.com'`: the By column shows
    `a@example.com`.
  - With `KUBEDELOS_READ_ONLY=true`: the notice shows and the POST gets 403.

  Stop the process afterwards.
- [ ] **Step 5:** Commit `docs: document writes and read-only mode for kubedelos serve`, then push
  `feat/serve-identity` and open the PR with `Refs #12, #24`.
