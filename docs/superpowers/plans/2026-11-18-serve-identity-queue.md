# kubedelos serve: sign-in header, view-only mode and UI scans through the queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user signed in by the operator's proxy start scans, retries and cancels, and accept or revoke risks in
`kubedelos serve`, with every scan going through the queue and limited to the configured scope. Without a trusted
identity, `serve` stays view-only and hides its forms.

**Architecture:**
- **Identity.** The serve middleware reads the identity header only when `KUBEDELOS_TRUST_PROXY_HEADERS` is on. It
  cleans the value and puts it on `request.state.identity`.
- **Writes.** A write needs an identity, an Origin that names an allowed host, and a CSRF token. The token is an HMAC
  of the identity, keyed by a secret made at start-up.
- **Routes in `serve`.** The serve branches of the POST routes enqueue requests instead of calling the runner, so the
  queue worker stays the only scan starter. A pure function rejects scan requests that reach outside the configured
  scope.
- **Laptop UI.** `kubedelos ui` is unchanged.

**Tech Stack:** Python 3.12+, FastAPI, Jinja2, SQLite.

**Spec:** `docs/superpowers/specs/2026-11-18-in-cluster-mode-design.md`:
- section 2: "Scope is narrow-only", "Coalesced", "Bounded", "Cancellable", "Retries are queued too";
- section 4: Identity and view-only mode;
- "Delivery" item 2.

The chart (NetworkPolicy guard, `NOTES.txt`) is PR 3. Registry login and the "Test an image" box are PR 4.

## Global Constraints

- Read-only cluster access: no code path may change cluster objects or read Secrets.
- Credentials never touch disk or logs. The identity value is not a credential, but it is untrusted text: it is cleaned
  before any use.
- TDD; one test file per module; ruff line length 120; a docstring at the top of every new module saying what and why.
- Placeholders only: `my-cluster`, `my-context`, `example.com`, `a@example.com`.
- Conventional Commits with lowercase subjects, no co-author or attribution lines. Work on branch `feat/serve-identity`.
- `CHANGELOG.md` entries go under `## Unreleased`. The README's `kubedelos serve` section is updated.
- `kubedelos ui` behaviour does not change; every existing test keeps passing.
- Spec values:
  - `KUBEDELOS_TRUST_PROXY_HEADERS`: default `false`.
  - `KUBEDELOS_IDENTITY_HEADER`: default `X-Auth-Request-Email`.
  - The identity value has control characters stripped and is capped at **256** characters. An empty result means no
    identity.
  - The queue holds at most 10 requests (`queue.MAX_QUEUED`). A full queue gives the message `the queue is full`. A
    coalesced request gives `already queued`.
  - The CSRF token is the HMAC-SHA256 of the identity value, keyed by a secret made at start-up.
  - An acceptance whose owner field is left empty is recorded with the identity as owner.

## Rulings this plan makes on top of the spec

- **Selector narrowing.** A configured namespace or label selector is narrowed only by sending exactly the same
  selector. A selector cannot be safely ANDed by splitting on commas (`env in (a,b)`). When none is configured, any
  selector narrows.
- **Origin check.** In `serve` the Origin (or the Referer, if no Origin) must use `http` or `https` and name an allowed
  host; the port is ignored, as in the Host check. Behind a TLS-terminating proxy the browser sends `https`.
- **The identity is checked before CSRF.** A write without an identity gets the existing view-only 403 page, whatever
  else it carries.
- **Cancels.** Cancelling the running scan stays `POST /scans/cancel` (needs an identity). Cancelling a queued request
  is a new `POST /scans/queue/{request_id}/cancel`.
- **`FIELDS` moves.** `FIELDS` and `ACTIVE` move from `web/routes/scans.py` to `web/jobs.py`. The final review of PR 1
  asked for this: the worker should not import from a routes module.
- **Access log.** In `serve` the access log line gains the identity as its last field (`-` when there is none).

## Review Focus

1. **Forged or odd headers.** A request with the identity header while trust is off must be treated as anonymous. A
   header that is only whitespace or control characters means no identity. An identity of 10,000 characters is
   stored cut to 256. *Pinned in Task 1 and Task 2.*
2. **CSRF bound to identity.** A form fetched as user A and posted with user B's header, or with no token, or with an
   Origin of `https://evil.example.org` must get 403. The same form posted as A, with an Origin of
   `https://kubedelos.example.com:443`, must pass. *Pinned in Task 2.*
3. **Scope escapes.** These must be rejected with a message naming what was outside, and nothing may be queued:
   - a namespace outside the configured list;
   - with "all namespaces" configured, a namespace the configuration excludes;
   - dropping a configured image exclusion;
   - a different selector;
   - a package type the configuration does not scan.

   *Pinned in Task 3 and Task 4.*
4. **Queue edge cases from the UI:**
   - Pressing Scan twice with the same form queues one request and shows `already queued`.
   - The 11th distinct request shows `the queue is full` (409) and queues nothing.
   - Cancelling a request that already started returns to the page with no error and changes nothing.

   *Pinned in Task 4.*
5. **Laptop UI.** The laptop must keep its token, session and CSRF flow, its start form and its direct runner start.
   *Pinned by the existing test suite, which every task runs, plus `test_laptop_scan_still_starts_the_runner` in Task 4.*

---

### Task 1: Identity settings and the identity cleaner

**Files:**
- Modify: `kubedelos/config.py`
- Create: `kubedelos/web/identity.py`
- Test: `tests/test_config.py`, `tests/web/test_identity.py`

**Interfaces:**
- Produces:
  - `Settings.trust_proxy_headers: bool = False` and `Settings.identity_header: str = "X-Auth-Request-Email"`.
    `identity_header` is stripped; an empty value or one with a character outside `[A-Za-z0-9-]` raises
    `ValueError`.
  - `kubedelos/web/identity.py`:
    - `MAX_IDENTITY = 256`;
    - `def clean_identity(raw: str | None) -> str | None` removes every Unicode category `Cc`/`Cf` character, strips
      surrounding whitespace, cuts to `MAX_IDENTITY`, and returns `None` for an empty result or `None` input;
    - `def identity(request: Request) -> str | None` returns `getattr(request.state, "identity", None)`.

- [ ] **Step 1: Write failing tests**
  - `test_identity_header_defaults` (test_config): `Settings().identity_header == "X-Auth-Request-Email"` and
    `Settings().trust_proxy_headers is False`.
  - `test_identity_header_must_be_a_header_name`: `"X Auth"` and `""` raise `ValidationError`; `"Remote-User"` passes.
  - test_identity:
    - `test_clean_identity_strips_control_characters`: `clean_identity("a@example.com\r\nX-Evil: 1") == "a@example.comX-Evil: 1"`.
    - `test_clean_identity_caps_length`: `len(clean_identity("a" * 10_000)) == 256`.
    - `test_clean_identity_blank_means_none`, parametrized: `None`, `""`, `"   "`, `"\x00\x1b"` → `None`.
    - `test_clean_identity_keeps_unicode_names`: `clean_identity("  Jūratė@example.com ") == "Jūratė@example.com"`.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/test_config.py tests/web/test_identity.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Use `unicodedata.category`.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: add the proxy identity settings and clean the identity value`.

### Task 2: Identity, Origin and CSRF in the serve middleware

**Files:**
- Modify: `kubedelos/web/security.py` (`install_serve`, `_origin_ok` stays laptop-only), `kubedelos/web/app.py`
  (`create_serve_app`, the template globals)
- Test: `tests/web/test_security.py`, `tests/web/test_app.py`, `tests/web/conftest.py` (fixtures)

**Interfaces:**
- Consumes: `clean_identity` and `identity` (Task 1); `Settings.trust_proxy_headers` and `identity_header`.
- Produces:
  - `security.ServeGuard`: `__init__(self, *, trust_proxy_headers: bool, identity_header: str)`. It makes
    `csrf_secret = secrets.token_bytes(32)` and has these methods:
    - `identity_of(request) -> str | None` returns `clean_identity(request.headers.get(identity_header))` when trust
      is on, else `None`;
    - `csrf_token(identity: str) -> str` returns the hex HMAC-SHA256 of `identity`, keyed by `csrf_secret`;
    - `check_csrf(identity: str, sent: str | None) -> bool`, in constant time.
  - `install_serve(app, allowed_hosts, guard: ServeGuard)`. Per request, in this order:
    1. the Host check, as today;
    2. `request.state.identity = guard.identity_of(request)`;
    3. for a non-GET/HEAD request: no identity → the existing `_view_only` 403 page;
    4. then an Origin/Referer whose scheme is `http`/`https` and whose `host_name(netloc)` is in `allowed_hosts`,
       plus a CSRF token (header `x-csrf-token` or form field `csrf_token`, read with the existing `_sent_csrf`) that
       passes `check_csrf`; failing either → `403 CSRF check failed`.

    The access line ends with ` <identity or ->`.
  - `create_serve_app` builds a `ServeGuard` from settings and stores it as `app.state.serve_guard`. The template
    global `csrf_token(request)` returns `guard.csrf_token(identity)` when there is an identity, else `""`.
  - A template global `can_write(request) -> bool`: True on the laptop, and in `serve` only when
    `identity(request) is not None`.

- [ ] **Step 1: Write failing tests** (test_security). Use a `serve_client` fixture with
  `trust_proxy_headers=True, allowed_hosts=["kubedelos.example.com"]`, and helpers to send `X-Auth-Request-Email` and
  a token taken from `app.state.serve_guard.csrf_token(...)`.
  - `test_trust_off_ignores_the_header`: trust off, a POST with header `a@example.com` → 403 and `view-only` in the body.
  - `test_write_without_identity_is_view_only`: trust on, no header → 403 `view-only`.
  - `test_write_with_identity_origin_and_token_reaches_the_route`: `POST /scans/cancel` with header, Origin
    `https://kubedelos.example.com:443` and A's token → 303.
  - `test_token_of_another_identity_is_refused`: B's header with A's token → 403 `CSRF check failed`.
  - `test_missing_token_is_refused` and `test_foreign_origin_is_refused`: Origin `https://evil.example.org` → 403.
  - `test_referer_counts_when_origin_is_absent`.
  - `test_access_log_names_the_identity`: caplog at INFO contains `POST /scans/cancel 303 a@example.com`. An
    anonymous GET ends in ` -`.
  - `test_identity_is_cleaned_before_use`: header `a@example.com\x1b[31m` → the log holds `a@example.com[31m` and no
    ESC character.
  - test_app:
    - `test_serve_forms_carry_the_identity_token`: with identity A, the Scans page HTML contains
      `value="<A's token>"`;
    - `test_can_write_false_without_identity`: no Scans start form and no Cancel button in the HTML.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web/test_security.py tests/web/test_app.py -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Replace the Scans template's `{% if serve %}` hiding of the start form and Cancel button
  with `{% if can_write(request) %}`, keeping the laptop markup unchanged.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: let a proxy-signed-in user write in kubedelos serve`.

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
  - `identity(request)` (Task 1);
  - `outside_scope` (Task 3);
  - `queue.enqueue`, `queue.cancel`, `queue.QueueFull`, `queue.queued`;
  - `app.state.worker.wake()`;
  - `app.state.serve`.
- Produces, in `serve` only (`app.state.serve` is True); the laptop branches are untouched:
  - **`POST /scans`**, after today's validation:
    - `outside_scope(app.state.settings, valid)`: a problem → 400 with that message on the page.
    - Then `queue.enqueue(conn, kind="scan", trigger="ui", overrides={**{n: getattr(valid, n) for n in FIELDS},
      "rescan": rescan}, requested_by=identity, now=clock())`, followed by `worker.wake()`.
    - Results:
      - `added` → 303 to `/scans`;
      - not `added` → 303 to `/scans?notice=queued`, where the page shows `already queued`;
      - `QueueFull` → 409 with `the queue is full`.
  - **`POST /scans/{run_id}/retry`**, after today's checks: enqueue `kind="retry", trigger="ui", target_run_id=run.id,
    overrides={"scan_timeout_s": timeout, "parallelism": valid.parallelism, "kinds": sorted(chosen)},
    requested_by=identity`, then `wake()`. The redirects and the 409 are the same as for `POST /scans`.
  - **`POST /scans/queue/{request_id}/cancel`** (new; `request_id` is a path int `ge=1`): `queue.cancel(conn, id)`,
    then 303 to `/scans` whatever the result.
  - **`POST /scans/cancel`** stays `runner.cancel()`.
  - **`partials/scan_queue.html`** gains a Cancel button per queued request when `can_write(request)`. It is a form
    posting to the new route with the CSRF token.
  - **`?notice=queued`** shows the line `already queued` in the queue card. Any other `notice` value is ignored.

- [ ] **Step 1: Write failing tests.** Use the Task 2 signed-in `serve_client` helpers; the worker fake records `wake()`.
  - test_scans:
    - `test_serve_scan_is_queued_with_the_requester`: one `queued` request with `trigger == "ui"`,
      `requested_by == "a@example.com"` and the form's namespaces in its overrides; `wake` called; the runner was not
      started.
    - `test_serve_same_scan_twice_says_already_queued`: the second POST lands on `/scans?notice=queued`; the page
      contains `already queued`; still one request.
    - `test_serve_full_queue_is_409`: with 10 distinct requests queued, the 11th → 409 `the queue is full`, still 10.
    - `test_serve_scan_outside_scope_is_rejected`: configured `namespaces=["web"]`, form `kube-system` → 400 with
      `namespace kube-system is outside the configured scope`, and nothing queued.
    - `test_serve_cancel_queued_request`: the request becomes `cancelled`.
    - `test_serve_cancel_started_request_changes_nothing`: still `started`, 303.
    - `test_queue_card_offers_cancel_only_when_signed_in`.
    - `test_laptop_scan_still_starts_the_runner`: the existing laptop client POST starts the fake runner, and no
      `scan_request` row is written.
  - test_failed:
    - `test_serve_retry_is_queued`: `kind == "retry"`, `target_run_id == run.id`, `overrides["kinds"]` sorted, the
      requester set.
    - `test_serve_retry_twice_says_already_queued`.
  - test_worker: the existing tests still pass with the new import path (no new test).
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. Move `FIELDS` and `ACTIVE` into `jobs.py`; `routes/scans.py` and `worker.py` import them
  from there.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: queue ui scans, retries and cancels in kubedelos serve`.

### Task 5: View-only pages and the acceptance owner

**Files:**
- Modify: `kubedelos/web/templates/failed.html`, `kubedelos/web/templates/accept_form.html`,
  `kubedelos/web/templates/accepted.html`, `kubedelos/web/templates/base.html` (a view-only notice),
  `kubedelos/web/routes/accepted.py`
- Test: `tests/web/test_failed.py`, `tests/web/test_accepted_pages.py`, `tests/web/test_app.py`

**Interfaces:**
- Consumes: `can_write(request)` and `identity(request)` (Tasks 1–2).
- Produces:
  - **Hidden forms.** When `can_write(request)` is false:
    - the retry form on the failures page is not rendered;
    - the accept form is replaced by its page text plus the notice;
    - revoke buttons are not rendered.
  - **View-only notice.** In `serve` with no identity, `base.html` shows one notice under the page head:
    `View-only: sign in through your proxy to start scans or accept risks.` (class `notice`). The laptop never shows
    it.
  - **Acceptance owner in `serve`:**
    - The accept form's owner field is prefilled with the identity.
    - `POST /accepted` with an empty `owner` records the identity as owner.
    - A non-empty owner is kept as typed; it can name a team.
  - **Laptop.** The owner rules are unchanged on the laptop.

- [ ] **Step 1: Write failing tests**
  - `test_serve_anonymous_pages_show_the_view_only_notice`: `/`, `/findings`, `/scans` and `/accepted` contain the
    notice; the laptop `/` does not.
  - `test_serve_anonymous_failures_page_has_no_retry_form`, and `test_serve_signed_in_failures_page_has_it`.
  - `test_serve_anonymous_accepted_page_has_no_revoke`.
  - `test_serve_accept_form_prefills_the_owner`: `value="a@example.com"`.
  - `test_serve_empty_owner_becomes_the_identity`: the stored acceptance has owner `a@example.com`.
  - `test_serve_typed_owner_is_kept`: owner `team-payments` is stored as typed.
- [ ] **Step 2:** Run `.venv/bin/pytest tests/web -q`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement. In serve, the accept route removes `required` from the owner check only when an identity
  is present.
- [ ] **Step 4:** Run `.venv/bin/pytest -q`. Expected: all PASS.
- [ ] **Step 5:** Commit `feat: hide write forms in view-only serve and own acceptances by identity`.

### Task 6: Docs and a manual check

**Files:**
- Modify: `README.md` (the `kubedelos serve` section), `CHANGELOG.md`, `AGENTS.md` (Project paragraph: serve is no
  longer only view-only)
- Test: none new. The full suite and the manual check are the evidence.

- [ ] **Step 1: README.** Rewrite the serve section's sign-in paragraph:
  - `KUBEDELOS_TRUST_PROXY_HEADERS` and `KUBEDELOS_IDENTITY_HEADER`, with their defaults;
  - with trust on, a signed-in user can scan (within the configured scope), retry, cancel, and accept or revoke risks;
    without trust, the instance is view-only;
  - turn trust on only when the proxy overwrites the header and nothing else can reach the pod (the chart's
    NetworkPolicy, coming next), because otherwise any client can claim to be anyone;
  - the narrow-only rule in one sentence.
- [ ] **Step 2: CHANGELOG** under `## Unreleased` Features:
  - sign-in through a trusted proxy header for `kubedelos serve`;
  - UI scans, retries and cancels go through the queue, within the configured scope;
  - view-only pages hide their forms;
  - acceptances default their owner to the signed-in user.
- [ ] **Step 3:** Run `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . &&
  .venv/bin/pre-commit run --all-files`. Expected: all clean.
- [ ] **Step 4: Manual check against a disposable test cluster.** Use a scratch data dir and
  `KUBEDELOS_TRUST_PROXY_HEADERS=true`, and run `serve` on `127.0.0.1:9371`.
  - Anonymous: `curl` of `/scans` shows the view-only notice, and a POST gets 403.
  - Signed in: `curl -H 'X-Auth-Request-Email: a@example.com'` of `/scans` gives a page with the CSRF token. A POST
    to `/scans` with that header, `Origin: http://127.0.0.1:9371` and the token queues a scan that runs and shows
    `a@example.com` in the By column.

  Stop the process afterwards.
- [ ] **Step 5:** Commit `docs: document sign-in for kubedelos serve`, then push `feat/serve-identity` and open the
  PR with `Refs #12, #24`.
