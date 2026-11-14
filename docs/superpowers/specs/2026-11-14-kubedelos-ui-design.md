# kubedelos ui: local web UI (Phase 2, #11)

Parent spec: `docs/superpowers/specs/2026-11-13-kubedelos-design.md`. Run-selection rules: issue #24.

## Intent

When you open `kubedelos ui` on a laptop, the first thing you want is the **overall status of the cluster and its most important
findings**: how bad it is, what to fix first, and whether the data can be trusted (how old it is, what failed). Everything else
in Phase 2 (scanning from the UI, accepted risk, namespaces, compare, reports) builds on that screen.

The UI is a single-user local tool. It reads what `kubedelos scan` stored in SQLite, and from PR 2 on it can start scans
through the same read-only scan service. The older internal tool is a feature and UX reference only: no code, markup, CSS or
SQL is reused, and no internal names appear.

## Goals

- One screen that answers "how is this cluster doing, and what do I fix first", with numbers you can trust.
- Every page says which run it shows, how old it is, and why that run.
- Nothing is capped silently. Where a list is cut, the page gives the real total and links to the full list.
- Filters and sorting live in the URL, so a view survives a reload, a bookmark and a link sent to a colleague.
- It works without JavaScript except for live scan progress (PR 2).

## Non-goals (Phase 2)

- Trend charts. Trends compare sweeps (#24), and sweeps arrive with Phase 3. On a laptop the dashboard compares against the
  previous comparable run instead.
- Authentication, multiple users, any remote-access mode, and a scan queue. All of these are Phase 3 (#12, #24).
- Emailing owners (Phase 4, #15, #28).
- A context switcher. The UI is bound to one kube context at launch.
- PDF generation. The report is a print-friendly HTML page.

## Anti-goals (it fails even if it technically works when...)

- An incomplete run reads as a clean cluster: failed images hidden, a failed run linked as results, or a one-namespace scan
  shown as the cluster.
- The action list is hundreds of rows repeating one base-image rebuild (that is why the default groups by fix).
- Any page can change cluster objects or read Secrets, or a credential reaches the page, the DB or a log.
- A web page on another origin can drive the UI: DNS rebinding, CSRF or framing.

## Constraints

- All the AGENTS.md rules: read-only cluster access, Trivy pinned, credentials never on disk or in logs, TDD, one test file
  per module, Python 3.12+, Ruff at line length 120, a docstring per module, placeholders in examples.
- FastAPI + Jinja2 + HTMX, no Node build. Static assets ship in the wheel. HTMX is vendored at a pinned version with its
  SHA-256 recorded and checked by a test.
- `kubedelos ui` is a subcommand of the one `kubedelos` command. The dependencies are core, not an extra, with bounds of
  `>=X.Y,<X+1` at the current stable release.
- Binds to loopback only (`127.0.0.1:9370` by default). Phase 2 has no `--allow-remote`. To use it from another machine,
  forward the port over SSH (`ssh -L 9370:127.0.0.1:9370 host`). This overrides the parent spec's `--allow-remote` call:
  remote access comes with `kubedelos serve` and its proxy auth in Phase 3.

## Approaches

1. **Dashboard first, one slice at a time (picked).** PR 1 ships the app, its security, the dashboard and the findings
   page, reading stored runs. PRs 2–4 each add one capability. The screen the user asked for comes first, and each PR stays
   reviewable.
2. All read-only pages first, then the write actions. Cleaner to review, but scanning from the UI waits until the end.
3. One PR for the whole phase. Rejected: too large to review well.

The user picked approach 1 on 2026-11-14.

## PR 1: the app, the dashboard and findings

### Command

`kubedelos ui [--port 9370] [--host 127.0.0.1|::1|localhost] [--no-browser] [--context NAME] [--kubeconfig PATH]`

- **`--host`:** only loopback values are accepted. Any other value exits 2.
- **Database:** at startup the UI opens the database once with the normal `store.db.connect()`, which creates it if
  missing and applies migrations (including PR 1's coverage and index migration). After that, every request opens it
  read-only.

- **Context resolution:** the context comes from `--context` or the kubeconfig's current context, resolved once at startup
  with the existing kube client loader. If none can be resolved, it exits 2 with the same message `scan` gives. PR 1 needs
  the context name only, not API access.
- **Startup URL:** a random token of at least 32 bytes is generated at startup and printed as
  `http://127.0.0.1:9370/?token=…`, and the browser opens that URL unless `--no-browser` is passed.
- **Session:** a valid token sets an HttpOnly, `SameSite=Strict` session cookie, then redirects to the same URL without the
  token. A request without a valid cookie gets a 403 page that says to use the URL printed in the terminal.
- **Server:** one uvicorn process with one worker, and Ctrl-C stops it cleanly.
- **Port in use:** it exits 2 with `error: port 9370 is in use; pass --port`.

### Security (always on)

- **Host header check:** the Host header must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`. Anything else
  gets a 400. This is the DNS-rebinding defence.
- **Response headers:** a strict CSP with a fresh nonce per response: `default-src 'self'; script-src 'self' 'nonce-…';
  style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  Also `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cross-Origin-Opener-Policy: same-origin` and
  `Cache-Control: no-store` on HTML.
- **CSRF on every non-GET:** an HMAC token tied to the session, sent as a form field or an `X-CSRF-Token` header and
  compared in constant time. The `Origin` header (or `Referer`) must match the host. PR 1 has no write routes, but the
  middleware and its tests land here.
- **Output:** Jinja autoescape stays on, and there are no inline event handlers.
- **External links:** a CVE's `primary_url` is rendered as a link only when its scheme is http or https, with
  `rel="noopener noreferrer"`.
- **Access log:** never logs query strings, because the startup token is one.

### Which run each page shows

- **Runs considered:** only runs of the UI's context with status `ok` or `partial` count as results. `failed`, `cancelled`
  and `running` runs are never shown as results.
- **Cluster scope:** a run has cluster scope when its scope has no `namespaces`, no `namespace_selector` and no `selector`.
  Exclusions (`exclude_namespaces`, `exclude_images`) are allowed but are named in the run label.
- **Rule per page:**

| Page | Run | Why |
|---|---|---|
| Dashboard | newest cluster-scope run | the status of the cluster needs a run that covered the cluster |
| Findings | newest run of any scope | the scan you just ran |
| (PR 3) Namespaces | newest cluster-scope run | a per-namespace breakdown only makes sense against the whole cluster |

- **Runs from before migration 3:** a run with no recorded scope (`scope IS NULL`) never counts as cluster scope and is
  never comparable. When it is shown (findings, or pinned), the run line says "scope not recorded". A run with no
  recorded scan level (`pkg_types IS NULL`) says "package types not recorded" and gets no OS-only note. Its findings,
  whose `pkg_class` is NULL, match only `pkg=all`.
- **Pinning:** `?run_id=N` pins any page to one run, and the page says it is pinned. A `run_id` of another context, or of a
  run that isn't `ok`/`partial`, gets a 404 page that says why.
- **The run line:** every page has a sentence under its heading naming the run. Example: "Run 42 · whole cluster, excluding
  images `busybox:*` · os + library packages · finished 2 h ago · 142 images, 3 failed".
- **Staleness:** a run older than 24 hours gets a "stale" badge in the run line.
- **A newer, narrower run:** when the dashboard skips one, the page says so and links to it ("a newer run of namespace `web`
  exists, from 10 min ago: see its findings").

### Coverage gaps (stored from PR 1)

- **The problem:** today a run whose inventory skipped namespaces or resources (`InventoryWarning(coverage=True)`: forbidden,
  or not found) is stored as `ok`, because nothing records the warnings. The dashboard would then show a cluster with
  invisible namespaces as whole and clean. That is the first anti-goal.
- **The fix:** PR 1 adds a migration with a `run_warning` table (run_id, text, coverage), and `run_scan` stores every
  inventory warning through `Repo`. The CLI's output and exit codes don't change.
- **How the UI uses it:**
  - A cluster-scope run with coverage gaps still counts as cluster scope, but it's marked incomplete.
  - The run line says "incomplete: N namespaces or resources could not be listed", with the list in a `<details>`.
  - Every KPI tile gets the caution mark.
  - A run with gaps is still comparable, and the caution names both sides.

### What is counted

These units are used everywhere (tiles, bricks, totals, the findings page and, later, CSV and accepted risk), so the numbers
always agree:
- **An image** is a distinct scanned ref (`repo@digest`, or the ref for tag-only images). A multi-platform ref scanned for
  two node platforms is one image. Its findings are the union of both platforms, without duplicates.
- **A finding** is a distinct (image, CVE, package, installed version). Trivy reporting the same package twice in one image
  (two jars, for example) is one finding. Its targets are kept for the findings page.
- **A failed image** is a ref with at least one failed platform. The failed-images list shows each failed platform.

### Dashboard (`/`), top to bottom

1. **Header** (on every page): wordmark, nav (Dashboard, Findings; more in later PRs), and the context as a label.
2. **Run line**, as above.
3. **KPI tiles:**
   - Critical findings
   - High findings
   - images with a Critical, out of the images scanned
   - all findings
   - images that failed to scan (only when non-zero, with an error style)

   Each tile shows the change since the **previous comparable run**: same context, same scope JSON, same scan level, status
   `ok`/`partial`. If there's none, it says "no earlier comparable run". A tile's change gets a caution mark when either
   run had failed images.
4. **Severity bricks:** one per severity (Critical, High, Medium, Low, and Unknown only if non-zero). Each shows its count
   and links to the findings filtered to that severity. Severity is always written in words, never shown by colour alone.
5. **Fix first:** Critical and High findings that have a `fixed_version`, from the dashboard's run.
   - **Grouped by fix (the default):**
     - **Row key:** CVE, package and fixed version.
     - **Columns:** severity, CVE (linked when allowed), package, installed versions (distinct, comma-separated), fixed in,
       images, namespaces.
     - **Sort:** severity, then images (descending), then namespaces (descending), then CVE.
     - **Expander:** each row is a native `<details>` that lists the affected images and their namespaces, capped at 20,
       followed by "and N more" and a link to the findings page filtered to that CVE and package.
   - **Grouped by image (`?by=image`):** one row per image, with its namespaces, the Critical count, the High count and how
     many have a fix. Sorted by Critical count, then High count.
   - **Cap and summary:** both views show the first 25 rows, then "showing 25 of N" with a link to the full list on the
     findings page. Under the list goes one line: "N Critical/High findings have no released fix yet, across M images",
     linking to findings with `has_fix=no`.
6. **Failed images:** only when some images failed.
   - **Rows:** one per failed image, showing ref, platform, error kind and `error_cause()` of its stored error (#18).
   - **Login hints:** auth failures get the same login hint the CLI prints, once per registry host.
   - **Cap:** 25 rows, with the real total stated.
7. **Empty states:**
   - **No runs for this context:** "No scans of `<context>` yet. Run `kubedelos scan` and reload." From PR 2 it is a
     button instead.
   - **Only narrower runs:** the dashboard says no cluster-wide run exists and links to the newest narrower run's findings.
   - **A run with zero findings:** "No vulnerabilities found in N images." This shows only when no image failed. Otherwise
     it says how many failed, so a clean result and a broken scan can't look the same.

### Findings (`/findings`)

- **Rows:** one per finding per scanned image.
- **Columns:** severity, CVE, package, installed, fixed in, package class (os/library), image (`repo:tag` plus a short
  digest, with the full ref in a `title`), and namespaces (the first 3, then "+N").
- **Filters (all GET parameters):**
  - `severity`: one or more
  - `namespace`: exact, chosen from the run's namespaces
  - `cve`: exact
  - `package`: exact
  - `has_fix`: `any`, `yes` or `no`
  - `pkg`: `all`, `os` or `library`, default `all`
  - `q`: a substring of the image, CVE or package
  - `run_id`

  The filter form is a plain GET form, and a "clear filters" link resets it.
- **Sort:** `sort` (severity, cve, package, image, namespace, fixed) and `dir`. The default is severity, worst first, then
  CVE and image. Clicking the active column heading reverses it.
- **Paging:** `page`, 100 rows per page, with "X–Y of N" and previous/next links. Filtering, counting and paging happen in
  SQL, so the total and the rows always describe the same set.
- **Library note:** when the run scanned OS packages only, the page says so ("this run scanned OS packages only; library
  findings were not collected").
- **Empty results:** "No findings match these filters", with a clear link.

### Data access

- **Connections:** each request opens its own SQLite connection, read-only (`mode=ro` URI) in PR 1, and closes it.
  sqlite3 objects never cross threads.
- **Read queries** live in a new `kubedelos/store/queries.py` (run selection, KPIs, the fix list, the findings page), and
  `kubedelos/analytics.py` holds the pure logic over their rows: grouping, deltas and the comparable-run rule. The existing
  `Repo` stays the write path.
- **Indexes:** a migration adds the indexes these queries need, at least `scan_run(context, status, finished_at)` and
  `finding(vuln_id)`. The builder decides the exact set from query plans on a seeded DB of about 1,000 images and 100,000
  findings. Every page must render in under 300 ms on that DB.

### Look

- **CSS:** hand-written, a single stylesheet, no framework.
- **Themes:** light and dark via `prefers-color-scheme`.
- **Layout:** readable at 360 px wide, and tables scroll inside their own container.
- **Print:** the dashboard prints cleanly; the nav is hidden in print.
- **Severity colours:** Critical, High, Medium, Low and Unknown each get a colour, always paired with the word.

### Packaging

- **New core dependencies:** `fastapi`, `jinja2` and `uvicorn` (plain, without the `[standard]` extras), with bounds per
  AGENTS.md.
- **Assets:** templates and static files live under `kubedelos/web/` and are included in the wheel. A test builds the
  wheel and checks that they are there.
- **Layout:**

```
kubedelos/web/app.py         create_app(settings, *, context, token) -> FastAPI
kubedelos/web/security.py    host check, session/token, CSRF, CSP nonce, headers
kubedelos/web/routes/dashboard.py, findings.py
kubedelos/web/templates/     base.html, dashboard.html, findings.html, error.html, partials/
kubedelos/web/static/        app.css (htmx.min.js arrives in PR 2)
```

### Verification for PR 1

- Unit tests per module use FastAPI's TestClient against a temporary DB seeded through `Repo`. They cover:
  - every run-selection case (none, narrower only, pinned, foreign context, failed run)
  - the KPI deltas and the comparable-run rule
  - fix-list grouping, sorting, caps and stated totals
  - findings filters, sort and paging totals
  - each security control: Host, token and cookie, CSRF, CSP nonce uniqueness, the http(s)-only link rule, and no token
    in the access log
- **Real check:** scan a kind cluster with `kubedelos scan`, open `kubedelos ui`, and check the dashboard and findings in
  a browser. Take screenshots in light and dark at desktop and phone width.
- `/security-review` runs on the branch before the PR is marked ready.

## PRs 2–4, in outline (each gets its own plan)

**PR 2: Scans.**
- **Page:** a `/scans` page with a start-scan form covering namespaces, namespace selector, label selector, image
  exclusions and package types. Each field defaults to the saved settings and is labelled "saved: X".
- **One run at a time, in-process.** A second start is refused with a message; the queue is Phase 3 (#24). The scan runs
  `run_scan` on a background thread with a cancel event, and `trigger` is `ui`.
- **Live progress:** HTMX polls a fragment every 2 seconds. It shows the phase (Trivy DB, inventory, scanning, saving), N
  of M images, scanned/cached/failed counts from the first image, the image in flight, and an ETA once 5 images are done.
  `Progress` gains the phase and the cached count.
- **Cancel:** the readout switches to "stopping after the current image" at once. When the run finishes, the page links to
  its results.
- **Run history:** newest first, paged (not silently capped). Each row shows status, scope, scan level, images, failures
  and duration. Failed and cancelled runs aren't linked as results.
- **Stale `running` rows:** these are closed as `failed` only when no live process owns them. A CLI scan running in
  another terminal must never be marked failed. The builder picks the mechanism, for example a PID and start time on the
  run row.
- **Write routes** use CSRF, and the DB connection becomes read-write for them only.

**PR 3: Accepted risk and namespaces.**
- **New `exception` table** (migration).
  - **Required fields:** CVE, reason, owner (defaulting to the OS user) and expiry (defaulting to +90 days, never in the past).
  - **Optional narrowing:** namespace, image and package; blank means anywhere.
  - **Matching:** done on read. Expired or revoked entries stop matching at once, and revoke takes effect immediately.
  - **The register:** shows each entry's state, days left and "covers N findings in run X". An entry that covers nothing
    is flagged.
  - **The rule:** an acceptance takes a finding off the work lists (dashboard fix list, findings page) and leaves every
    count alone (KPIs, bricks, CSV). Each work list states how many accepted findings it left out and links to them.
  - **Accept…:** each findings row gets an "Accept…" link that opens the form prefilled.
- **Namespaces page:**
  - **Rows and columns:** one row per namespace, with owner and team (from the existing workload columns), the five
    severity counts, total and images.
  - **Sort and filters:** worst first by Critical then High, every column sortable, a substring filter, and "has at least
    one <severity>".
  - **Links:** each non-zero count links to the exact findings.
  - **Run rule:** the cluster-scope rule from the table above.

**PR 4: Compare, reports and settings.**
- **Compare (`/diff`):**
  - **Default pair:** the newest comparable pair.
  - **Banners:** a mismatch is named above the numbers, and a run with failed images gets a caution.
  - **Contents:** counts for new findings, fixed or gone, images added and images gone, plus tables sorted worst first.
    The tables are capped with the real total stated.
- **Reports:** a print-friendly HTML sheet of the dashboard's run (status, fix-first list, failed images) and a CSV
  download of the findings view as filtered. The CSV reuses the formula-safe writer in `output.py`.
- **Settings:** read-only. It shows every setting with its value and source (flag, environment or default), and lists no
  credentials.

## Left to the builder

- Template and partial structure, CSS details, and the exact wording of the run line and empty states, within the rules above.
- The index set (measured as described) and the query shapes.
- How the CSRF secret and session are held in memory. A restart invalidates them, and the terminal prints a new URL.

## Calls I made (please check)

- The dashboard compares with the previous comparable run instead of drawing trends; trends wait for sweeps (Phase 3).
- "Most important" means Critical and High findings with a released fix, grouped by fix. Medium and Low appear only in
  the bricks and the findings page.
- The default package view is `all`, because kubedelos scans `os,library` by default (the reference tool defaulted to OS).
- Runs older than 24 hours are marked stale. This is not configurable in Phase 2.
- The UI is fixed to the context it was started with; there's no switcher.
- Page caps: 25 rows for the dashboard lists, 20 images per expander, 100 rows per findings page. All of them state the
  real totals.
- PR 1 stores inventory coverage warnings (a new `run_warning` table), so a run that couldn't see every namespace is never
  shown as the whole cluster.
- Runs with no recorded scope never count as the cluster and are never compared.
- An image means a distinct ref, and a finding means a distinct (image, CVE, package, installed version).
- No `--allow-remote` in Phase 2. It's loopback only, with SSH port forwarding for remote use; remote access waits for
  Phase 3.
- The UI creates and migrates the database at startup, then reads it read-only per request.
