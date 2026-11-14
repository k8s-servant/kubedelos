# UI Restyle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle `kubedelos ui` to the approved "Look, version 2" (a Lens-style sidebar holding Grafana-style panels), add
a logo, and add the Worst images panel.

**Architecture:** Same FastAPI + Jinja2 app from PR 1. `base.html` becomes a sidebar shell, the run line becomes chips,
and the dashboard and findings templates become cards. One new read query, `worst_images`. `app.css` is rewritten. Charts
are inline SVG whose geometry comes from the route, because the CSP (`style-src 'self'`) forbids `style=` attributes.

**Tech Stack:** Python 3.12, FastAPI, Jinja2, SQLite, one hand-written CSS file, SVG.

**Spec:** `docs/superpowers/specs/2026-11-14-kubedelos-ui-design.md`, sections "Look" and "Look, version 2".

## Global Constraints

- **Only the stylesheet:** one hand-written `kubedelos/web/static/app.css`, no CSS framework, no webfont, no Node build.
- **No inline code:** no JavaScript, and no `<script>`, `<style>`, `style=` or `on*=` in any page. `tests/web/test_app.py`
  already enforces this, so every width or position goes in SVG attributes (`x`, `width`) or CSS classes.
- **Themes:** light and dark through `prefers-color-scheme`. The page must read at 360 px, tables scroll inside their own
  container, and when printed the sidebar is hidden.
- **Severity in words:** every severity colour sits next to its word ("Critical", "High", "Medium", "Low", "Unknown").
- **Dark palette** (copied verbatim from the spec):
  - surfaces: background `#1e2124`, sidebar `#25282c`, cards `#2a2e33`, accent `#7c5cff`
  - severity: Critical `#ff5c7a`, High `#ffab5c`, Medium `#f2cc4b`, Low `#5ea4ff`, Unknown `#7d8590`
  - "Fixed in" versions in green.
- **Light theme:** same accent and severity hues, darkened until the text reaches WCAG AA contrast on its card.
- **Freshness dot:** green under 24 h, amber when `is_stale(...)` is true. It never says "connected".
- **Worst images:** the top 5 by Critical + High units of the run (a finding counted once per image, as in the fix lists).
  - **Ties:** sorted by Critical, then by ref.
  - **Hidden** when the run has no Critical or High.
  - **Speed:** within the 300 ms page budget, and indexed.
- **Every PR 1 behaviour stays:** links keep `run_id`, the caution marks stay, and so do the empty states.
- **Phone width:** the sidebar becomes a top bar below 760 px.
- **Project rules:** TDD, one test file per module, Ruff at line length 120, a docstring per module, and placeholders only.
  Conventional Commits, lowercase, with no attribution lines.
- **Logo:** option C, "Radar", saved as `kubedelos/web/static/logo.svg` (its source is in
  Task 2).

## Review Focus

1. **A run with no Critical or High findings:** the Worst images panel is absent, not an empty card or a division by zero
   (Task 1, Task 3).
2. **A run whose `finished_at` is NULL** (still running or crashed) shown through `run_id`: the freshness dot and chips
   render "at an unknown time" without a 500 (Task 2).
3. **A severity with a count of 0 in the stacked bar:** no zero-width rect, and the legend still lists Critical to Low,
   with Unknown only when non-zero, exactly like the old bricks (Task 3).
4. **A long image ref or context name at 360 px:** it wraps or ellipsises inside its card and doesn't widen the page
   (Task 5, checked on screenshots).
5. **Light mode:** every severity word and the "Fixed in" green stay readable on the light card (Task 5, checked on
   screenshots).

---

### Task 1: `worst_images` query

**Files:**
- Modify: `kubedelos/store/queries.py` (after `fix_by_image`)
- Test: `tests/store/test_queries.py`, `tests/web/test_perf.py`

**Interfaces:**
- Produces:
  - `WorstImage(ref: str, critical: int, high: int)`, a frozen dataclass.
  - `worst_images(conn, run_id: int, limit: int = 5) -> list[WorstImage]`.

- [ ] **Step 1: Write the failing tests** in `tests/store/test_queries.py`, using the existing `_run`, `_add_in` and `_fx`:

```python
def test_worst_images_ranks_by_critical_plus_high(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "a", [_fx("C1", "CRITICAL"), _fx("H1", "HIGH"), _fx("H2", "HIGH", fixed=None)])
    _add_in(repo, run_id, "b", [_fx("C1", "CRITICAL"), _fx("C2", "CRITICAL"), _fx("M1", "MEDIUM")])
    _add_in(repo, run_id, "c", [_fx("H1", "HIGH"), _fx("H3", "HIGH"), _fx("H4", "HIGH")])
    _add_in(repo, run_id, "d", [_fx("L1", "LOW")])
    rows = worst_images(conn, run_id)
    assert [(r.ref, r.critical, r.high) for r in rows] == [("a", 1, 2), ("c", 0, 3), ("b", 2, 0)]


def test_worst_images_ties_break_on_critical_then_ref(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "z", [_fx("C1", "CRITICAL"), _fx("H1", "HIGH")])
    _add_in(repo, run_id, "y", [_fx("H1", "HIGH"), _fx("H2", "HIGH")])
    _add_in(repo, run_id, "x", [_fx("C1", "CRITICAL"), _fx("H2", "HIGH")])
    assert [r.ref for r in worst_images(conn, run_id)] == ["x", "z", "y"]


def test_worst_images_counts_a_finding_once_per_image_and_caps(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "multi", [_fx("C1", "CRITICAL")], platform="linux/amd64")
    _add_in(repo, run_id, "multi", [_fx("C1", "CRITICAL")], platform="linux/arm64")
    for i in range(7):
        _add_in(repo, run_id, f"img{i}", [_fx("H1", "HIGH")])
    rows = worst_images(conn, run_id)
    assert len(rows) == 5
    assert rows[0] == WorstImage("multi", 1, 0)


def test_worst_images_empty_without_critical_or_high(db):
    conn, repo = db
    run_id = _run(repo)
    _add_in(repo, run_id, "a", [_fx("M1", "MEDIUM")])
    assert worst_images(conn, run_id) == []
```

  In `tests/web/test_perf.py::test_query_plans_use_indexes`, add `"worst_images": lambda: queries.worst_images(conn, run_id)` to `calls`.

- [ ] **Step 2: Run the tests and watch them fail.**
  Run: `.venv/bin/pytest tests/store/test_queries.py -k worst_images tests/web/test_perf.py::test_query_plans_use_indexes -v`
  Expected: an ImportError, or a FAIL because `worst_images` doesn't exist.

- [ ] **Step 3: Implement `worst_images`.** Take a `units AS MATERIALIZED (_FIX_UNITS_SQL)` CTE, `GROUP BY ref`, and
  select `SUM(sev_rank = 4) AS critical, SUM(sev_rank = 3) AS high`, ordered by `critical + high DESC, critical DESC, ref`
  with `LIMIT :limit`. It uses the same unit index as `fix_by_image`, without that function's `HAVING fixable > 0`.

- [ ] **Step 4: Run the tests and watch them pass.** Use the same command as Step 2. Expected: all PASS.

- [ ] **Step 5: Commit.**
  `git commit -m "feat: add the worst images query for the ui dashboard"`

### Task 2: sidebar shell, logo, chips run line and the CSS foundation

**Files:**
- Create: `kubedelos/web/static/logo.svg`
- Modify:
  - `kubedelos/web/templates/base.html`
  - `kubedelos/web/templates/partials/run_line.html`
  - `kubedelos/web/static/app.css`
  - `tests/test_packaging.py` (add `kubedelos/web/static/logo.svg` to the expected files)
- Test: `tests/web/test_app.py`, `tests/web/test_dashboard.py`

**Interfaces:**
- Consumes: the `run`, `pinned` and `now` the templates already get. `is_stale` and `ago` are Jinja globals.
- Produces (CSS, which later tasks use):
  - **Layout:** `.shell`, `.sidebar`, `.main`, `.card`, `.chips`, `.chip`, `.chip-ok`, `.chip-bad`, `.callout`.
  - **Severity colour classes:** `.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`, `.sev-unknown`. They set
    `color` and SVG `fill` to the severity token.
  - **Custom properties:** `--critical`, `--high`, `--medium`, `--low`, `--unknown`, `--ok`, `--warn`, `--accent`.

- [ ] **Step 1: Write the failing tests.**
  - `test_app.py::test_base_page_has_nav_context_and_stylesheet` keeps its no-inline asserts. Add:
    - `'<aside class="sidebar"'`
    - `'<link rel="icon" type="image/svg+xml" href="/static/logo.svg">'`
    - `'<img class="logo" src="/static/logo.svg" alt="" width="24" height="24">'`
    - `"site-header" not in html`
  - New `test_app.py::test_logo_is_served_without_a_session`: `GET /static/logo.svg` with no cookie returns 200, its
    content type starts with `image/svg+xml`, and the body has no `<script`.
  - New `test_dashboard.py::test_sidebar_freshness_dot`:
    - a run that finished 5 minutes ago gives `class="fresh"` and "scanned 5 min ago";
    - a run 30 hours old gives `class="stale"`;
    - neither page contains the word "connected".
  - New `test_dashboard.py::test_run_chips`:
    - the chips hold `Run {id}`, the scope text, the package text and the age;
    - `chip-ok` with "8 images · 0 failed" when nothing failed;
    - `chip-bad` when an image failed.
  - New `test_dashboard.py::test_run_line_unknown_finish_time`: a run left `running`, pinned with `?run_id=`, renders
    "at an unknown time" in a chip and in the sidebar, with status 200 or the existing 404 reason. Assert whichever PR 1
    gives, and that it is not a 500.

- [ ] **Step 2: Run the tests and watch them fail.**
  Run: `.venv/bin/pytest tests/web/test_app.py tests/web/test_dashboard.py tests/test_packaging.py -v`
  Expected: the new asserts FAIL.

- [ ] **Step 3: Implement.**
  - **`logo.svg`:** the owner picked option C, "Radar": a radar sweep over four container blocks, with one block flagged
    red. Write it exactly as below; it is a standalone file with its own gradient.

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#3ec6ff"/>
    </linearGradient>
  </defs>
  <circle cx="32" cy="32" r="27" fill="none" stroke="url(#g)" stroke-width="4"/>
  <g fill="url(#g)" opacity=".4">
    <rect x="19" y="19" width="11" height="11" rx="2"/><rect x="34" y="19" width="11" height="11" rx="2"/>
    <rect x="19" y="34" width="11" height="11" rx="2"/>
  </g>
  <rect x="34" y="34" width="11" height="11" rx="2" fill="#ff5c7a"/>
  <path d="M32 32 32 5A27 27 0 0 1 57.7 23.6Z" fill="url(#g)" opacity=".55"/>
  <circle cx="32" cy="32" r="3" fill="#fff"/>
</svg>
```
  - **`base.html`:** `<div class="shell"><aside class="sidebar">…</aside><div class="main">…</div></div>`. The sidebar
    holds, in order:
    1. The wordmark: the logo `<img>` plus "kubedelos", linking to `/`.
    2. The context card: the label "Context", the context name, and a dot reading
       `<span class="fresh|stale">scanned {{ ago }}</span>`. Without a run it reads "no scans yet".
    3. `<nav aria-label="Main">` with the existing `nav` items, `aria-current="page"` kept.
    The `run_line` block moves into `.main`, above `content`.
  - **`run_line.html`:** a `<div class="page-head">` holding the page `<h1>` (from a new `page_title` block) and a
    `<ul class="chips">`. The pinned and stale badges become chips. The gaps `<details>` becomes a `.callout`.
  - **`app.css`:** rewrite it.
    - The dark tokens from Global Constraints, and light tokens under `@media (prefers-color-scheme: light)`.
    - The background glow via `background-image` on `body`.
    - Cards with a 12 px radius and hairline borders.
    - Below 760 px the sidebar becomes a top bar: wordmark and context on one row, nav as a row below.
    - `@media print` hides `.sidebar`.
    Keep the PR 1 selectors for the dashboard and findings until Tasks 3 and 4 replace them.
  - **Page titles:** `dashboard.html` and `findings.html` move their `<h1>` into the `page_title` block. Without a run
    the title still shows; it just has no chips.

- [ ] **Step 4: Run the full suite.**
  Run: `.venv/bin/pytest -q`
  Expected: everything passes. Any PR 1 test that asserted the old header markup is updated to the new markup, never
  deleted, and the commit message says which ones.

- [ ] **Step 5: Commit.**
  `git commit -m "feat: give the ui a sidebar shell, a logo and a chip run line"`

### Task 3: dashboard cards, severity bar and the Worst images panel

**Files:**
- Modify:
  - `kubedelos/web/routes/dashboard.py`
  - `kubedelos/web/templates/dashboard.html`
  - `kubedelos/web/static/app.css`
- Test: `tests/web/test_dashboard.py`

**Interfaces:**
- Consumes: `worst_images` and `WorstImage` (Task 1), and the CSS classes from Task 2.
- Produces:
  - `SeverityShare(severity: str, count: int, x: float, width: float, href: str)`, which replaces `Brick`.
  - `WorstBar(ref: str, short: str, critical: int, high: int, width: float, href: str)`.
  - The context keys `shares` and `worst`. `bricks` is gone.

- [ ] **Step 1: Write the failing tests** in `tests/web/test_dashboard.py`.
  - **Rename** `test_bricks_link_and_unknown_hidden_when_zero` to `test_severity_legend_links_and_unknown_hidden_when_zero`.
    The asserts stay the same: the links `/findings?run_id={id}&amp;severity=…`, and UNKNOWN only when non-zero. Add that
    each legend entry holds the full severity word.
  - **New `test_severity_bar_geometry`:** with 1 Critical and 3 Low, the SVG has exactly two rects:
    - Critical with `x="0"` and `width="25.0"`;
    - Low with `x="25.0"` and `width="75.0"`;
    - no rect for High or Medium.
    The SVG has `role="img"` and an `aria-label` naming every severity and count.
  - **New `test_worst_images_panel`:**
    - image "a" has 1 Critical and 2 High; image "b" has 1 High;
    - the panel title "Worst images" appears;
    - "a" comes before "b", with "1 Critical · 2 High";
    - the bar widths are `width="100.0"` and `width="33.3"`;
    - each row links to `/findings?run_id={id}&amp;q=<ref>`, URL-encoded.
  - **New `test_worst_images_hidden_without_critical_or_high`:** a run with only Medium findings has no "Worst images".
  - **New `test_fix_row_installed_shows_first_plus_n`:** a fix group with installed versions `1.0`, `1.1` and `1.2`
    shows `1.0` and `+2`, and puts `1.0, 1.1, 1.2` in a `title`.

- [ ] **Step 2: Run the tests and watch them fail.**
  Run: `.venv/bin/pytest tests/web/test_dashboard.py -v`
  Expected: the new and renamed tests FAIL.

- [ ] **Step 3: Implement.**
  - **Route:** build `shares` from `current.by_severity`.
    - Skip zero counts.
    - `width = round(100 * count / total, 1)`, and `x` is the running sum of the widths before it.
    - Build `worst` from `worst_images(conn, run.id)`: `width = round(100 * (critical + high) / top, 1)`, where `top` is
      the first row's total.
    - `short` reuses `output.short_image` (see `routes/findings.py` for how the findings page calls it).
    - The query runs inside the existing `with open_db(...)` block.
  - **Template:**
    - **Tiles:** the label, the number (with the `sev-critical` or `sev-high` class on those tiles), the suffix and the
      change line, keeping the caution marks.
    - **All findings tile:** carries `<svg class="sevbar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img"
      aria-label="…">` with one `<rect class="sev-…">` per share, then the legend `<ul>` of links.
    - **Fix first:** a `.card` with the by fix / by image switch in its header. Severity shows as a dot plus the word.
      Installed shows the first version plus `+N`.
    - **Worst images:** a `.card` with `<svg viewBox="0 0 100 6" preserveAspectRatio="none">` bars.
    - **Layout:** a two-column `.row` (2fr / 1fr) that stacks below 960 px.
    - **Failed images:** a `.card.card-error` with a red left edge.
  - **CSS:** the styles for these parts.

- [ ] **Step 4: Run the full suite.**
  Run: `.venv/bin/pytest -q`
  Expected: everything passes.

- [ ] **Step 5: Commit.**
  `git commit -m "feat: restyle the ui dashboard and add the worst images panel"`

### Task 4: findings page in cards

**Files:**
- Modify:
  - `kubedelos/web/templates/findings.html`
  - `kubedelos/web/static/app.css`
- Test: `tests/web/test_findings.py`

**Interfaces:**
- Consumes: the Task 2 CSS classes. The route doesn't change.

- [ ] **Step 1: Write the failing test.**
  New `test_findings.py::test_filters_are_one_card_with_severity_pills`:
  - the form has `class="card filters"`;
  - each severity is still `<input type="checkbox" name="severity" value="…">`, inside a
    `<label class="pill sev-…">` that holds the full word;
  - the Apply button has `class="btn"`;
  - the table sits in a `.card` holding a `.table-wrap`;
  - the current page link in the pager has `aria-current="page"`.

- [ ] **Step 2: Run the test and watch it fail.**
  Run: `.venv/bin/pytest tests/web/test_findings.py -v`
  Expected: the new test FAILS.

- [ ] **Step 3: Implement.**
  - **Filters:** keep the PR 1 fields and their order.
  - **Pills:** the checkbox is visually hidden but still focusable. Use `:has(input:checked)` and `:focus-within` on the
    pill, so it works without JavaScript.
  - **Pager:** the current page is an accent pill.

- [ ] **Step 4: Run the full suite.**
  Run: `.venv/bin/pytest -q`
  Expected: everything passes.

- [ ] **Step 5: Commit.**
  `git commit -m "feat: restyle the ui findings page filters, table and pager"`

### Task 5: real-data check, screenshots and docs

**Files:**
- Modify:
  - `CHANGELOG.md`: change the PR 1 `kubedelos ui` line to mention the sidebar layout, the logo and the Worst images
    panel. Don't add a separate line.
  - `README.md`: only if its "Local web UI" text describes the old header.

- [ ] **Step 1: Scan a local kind cluster and start the UI.**
  Run `kubedelos scan --context kind-lab`, then `kubedelos ui --context kind-lab --no-browser`.

- [ ] **Step 2: Take screenshots** of the dashboard, `?by=image` and the findings page with a filter applied, at 1280 px
  and 360 px, in dark and in light (emulate with Chrome DevTools or `--force-prefers-color-scheme`). Save them in the
  session scratchpad, never in the repo, because they show real cluster data.
  Check each one against Review Focus 4 and 5, plus:
  - no horizontal page scroll at 360 px;
  - severity words readable in both themes;
  - the logo sharp at 24 px and in the browser tab.

- [ ] **Step 3: Run the checks.**
  Run: `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pre-commit run --all-files`
  Expected: all clean.

- [ ] **Step 4: Commit.**
  `git commit -m "docs: describe the restyled ui"`
