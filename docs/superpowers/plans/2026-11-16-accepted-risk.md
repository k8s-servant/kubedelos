# Accepted risk implementation plan

**Goal:** record accepted findings and take them off the work lists. Counts don't change.

**Spec:** `docs/superpowers/specs/2026-11-16-accepted-risk-design.md`

**Architecture:** a new store module `kubedelos/store/accepted.py` owns the `acceptance` table's reads and writes and
the SQL fragment that turns a run's active entries into the set of accepted unit keys. The fix-list and findings
queries in `queries.py` join that set. A new route module `kubedelos/web/routes/accepted.py` serves the register, the
form, create and revoke.

## Global constraints

- Credentials never touch disk or logs. Acceptance text is user input: escape it, never put it in logs.
- Writes use `open_db_rw` and the CSRF guard. GET routes never write.
- Every UI page stays under 300 ms on 100,000 findings, and `test_query_plans_use_indexes` stays green.
- One test file per module, TDD, Ruff at 120 columns, and a docstring on every module.

## Tasks

1. **Store (`kubedelos/store/accepted.py`, `tests/store/test_accepted.py`). Migration 7.**
   - `add(conn, *, vuln_id, reason, owner, expires, context, namespace, repo, pkg_name, now) -> int`.
   - `revoke(conn, id, now) -> bool`.
   - `register(conn, context, run_id, today) -> list[Entry]`: state, days left, covers.
   - `ACCEPTED_CTES`: `acc_active`, `acc_cand`, `acc_ns` and `accepted`, keyed by `:run` and `:today`. The context
     comes from the run row.
   - Tests:
     - every match dimension;
     - the every-namespace rule;
     - an image with no workload;
     - expired and revoked entries;
     - a context-only entry next to an all-clusters entry.
2. **Work lists (`queries.py`).**
   - `fix_by_fix` and `fix_by_image` drop accepted units, both in the rows and in the no-fix line, and in the samples.
     `FixList.accepted` counts the Critical/High accepted units.
   - `FindingFilter.accepted: Literal["hide", "only", "all"] = "hide"`. Rows carry `accepted`, and `findings_page`
     returns the number left out.
   - The queries take `today: date | None` (default: today in UTC).
   - Tests go in `tests/store/test_queries.py`. The plan test covers the queries with entries present.
3. **UI.**
   - The register at `/accepted` (nav after Namespaces), with a `cve` filter.
   - `GET /accepted/new`, `POST /accepted` and `POST /accepted/{id}/revoke`.
   - The dashboard and findings show "N accepted findings not shown". Findings rows get an Accept… link and an
     accepted badge, and the filter gets an accepted select.
   - Tests go in `tests/web/test_accepted.py`, plus additions to the findings and dashboard tests. The perf test seeds
     50 entries.
4. **Docs.** A README section and a CHANGELOG line.
