# Namespaces page

**Goal:** a `/namespaces` page: one row per namespace in the shown run, worst first, with links to the exact findings.

**Spec:** the "PR 3: Accepted risk and namespaces" outline in `docs/superpowers/specs/2026-11-14-kubedelos-ui-design.md`.
The user split PR 3 on 2026-11-15, so this PR covers the namespaces page and accepted risk follows on its own. The page
follows the multi-context UI (`2026-11-15-multi-context-ui-design.md`): it shows the shown context, and its links keep
that context.

## Decisions

- **Which run:** the dashboard's rule. That is the newest whole-cluster result run of the shown context, or the run that
  `?run_id=` pins. Without a whole-cluster run, the page says so and links to the newest run's findings, as the dashboard
  does.
- **Counting:** a namespace counts a finding unit (a distinct image, CVE, package and installed version) when the unit's
  image runs in that namespace. That is the same rule as the findings page's namespace filter, so each count equals the
  findings its link opens. An image in two namespaces counts in both.
  - Images counts distinct refs, including images that failed or have no findings.
  - Owner and team come from the namespace's workloads.
- **Columns:** namespace, owner, team, Critical, High, Medium, Low, Unknown, total and images.
  - Every column is sortable through `?sort=`, with `&dir=`.
  - The default order is worst first: Critical, then High, then total, all descending, then the name.
- **Filters:**
  - `q`: a case-insensitive substring of the namespace, owner or team.
  - `has`: at least one finding of that severity.
  - No paging. Every namespace is listed, and the page says how many match.
- **Links:**
  - Each non-zero severity count opens `/findings?run_id=…&namespace=…&severity=…`.
  - The total opens `/findings?run_id=…&namespace=…`.
  - Every link carries the shown context.
- **Nav:** Dashboard, Findings, Namespaces, Scans.
- **Speed:** the page is added to the 300 ms perf test on the 100,000-finding database.

## Tasks

1. `queries.namespace_counts(conn, run_id) -> list[NamespaceRow]`, with tests in `tests/store/test_queries.py`. It must
   pass the query-plan test, which rejects full scans.
2. The route `kubedelos/web/routes/namespaces.py`, the template `namespaces.html` and the nav entry, with tests in
   `tests/web/test_namespaces.py`. Sorting and filtering happen in Python, since a run has at most a few hundred
   namespaces.
3. The README, the CHANGELOG and the perf test.
