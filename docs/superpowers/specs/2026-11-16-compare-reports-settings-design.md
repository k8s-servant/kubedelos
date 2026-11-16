# Compare, reports and settings: design

This implements "PR 4" of `2026-11-14-kubedelos-ui-design.md`, updated for what has shipped since:
- per-cluster contexts and run numbers;
- accepted risk;
- removal of `output.py`, the CLI's CSV writer, which the spec meant to reuse.

It ships as three PRs in this order: compare, reports, settings.

## Intent

- **Compare:** answers "what changed since last time?" after a rescan or an upgrade: what is new, what went away, and
  which images changed.
- **Reports:** produce something to hand to someone who doesn't run kubedelos, either a printed page or a spreadsheet.
- **Settings:** answers "why did the scan do that?" by showing every setting in effect and where its value came from.

- **Non-goals:**
  - comparing two clusters (dev against prod);
  - trend charts (Phase 3 sweeps);
  - scheduled or mailed reports (Phase 4);
  - PDF;
  - editing settings.
- **Anti-goals:**
  - a tag bump that reads as "every finding fixed and every finding new";
  - a CSV cell that a spreadsheet runs as a formula;
  - a credential on any page or in any file.

## 1. Compare (`/diff`)

- **The pair:**
  - **Default:** the newest comparable pair of the shown context. That is the dashboard's run and its previous
    comparable run, using the existing rule (same scope and scan level, status ok or partial).
  - **Choosing:** `?from=<run_id>&to=<run_id>` picks any two result runs of the shown context. Two pickers list that
    context's result runs by number.
  - **Other clusters:** a run of another context gets 404.
- **Banners above the numbers:**
  - **Different scope or scan level:** named, for example "these runs scanned different namespaces", because
    differences may come from what was scanned, not from what changed.
  - **Failed images:** a caution names the side, because a failed image's findings look "gone".
  - **Coverage gaps:** a run with gaps also gets a caution.
- **What is compared (my call):** images are matched by **repository**, not by ref.
  - **Images:** one of four states:
    - **added**, when the repository is only in the newer run;
    - **gone**, when it is only in the older run;
    - **changed**, when it's in both but with a different tag or digest;
    - **unchanged**.
  - **Findings:** keyed by (repository, CVE, package).
    - **New:** in the newer run only.
    - **Fixed or gone:** in the older run only. A finding of a gone image counts here and is labelled "image gone".
    - **Still open:** in both, counted only.
  - **Why:** a tag bump that keeps a CVE neither "fixes" it nor makes it "new"; it stays open. A repository that runs
    under two tags at once is compared as the union of its tags.
- **Contents:**
  - count tiles for new findings, fixed or gone, images added, gone and changed;
  - tables, sorted worst first by severity and then by the number of images, each capped at 100 rows with the real
    total stated.
  - **Rows and links:** each finding row links to the findings page of the run it is in, filtered to its CVE.
- **Acceptances:** they don't apply here. Compare counts, and counts never change for an acceptance.
- **Where it's linked:** the nav (after Namespaces), the dashboard's "change since the previous comparable run" tiles,
  and the Scans history (a "compare" link on each result run that has a previous comparable run).

## 2. Reports

- **Print sheet (`/report`):** one page of the dashboard's run (or of `?run_id=`), styled for printing with a print
  stylesheet; Save as PDF comes from the browser.
  - **Header:** the cluster, run number, date, scope and scan level, and status.
  - **Body:** the KPI numbers, severity counts, the fix-first list (up to 50 rows, with the total), the accepted
    findings left out of it ("N accepted, not listed"), and failed images with their causes.
  - **Links:** from the dashboard ("Print report") and each Scans history row.
- **CSV (`/findings.csv`):** the findings view as filtered, using the same query parameters as `/findings` and every
  row, not one page. Its link sits next to the findings pager.
  - **Columns:** severity, CVE, package, installed, fixed in, class, image, namespaces, accepted, title and URL.
  - **Formula-safe:** a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`.
  - **Memory:** the response is streamed from SQL in pages, so 100,000 rows never sit in memory.
  - **File name:** `kubedelos-<context>-run<N>.csv`, with unsafe characters replaced.

## 3. Settings (`/settings`)

- **Read-only.** It shows every `Settings` field with its value and its source:
  - **flag**, for `--context` or `--kubeconfig` given to `kubedelos ui`;
  - **environment**, for the `KUBEDELOS_*` variable that set it;
  - **default** otherwise.
- **It also shows:**
  - the database file, cache and data directories;
  - the pinned Trivy version, and whether a custom Trivy (`KUBEDELOS_TRIVY_PATH`) is in use;
  - the log level.
- **Credentials:** none are listed. `Settings` holds none today, and registry credentials live in Docker's own
  config, which this page never reads. A test makes sure no field whose name suggests a secret (token, password, key,
  secret) is ever added to the page.
- **Where it's linked:** the nav, at the end.

## Left to the builder

- Template structure, CSS (including the print stylesheet) and copy.
- The SQL shape of the diff, which has to stay under 300 ms on two runs of 100,000 findings, measured as before.
