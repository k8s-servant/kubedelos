# Reports page (design)

## Why

The run report (`/report`) and the findings CSV (`/findings.csv`) work, but they are reached only from a link on the
dashboard's Fix first card, the Scans history and the findings pager. There is no place in the sidebar to go to when
the job is "produce a report". The Reports page is that place: pick a run, set what goes in, open or download.

## Approaches

- **A page of forms over the existing reports (chosen).** Nothing new to keep in step: the forms send the same query
  parameters the report and the CSV already take.
- **Saved reports, a list of generated files.** Rejected for now: it needs storage and cleanup, and a run's report can
  always be built again from the run.

## Behaviour

- **Where:** `GET /reports`, a "Reports" item in the sidebar after Compare. It follows the shown context like every
  page.
- **Run report card:** a run picker (the context's result runs, newest first, the newest selected) and "Open report",
  a GET form to `/report` with `run_id`.
- **Findings CSV card:** a run picker, severity checkboxes (Critical and High ticked), namespace (a text field that
  suggests the newest run's namespaces), fix, package class and accepted, as on the Findings page; "Download CSV" is a
  GET form to `/findings.csv`, so the file matches the Findings page with the same filters.
- **No runs yet:** a notice pointing to the Scans page.
- The existing links (dashboard, Scans history, findings pager) stay.

## Builder's calls

- The namespace is a text field with a datalist rather than a select: the list comes from the newest run, and another
  picked run may have other namespaces.
- A compare report (a printable Compare) is a possible follow-up, not part of this page.
