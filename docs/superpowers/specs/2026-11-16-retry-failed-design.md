# Retry failed images (design)

## Why

A scan of a large cluster from a laptop pulls every layer from the registry, so big images (.NET, WebSphere) can run
past the per-image time limit (`KUBEDELOS_SCAN_TIMEOUT_S`, 600 s), and a network blip can fail an image twice. Running
the whole scan again costs an hour to fix twenty images. A retry rescans only a run's failed images, with a longer
limit and fewer parallel images, and puts the results into the same run.

## Approaches

- **In place, in the same run (chosen).** Each failed image's row is replaced by its new result, and the run goes
  from `partial` to `ok` when nothing fails anymore. The dashboard, compare and report stay right without a run that
  covers only twenty images.
- **A new run of the failed images.** Rejected: the dashboard and compare would treat it as a whole run of a tiny
  cluster.

## Behaviour

- **Where:** a "Retry failed images" form on a run's failures page, and a "retry" link beside the failed count in
  the Scans history. Fields: time limit per image (default 3× the setting, capped at 3,600 s; 60–3,600) and parallel
  images (default 2; 1–32).
- **Which runs:** only the newest result run of a context, once finished as `partial` with failed images, so earlier
  runs (and compares against them) never change. The run's Trivy must match this kubedelos's (the pinned version, or
  `custom` for a user-supplied Trivy), so a run's results come from one scanner.
- **What:** every failed image, including `not_found` (cheap: it fails again in seconds). Same platform, same package
  types as the run, same refs; workloads are kept. The result cache is used and filled as in a scan.
- **No cluster access:** the refs and workloads come from the database.
- **Job:** the same single job slot as scans ("a scan is already running"), the same progress readout titled
  "Retrying failed images of run N", and Cancel. A cancelled retry keeps what finished.
- **Record:** the run's status and failed count are recomputed (`finished_at` is kept), and a note is stored with
  the run: `retried N failed images at HH:MM UTC: X scanned, Y still failing`. The failures page shows the notes.

## Builder's calls

- The retry does not take the run lock: the run's status never goes back to `running`, so the stale-run sweep has
  nothing to close, and the UI's single job slot keeps retries and scans apart.
- The note is a `run_warning` row with `coverage = 0`, recognised by its `retried ` prefix.
