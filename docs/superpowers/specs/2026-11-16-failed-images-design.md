# Failed images: design

Agreed in chat on 2026-11-16 after a real scan in which one image failed with "failed to extract the archive: unexpected
EOF".

## Intent

When an image fails to scan, you want to know which one and why without opening the database. Today the cause appears
only in the dashboard's Failed images panel, and only once the run has finished. The panel caps the list at 25 and
shows only the dashboard's run, which is the newest whole-cluster run. A failure caused by the network shouldn't need a
second scan at all.

- **Goals:**
  - see failures while the scan runs;
  - see every failure of any run;
  - retry a passing network failure once by itself.
- **Non-goals:**
  - retrying a timeout (it would double a slow scan);
  - retrying auth or not-found errors (a retry can't fix them);
  - retrying a whole run;
  - a retry setting.
- **Anti-goals:**
  - a retry that hides a real failure;
  - a credential in any error text shown. Error text is redacted as today, by `error_cause`.

## Approaches considered

1. **The readout reads failures from the database (chosen).** Each result is written as its image finishes, so the run's
   error rows are there while it runs. `Progress` gains `run_id`, and the readout queries the failures it needs.
2. **Failures travel in memory in `Progress`.** This needs no query, but the list would need a cap, and a page reload
   after the scan would lose it.

## Design

- **`Progress.run_id`** is set from the moment the run row exists.
- **The readout** (`/scans/progress`) lists the run's newest 5 failures, newest first: the short ref, the error kind and
  the cause. When there are more, it says how many and links to the failures page. The link appears as soon as a run ID
  exists, even while scanning.
- **Failures page (`GET /scans/{run_id}/failed`):**
  - **Rows:** every failed (image, platform) row of the run, ordered by ref and then platform, 100 per page. Each row has
    the full ref, platform, error kind, the namespaces the image runs in, and the cause. The full redacted error is in a
    `<details>` element.
  - **Login hints:** when any failure is `auth`, the registry login hints appear above the list, as on the dashboard.
  - **Runs shown:** any run of the shown context, whatever its status, including a running or cancelled run. A run of
    another context gets 404.
- **Links to it:** the Scans history's "failed" count, when it isn't zero; the dashboard's Failed images panel ("see all
  N"); and the readout.
- **Retry once.** In `scan_many`, an image whose error is a passing one gets one more scan after 2 seconds, unless the
  scan was cancelled.
  - **Passing errors**, matched case-insensitively on stderr: `unexpected eof`, `connection reset`, `broken pipe`,
    `i/o timeout`, `tls handshake timeout`, `502 bad gateway`, `503 service unavailable`, `504 gateway timeout`,
    `too many requests`.
  - **Result:** the second attempt's result is the one recorded. When both fail, the stored error starts "failed twice:".
  - **Not retried:** `timeout` (Trivy's own deadline), `auth` and `not_found`.
- **Docs:** the README says where failures show and that a passing error is retried once.

## Left to the builder

- Copy, CSS and the template split.
- The order of the passing-error patterns and the error kinds they come with.
