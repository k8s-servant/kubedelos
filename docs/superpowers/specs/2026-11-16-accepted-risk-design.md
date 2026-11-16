# Accepted risk: design

This design implements the accepted-risk half of "PR 3" in `2026-11-14-kubedelos-ui-design.md`. The namespaces half
shipped in #37. It adds one decision from chat (2026-11-15, option A): an acceptance belongs to one cluster unless it is
marked as applying to all clusters.

## Intent

Some findings can't be fixed now, or don't matter where the image runs. Today they stay at the top of the fix list
forever, and a real new Critical gets lost among them. An acceptance records the decision (who made it, why, and until
when) and takes the finding off the work lists until it expires. It never hides a finding from the numbers.

- **Goals:**
  - accept a CVE in a few clicks from the findings row;
  - keep the work lists clean of accepted findings;
  - keep a register that shows what each acceptance still covers, and what has run out.
- **Non-goals:**
  - editing an entry (revoke it and accept again);
  - approval workflows;
  - accepting by severity or by wildcard;
  - write actions in in-cluster mode (Phase 3 gates them behind an identity header);
  - reports and CSV (PR 4 and Phase 4 read the same matching).
- **Anti-goals:**
  - an acceptance that changes a KPI, a brick, a namespace count or a total;
  - an acceptance that hides a finding in a namespace or a cluster it wasn't made for;
  - an expired acceptance that keeps hiding findings.

## Approaches considered

1. **Match on read (chosen, and fixed by the spec).** Each work-list query joins the active entries, so an expiry or a
   revoke takes effect on the next page load, and old runs are judged by today's register.
2. **Stamp findings at scan time.** The reads are cheaper, but revoke and expiry would need a rewrite of stored rows,
   and every run made before an acceptance would ignore it.

## Design

- **Table `acceptance`** (migration 7):
  - `id`, `vuln_id` (required);
  - `context`: NULL means all clusters;
  - `namespace`, `repo` and `pkg_name`: NULL means anywhere;
  - `reason` and `owner` (required);
  - `expires_at` (a date), `created_at`, `revoked_at`.
  - Index on `vuln_id`.
  - Contents are never credentials. They're free text shown escaped.
- **What an entry matches.** An entry matches a finding unit when it is active and every condition it sets holds:
  - **Active:** not revoked, and `expires_at` is on or after today (UTC).
  - **Cluster:** its context is the run's context, or it applies to all clusters.
  - **CVE:** `vuln_id` is equal.
  - **Package:** `pkg_name` is equal, when the entry sets one.
  - **Image:** `repo` is equal, when the entry sets one. My call: the image is the repository, not the tag or digest,
    so an acceptance survives a rebuild or a tag bump.
- **Namespaces.** A unit is accepted only when **every** namespace its image runs in is covered by a matching entry. An
  entry with no namespace covers all of them. An image with no workload is covered only by an entry with no namespace.
  My call: if a finding is accepted in `web` and the same image also runs in `api`, it stays on the work list, because
  it still matters in `api`. This follows the second anti-goal.
- **Work lists.** Accepted units leave the dashboard's fix list (both views), its no-fix line, and the findings page's
  default view. Everything that counts stays as it is: KPIs, bricks, the namespaces page and totals.
  - Each work list says "N accepted findings not shown" and links to `/findings?accepted=only`.
  - The findings page gains a filter `accepted=hide|only|all`, with `hide` as the default. In `only` and `all`, each
    accepted row shows an "accepted" badge that links to its register entry.
- **Register (`/accepted`, in the nav after Namespaces).**
  - It lists the shown context's entries and the all-cluster entries: active first by days left, then expired, then
    revoked.
  - Each row shows the CVE, scope (cluster or "all clusters", namespace, image, package), reason, owner and expiry with
    days left.
  - Each row also shows "covers N findings in run X", where X is the dashboard's run. An active entry that covers
    nothing is flagged "covers nothing".
  - Revoke is a POST button with CSRF. It sets `revoked_at`, and the row stays visible.
- **The Accept… form.**
  - `GET /accepted/new` is prefilled from the query string: CVE, package, image and namespace come from the findings
    row. The namespace is filled only when the findings view is filtered to one.
  - `POST /accepted` creates the entry and redirects to the register.
  - **Validation:** a CVE is required. The reason is required, at most 500 characters. The owner defaults to the OS user
    (`getpass.getuser()`). The expiry defaults to today + 90 days, can't be in the past and can be at most 365 days ahead
    (my call). A cluster can only be the shown context or "all clusters".
  - Writes use `open_db_rw` and the existing CSRF guard, like `POST /scans`.
- **Performance.** The perf test seeds 50 active entries and the pages stay under 300 ms. With no entries, the queries
  cost what they cost today.

## Left to the builder

- The SQL shape of the matching and its indexes.
- Template structure, CSS and exact copy, which follow the existing tone.
