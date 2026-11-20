# Risk score

Severity says how bad a vulnerability is in general. The risk score says how bad it is where it runs: a Critical CVE in
an image that nothing can reach matters less than a High one that attackers already exploit, in a pod on the internet
that runs privileged with a cluster-admin token. kubedelos gives every finding a score from 0 to 100, built from five
factors, and orders the fix-first lists and the findings page's `risk` sort by it.

The score is kubedelos's own ranking, not a CVSS score or a vendor severity. Every point comes from one of the factors
below. The dashboard shows them under each score (open the score to see them), and the MCP tools return them, so you
can tell why a finding ranks where it does.

## The factors

The score is the sum of the five factors, capped at 100. The highest possible sum is exactly 100.

### Severity

| Severity | Points |
| -------- | ------ |
| Critical | 40 |
| High | 30 |
| Medium | 15 |
| Low | 5 |
| Unknown | 3 |

### Known exploitation

From the [threat feeds](#the-threat-feeds). Only the first line that matches counts:

| The CVE is | Points |
| ---------- | ------ |
| in CISA KEV (known exploited) | 25 |
| EPSS 0.5 or more | 15 |
| EPSS 0.1 or more | 8 |
| EPSS below 0.1, or not in EPSS | 0 |

Only CVE ids are looked up. A GHSA or another id scores 0 here.

### Exposure

How far the workload is reachable, from the [attack-surface facts](attack-surface.md#exposure):

| Exposure | Points |
| -------- | ------ |
| `external`: a hostPort, a NodePort or non-internal LoadBalancer Service, `externalIPs`, or an Ingress or HTTPRoute | 15 |
| `unknown`: the Services (or the routes that might make it external) could not be listed | 10 |
| `cluster`: a Service selects the pod, but nothing proves reach from outside the cluster | 5 |
| `cluster`, with a NetworkPolicy that isolates its ingress | 2 |
| `none`: no Service selects the pod | 0 |

### Host access

| The pod | Points |
| ------- | ------ |
| can reach the node: privileged, host PID, network or IPC, a writable hostPath, or an added capability in `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH`, `BPF` or `ALL` | 10 |
| has none of those, and runs as root or may run as root (unknown) | 3 |
| has none of those and does not run as root | 0 |

Root adds nothing on top of host access: the two never stack, so this factor is at most 10.

### API rights

What the workload's ServiceAccount may do, from the [RBAC facts](attack-surface.md#rights):

| Rights | Points |
| ------ | ------ |
| the token is not mounted (`automountServiceAccountToken: false`) | 0 |
| `cluster_admin`, `escalates`, or reads Secrets cluster-wide | 10 |
| `pod_exec`, reads Secrets in some namespaces, `creates_workloads` or `wildcard` | 5 |
| rights `unknown`, rights not read (`off`), or `partial` with none of the above | 5 |
| rights `ok` (fully read) with none of the above | 0 |

A token whose mounting is unknown counts as mounted.

### Unknown is never safe

A workload with no facts at all (the scan ran with `KUBEDELOS_ATTACK_SURFACE=false`, or its rows were written before
facts existed) counts as unknown on every workload factor: exposure 10, host 3, rights 5, so 18 points. An image with no
workload row gets the same. Unknown always scores at least as high as known-harmless, because the absence of evidence
is not evidence of safety.

## How findings are combined

- **An image** with several workloads takes the points of its riskiest workload row in the run.
- **A fix group** on the dashboard (one CVE, package and fixed version) scores as its riskiest unit, the highest score
  of any image it clears. Its sample images are listed riskiest first, and the factors shown are that top unit's.
- **An image** on the dashboard's by-image list (`?by=image`) scores as its riskiest Critical or High unit, fixable or
  not.
- Ties keep the order the list had before the score: severity, then the number of images and namespaces for a fix,
  and Critical, then High for an image.

## Where it shows

- The dashboard's fix-first list, by fix or by image, is ordered by score and shows each score; open one to see its
  factors.
- The findings page shows a **Risk** column and sorts by it with `sort=risk`. The column that marks accepted findings
  is called **Status**.
- The print report (`/report`) shows the score of each fix.
- The CSV (`/findings.csv`) has a `risk` column. It is the last column, so a script that reads columns by position
  keeps working, and it is empty when the score is hidden.
- The MCP tools `fix_first` and `find_vulnerability` return the score, its factors and the CVE's KEV and EPSS data. See
  [Ask your agent](mcp.md).

## When the score is hidden

A run with no attack-surface facts, while no threat feed has ever been downloaded, has nothing to score but severity.
The score would only restate it, so the UI leaves the score out for that run, says so in a note, and the `risk` sort
falls back to the severity order. The MCP tools report it as `risk.shown: false`.

When only one half is there, the score is shown with a note that says what is missing:

- no facts for the run: exposure, host access and API rights count as unknown (18 points, as above);
- no feed copy yet: known exploitation adds nothing.

## The threat feeds

Known exploitation comes from two public feeds:

| Feed | URL |
| ---- | --- |
| CISA Known Exploited Vulnerabilities | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| EPSS (FIRST, served by Empirical Security) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` |

The EPSS URL redirects to the day's dated file (`epss_scores-YYYY-MM-DD.csv.gz`, about 3 MB compressed), and kubedelos
follows the redirect.

### When they are fetched

Each feed is downloaded at most once every 24 hours. kubedelos checks before each scan (from the UI, the `serve` queue
or a scheduled sweep) and when `kubedelos ui` starts, on a background thread so the UI does not wait for it. A page
request never downloads anything. The Settings page shows when each feed was last fetched.

### What the requests carry

Each request is a plain HTTPS `GET` of the fixed URL above, with no query string, no body, no cookie and no
credentials. The only header kubedelos sets is `User-Agent: kubedelos/<version>`. Nothing about the cluster, its
images or its findings is sent: the whole feed is downloaded and every lookup happens in the local database. These are
the only outbound calls kubedelos makes besides Trivy's and the registries'.

### When a download fails

A feed never fails a scan or the UI. A download that is not a usable copy of the feed is refused whole, and the last
stored copy is kept:

- an HTTP error, a connect timeout (10 s) or a read timeout (30 s);
- a body over 32 MiB, or an EPSS file that decompresses to more than 64 MiB;
- broken gzip or JSON, an unexpected EPSS header, no valid row, or more than 2,000,000 rows;
- a copy with fewer than half the rows of the stored one, while the stored copy is younger than 7 days. After that the
  smaller copy is taken as the feed's real new size, so a feed that really shrank is not refused for ever.

Each failure is logged once per feed as `threat feed <name> not updated: <reason>`, and the next scan tries again.

A scan checks the feeds before it lists the cluster, and a cancel is not checked during the download. A slow feed can
therefore delay a cancel that arrives at that point by up to the timeouts above.

### The switch

`KUBEDELOS_THREAT_FEEDS=false` turns the downloads off. A copy already stored is still used as it is; with no copy,
known exploitation adds nothing.

The Helm chart sets `KUBEDELOS_THREAT_FEEDS=false`, because many clusters give pods no egress to `cisa.gov` and
`empiricalsecurity.com`. See [Running kubedelos in a cluster](in-cluster.md#threat-feeds) to turn them on.

## Storage

The feeds live in two tables of the local database: `threat_intel` (one row per CVE the feeds name, about 410,000 in
November 2026) and `threat_feed` (per feed, when it was fetched, its version and its row count). Schema migration 13
adds them, plus a `risk_points` column on each workload row: the workload's exposure, host and rights points, computed
when the scan stores the row. The migration fills it for the rows already stored, from their facts.

## Design choices

- **Unknown severity is 3 points, not 5,** so a higher severity always scores strictly higher (Low is 5).
- **Host access is the one definition** the MCP server's `host_access` uses too. It is wider than a list of host
  namespaces and privilege alone (a writable hostPath, the listed capabilities), so it can overstate the risk but never
  understate it.
- **Unknown root counts as root (+3)**, as an unknown token counts as mounted.
- **No facts is 18 points**: exposure unknown (10), host unknown (3) and rights unknown (5).
- **Rights `partial` with no flag set is unknown (+5)**, because a partial read is not a full view. Only `ok` with no
  flag set is 0.
- **Feed freshness is one row per feed** in `threat_feed`, not a timestamp on each of the 400,000 intel rows.
- **The workload points are stored** (`risk_points`), so a change to the exposure, host or rights weights comes with a
  migration that recomputes that column. The SQL and the Python score are generated from the same constants in
  `kubedelos/risk.py`, so they cannot drift apart.
- **Feeds refresh before a scan and when `ui` starts**, never during a page request.
- **The CSV `risk` column is last**, so existing scripts keep their column positions.
- **The findings page shows a Risk column while the score is shown**: a sort by a value the page does not show would
  confuse.
- **`find_vulnerability` orders workloads by score while the score is shown**, then by exposure as before.
