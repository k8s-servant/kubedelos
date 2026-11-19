# Attack-surface facts, `kubedelos mcp` and the risk score: design

This design implements #63. It records the decisions from chat (2026-11-19):

- **Users:** platform engineers who want to know what to fix first, or who want to simulate an attack.
- **Reasoning only:** kubedelos never calls a model and never stores an API key. The engineer's own agent (Claude Code,
  Copilot and the like) does the reasoning.
- **Shape (option 2 of #63):** an MCP server, plus a deterministic risk score that takes exposure into account.
- **Local first.** `kubedelos mcp` runs on the engineer's machine and reads the local database. The in-cluster case
  follows later.
- **Order (approach A):** facts first, then the MCP server, then the score.

## Intent

Today the fix-first list ranks by severity, then by how many images and namespaces one fix covers (`fix_by_fix` in
`store/queries.py`). It cannot tell two Criticals apart:

- one in an internet-facing pod that runs privileged with a ServiceAccount that can read every Secret;
- one in a batch job that has no Service and no API rights.

Engineers want the first one at the top. They also want to ask "if this pod were compromised, where could an attacker
go next?" kubedelos already sees most of the facts that answer this. It just doesn't keep them.

## Goals

- Record each workload's attack-surface facts with every scan:
  - pod security;
  - network exposure;
  - NetworkPolicy coverage;
  - the ServiceAccount's API rights.
  Facts that can't be read are recorded as unknown.
- `kubedelos mcp`: a read-only MCP server over stdio. Through it, the engineer's agent can:
  - explain the fix-first list;
  - say where a CVE runs;
  - describe a workload's attack surface;
  - reason about attack paths.
- A deterministic risk score. It orders fix-first in the UI, in reports and over MCP, and each score lists the factors
  that make it up.

## Non-goals

- An in-cluster MCP endpoint (HTTP behind the sign-in proxy). The chart's opt-in RBAC for collecting facts in-cluster is
  also out. Both are follow-up issues.
- Full network reachability. kubedelos records which policies select a pod; it does not evaluate their rules hop by hop.
  CNI-specific policies (Cilium, Calico, Antrea CRDs) are not read.
- Cloud IAM, meaning what a workload identity can do in Azure, AWS or GCP.
- Vulnerabilities in nodes or the control plane.
- Write tools over MCP: no scans, no acceptances, no settings.
- Changing the CVE severity itself. The score sits next to severity; it does not replace it.

## Anti-goals (a failure even if it works)

- **Unknown reads as safe.** A workload whose exposure or RBAC couldn't be read must never rank below the same workload
  with known, harmless facts.
- **The score moves a count.** KPIs, severity bricks, the namespaces page and totals stay exactly as they are. Only the
  order of the work lists changes.
- **kubedelos calls an LLM, stores a key, or sends cluster data anywhere.** The only new outbound traffic is the
  threat-feed download (KEV and EPSS), which sends nothing about the cluster.
- **The MCP server changes state.** That includes the database, the cluster and the cache.
- **A Secret's contents are read** to work out facts. Names that appear in a pod spec are fine; they are already in the
  pod spec kubedelos lists.
- **The local UI gets slower.** Every page still renders in under 300 ms on 1,000 images and 100,000 findings, with the
  facts and the score in place.

## Constraints

- **AGENTS.md:**
  - read-only cluster access;
  - no Secret reads beyond the opted-in pull secrets;
  - TDD, one test file per module;
  - every module starts with a docstring;
  - placeholder names in tests and docs;
  - dependency bounds `>=X.Y,<X+1`.
- **Partial access is normal.** Fact collection must not fail a scan. A 403 or 404 on a new list becomes an unknown fact
  and an inventory warning with `coverage=False`, because image coverage is unaffected.
- **Old runs have no facts.** Every reader, the score included, handles a run collected before migration 12.
- **`kubedelos serve` keeps working unchanged.** Its ServiceAccount has no rights on the new resources. The chart sets
  fact collection off, so `serve` makes no extra calls and logs no new warnings.

## Approaches

1. **Facts, then MCP, then the score (chosen).** Each step ships something usable. With MCP in place, engineers can
   reason over real facts before the score's weights are fixed, so step 3 can set the weights from what turned out to
   matter.
2. **The score first, MCP last.** The UI improves sooner, but the weights get set before anyone has used the facts, and
   attack simulation waits until the end.
3. **MCP only; the agent ranks.** This is the smallest build. But rankings change with the model and the run, and the UI
   and reports gain nothing. It drops the deterministic half of #63.

## The design

### Step 1: attack-surface facts

**What gets collected.** Facts are collected per workload container, the same unit as a `workload` row:

- **Pod security**, from the pod spec kubedelos already lists. The container's `securityContext` is merged over the
  pod's. Fields:
  - `privileged`;
  - `allow_privilege_escalation`;
  - `runs_as_root`: true, false or unknown. True when the effective `runAsUser` is 0. Unknown when neither
    `runAsNonRoot` nor `runAsUser` says otherwise, because the image's own USER decides and kubedelos can't see it;
  - `read_only_root_fs`;
  - `added_capabilities` (list);
  - `host_network`, `host_pid`, `host_ipc`;
  - `host_path_volumes`: the paths, and whether each is mounted read-only;
  - `service_account`;
  - `automount_token`: the effective value, true, false or unknown.
    - The pod's `automountServiceAccountToken` wins when it is set.
    - Otherwise the ServiceAccount's own setting applies. That comes from listing ServiceAccounts per namespace, which
      returns no Secret contents.
    - When neither sets it, the Kubernetes default applies: true.
    - Unknown only when the pod doesn't set it and ServiceAccounts could not be listed;
  - `secret_refs`: names of the Secrets mounted as volumes, used by `envFrom` or used in `env` (names only).
- **Exposure**, from listing Services, Ingresses and Gateway API HTTPRoutes per namespace:
  - The Services whose selector matches the pod's labels, with their type: ClusterIP, NodePort or LoadBalancer.
  - `externalIPs`.
  - Whether a LoadBalancer carries one of the known internal-LB annotations for Azure, AWS or GCP.
  - The Ingress hosts and HTTPRoute hostnames that send traffic to those Services.
  - These combine into one `exposure` level:
    - `external`: a NodePort, a non-internal LoadBalancer, externalIPs, or the backend of an Ingress or HTTPRoute;
    - `cluster`: a ClusterIP or internal-LB Service only;
    - `none`: no Service selects the pod;
    - `unknown`: Services could not be listed. HTTPRoutes alone being absent (CRD not installed) is not unknown.
- **NetworkPolicy**, listed per namespace:
  - `ingress_policies` and `egress_policies`: the names of the policies whose `podSelector` selects the pod and whose
    `policyTypes` include that direction;
  - `ingress_isolated` and `egress_isolated`: whether each list is non-empty;
  - unknown when NetworkPolicies could not be listed.
- **ServiceAccount rights**, from Roles, ClusterRoles, RoleBindings and ClusterRoleBindings. Each list is called once
  per scan, cluster-wide. A binding in a namespace the scan doesn't cover can still grant a scanned workload rights.
  - A binding applies when it names the ServiceAccount, or the groups `system:serviceaccounts`,
    `system:serviceaccounts:<ns>` or `system:authenticated`.
  - The bound rules are reduced to a few flags:
    - `cluster_admin`: a binding to `cluster-admin`, or `*` verbs on `*` resources in `*` groups, cluster-wide;
    - `reads_secrets`: get, list or watch on secrets. Scope `cluster` comes through a ClusterRoleBinding. Otherwise
      the scope is the list of namespaces whose RoleBindings grant it, which may include other namespaces than the
      pod's own;
    - `creates_workloads`: create on pods or on any workload controller;
    - `pod_exec`: create on `pods/exec` or `pods/attach`;
    - `escalates`: `escalate`, `bind` or `impersonate`, or create or update on roles or bindings;
    - `wildcard`: any `*` in verbs or resources.
  - The names of the matching bindings are also kept.
  - **Partial access** is common: many engineers have only namespace-scoped rights.
    - When a cluster-wide list is forbidden, kubedelos falls back to listing Roles and RoleBindings in each scanned
      namespace. Whatever it can still read, it reads.
    - The result is then marked `partial` (`fact_sources` RBAC = `partial`).
    - Flags found in a partial view count in full.
    - "No rights found" in a partial view counts as unknown, never as none, because a partial view can understate
      rights.
    - When nothing could be listed, every flag is unknown. My call: this keeps the feature useful for namespace-scoped
      users without breaking the "unknown never reads as safe" anti-goal.

**Templates.** Workloads scaled to zero and CronJobs (the inventory's template workloads) get facts from their pod
template, the same way.

**Pods that disagree.** Two pods of one workload can differ, for example mid-rollout. Each fact then takes the riskier
value: true over false, the higher exposure level, and the union of lists. My call: the facts are about what an attacker
could reach right now.

**Storage (migration 12):**

- `workload.facts`: a JSON column, versioned (`{"v": 1, ...}`), NULL when facts were not collected;
- `scan_run.fact_sources`: JSON naming each source as `ok`, `partial`, `forbidden`, `absent` or `off`. The sources are
  pod security, services, ingresses, HTTPRoutes, NetworkPolicies, ServiceAccounts and RBAC.

No new table. My call: the facts go everywhere the workload row goes, cache hits included. The facts belong to the run's
inventory, not to the image, so a cached image result still gets fresh facts.

**Switch:** `KUBEDELOS_ATTACK_SURFACE`, on by default. The chart sets it to `false`. With it off, the new lists are not
called and `fact_sources` says `off`. Pod-security facts come free from the pod spec, so they are always recorded.

**UI in step 1:** only the run line changes. It notes the fact sources that were forbidden. The UI has no workload page
and step 1 doesn't add one. The facts become visible through MCP in step 2 and as the score's factors in step 3.

### Step 2: `kubedelos mcp`

**The command:** `kubedelos mcp [--context NAME] [--data-dir PATH]`.

- An MCP server over stdio, built on the official Python SDK (`mcp>=2.3,<3`).
- It opens the database with `connect_readonly` and never migrates, scans, reaches the cluster or writes.
- With no database it still starts, and every tool says how to create one (`kubedelos ui`, then a scan).
- `--context` sets the default cluster, and each tool can override it. Without `--context`, the default is the context
  with the newest run.

**Dependency:** a core dependency, not an extra. My call: the local case is the main one, and `pipx install kubedelos`
followed by a one-line agent config should just work. The in-cluster image grows a little and never runs it.

**Tools.** All are read-only and bounded, at most 100 rows a call with paging. They return structured content plus a
short text summary:

| Tool | Returns |
|---|---|
| `list_clusters` | each context with a run, its newest run's time, status and whether it is stale |
| `run_summary` | KPIs, coverage warnings, `fact_sources`, failed-image counts, and the previous comparable run |
| `fix_first` | the dashboard list (view `fix` or `image`), with the score and its factors once step 3 lands |
| `find_vulnerability` | for a CVE: the packages, fixed versions, images and workloads it runs in, with each workload's facts, and its acceptance |
| `list_findings` | the findings page's filters (severity, namespace, package class, text, fixable, accepted) and paging |
| `workload` | one workload: its images, finding counts by severity, top findings, and its facts |
| `attack_surface` | workloads filtered by facts (exposure level, privileged, host access, rights flags, has Critical/High), so an agent can find entry points and blast radius |
| `compare_runs` | new, fixed and still-open counts and lists between two runs, as the diff page computes them |
| `accepted_risks` | the acceptance register, active or all |

These reuse the existing `store/queries.py` functions where they exist (`fix_by_fix`, `fix_by_image`, `findings_page`,
the diff queries, `kpis`, `context_scans`). New queries go next to them.

**Prompts.** These are templates the agent fills in. They hold no model logic.

- `fix_first_briefing`: explain the top of fix-first and what fixing each item buys.
- `attack_paths`, which takes an optional workload. It starts from `external` workloads with exploitable findings and
  then follows:
  - host access;
  - the ServiceAccount's rights;
  - the names of mounted Secrets;
  - NetworkPolicy gaps.
  It says plainly which facts were unknown.
- `explain_cve`.

**Untrusted strings.** Names, CVE titles and image refs come from the cluster and the Trivy DB. Tool descriptions say
that every field is data. Strings go out as JSON fields, never folded into an instruction.

**Docs:**

- `docs/mcp.md`:
  - setup for Claude Code (`claude mcp add kubedelos -- kubedelos mcp`) and VS Code Copilot (`.vscode/mcp.json`);
  - the tool list;
  - example questions;
  - what the agent can and can't see.
- A README section and a CHANGELOG entry.

### Step 3: threat feeds and the risk score

**Feeds:**

- **CISA KEV** (JSON) and **EPSS** (daily CSV). Fetched by `ui` at most once a day, before a scan or on the page that
  needs them, into a `threat_intel` table (migration 13): `vuln_id`, `kev`, `kev_added`, `epss`, `epss_percentile`,
  `fetched_at`.
- One failed fetch keeps the last copy. With no copy at all, those factors count as unknown.
- `KUBEDELOS_THREAT_FEEDS`: on for `ui`; the chart sets it off.
- The builder confirms the current feed URLs. EPSS moved hosts in 2025.

**The score.** A pure function in `kubedelos/risk.py` builds the score for one finding in one workload. It is a sum of
named points, capped at 100. Each part is listed so the UI and MCP can show why:

| Factor | Points (starting values) |
|---|---|
| Severity | Critical 40, High 30, Medium 15, Low 5, Unknown 5 |
| Exploited | in KEV +25; else EPSS ≥ 0.5 +15, ≥ 0.1 +8, below 0.1 or unknown +0 |
| Exposure | external +15, cluster +5, none +0, **unknown +10** |
| Ingress isolation | an `ingress_isolated` pod at `cluster` exposure: the 5 points drop to +2 |
| Host access | privileged, host PID or network, a writable hostPath, or `SYS_ADMIN`/`NET_ADMIN`/`SYS_PTRACE` added +10; else `runs_as_root` true +3 |
| API rights | `cluster_admin`, `escalates` or cluster-wide `reads_secrets` +10; any other flag +5; **unknown +5**; no rights found in a full view +0; **token not mounted +0** (`automount_token` false; unknown counts as mounted) |

- A fix group's score is the highest score among the units it fixes. An image row's score is its highest unit.
- Fix-first sorts by score first, then by the current tiebreaks: severity, images, namespaces, CVE id.
- Runs without facts: those factors count as unknown, and the UI says the facts were not collected.
- **When there is nothing to add.** If a run has no facts (collection off, or an old run) and there is no feed copy,
  the score would only restate severity. Then the score column, the factor chips and the `risk` sort are hidden. The
  list keeps today's order, and a one-line note says why. This is what `serve` shows with the chart's defaults. The
  report CSV keeps a fixed schema: the `risk` column is always there, and empty in that case. My call: no inflated
  numbers that carry no information.
- The step 3 plan may change the starting values, using what step 2 showed. The properties below are fixed, and tests
  pin them.

**Properties the tests pin:**

- **Unknown never ranks below known-harmless.** Unknown exposure and unknown rights each score at least as high as
  `none` and no bindings.
- **Exploited beats not exploited.** With everything else equal, KEV scores strictly higher.
- **Exposure orders the score.** With everything else equal, `external` > `cluster` > `none`.
- **Severity decides when the exploit points are equal.** For two findings in the same workload with equal exploit
  points, the higher severity scores strictly higher. My call: across different exploit points, a High with EPSS 0.6
  may outrank a Critical with EPSS 0.01. That is the point of the exploit factor, so EPSS points are not capped below
  the severity gap.
- **Repeatable.** The same inputs always give the same score and the same factor list.

**Where the score shows:**

- The dashboard's fix-first in both views: a score column, with factor chips that expand to show where the points came
  from.
- The findings page: a `risk` sort, which stays within the 300 ms budget.
- Report HTML and CSV: a score column.
- `fix_first` and `find_vulnerability` over MCP.
- KPIs and counts do not change.

**Computing it:** on read, so a KEV addition re-ranks old runs too. This matches how acceptances work. To stay inside the
budget, the workload part of the score is built once per workload row: from the facts at write time, or with a migration
backfill for rows that have facts. The per-CVE part is a join on `threat_intel` in SQL. The builder picks the exact split
and proves it with the existing plan and perf tests.

## Delivery: three PRs, in this order

1. **Facts:**
   - the new `KubeApi` list methods;
   - fact extraction (`kubedelos/kube/facts.py`) and RBAC reduction (`kubedelos/kube/rbac.py`);
   - migration 12, the switch and the chart's `false` default;
   - the run-line note;
   - a kind e2e case with a NodePort Service, a NetworkPolicy and a RoleBinding.
2. **`kubedelos mcp`:** the command, tools, prompts and docs. Tests drive the server in-process through the SDK's
   client.
3. **Score:**
   - feeds (migration 13), `risk.py`, and the fix-first order and factors in the UI;
   - the findings sort, the report column, and the score in the MCP tools;
   - the perf test updated with facts and feeds seeded.

## Left to the builder

- Exact JSON key names inside `facts`, as long as they are versioned and documented in `docs/mcp.md`.
- How the inventory carries facts to the repo (for example a mapping keyed by `Workload` on `InventoryItem`), as long
  as `Workload` equality, and so the dedupe, is unchanged.
- The exact Azure, AWS and GCP internal-LB annotation keys. Take them from each vendor's docs.
- Tool argument names and paging style, as long as tools stay bounded and read-only.
- The UI layout of the factor chips, within the existing style.
- How the score's work is split between write time and read time, within the perf budget.
