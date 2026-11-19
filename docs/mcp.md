# Ask your agent: `kubedelos mcp`

`kubedelos mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio. It lets the AI
agent you already use (Claude Code, VS Code Copilot and others) query the scan results kubedelos has stored on your
machine, so you can ask "what should I fix first?" in plain words.

- **Read-only.** It opens the local SQLite database read-only. It never writes, never starts a scan, never loads a
  kubeconfig and never reaches the cluster.
- **Local, no keys.** It makes no network calls and calls no LLM, so it needs no API key. Your own agent does the
  reasoning; the server only returns data.
- **A scan first.** There must be results to read. Run `kubedelos ui` and start a scan. Without a database every tool
  answers `no kubedelos database at <path>; run "kubedelos ui" and start a scan first`.

## Set it up

Claude Code:

```bash
claude mcp add kubedelos -- kubedelos mcp
claude mcp add kubedelos -- kubedelos mcp --context my-cluster   # default to one cluster
```

VS Code Copilot, in `.vscode/mcp.json`:

```json
{"servers": {"kubedelos": {"type": "stdio", "command": "kubedelos", "args": ["mcp"]}}}
```

If `kubedelos` is not on the PATH the client sees, use the interpreter that has it installed instead:
`python -m kubedelos mcp`.

Options:

| Option | What it does |
| --- | --- |
| `--context NAME` | Default cluster for the tools; else the one with the newest finished run. |
| `--data-dir DIR` | The directory holding the kubedelos database (also `KUBEDELOS_DATA_DIR`). |

## Tools

All tools are read-only. A tool's `cluster` argument defaults to the `--context` cluster and `run` to the newest run the
dashboard shows. `run` is the run number you see in the UI (within that cluster), not a database id. An unknown cluster
answers `unknown cluster <name>; known: ...`.

Every list is bounded: `limit` (or `per_page`) defaults to 25 and is capped at 100. A larger value is clamped, not
refused. Each list result carries `total` and `truncated` so the agent knows whether more exists.

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_clusters` | none | `clusters`, `default` |
| `run_summary` | `cluster`, `run` | `kpis`, `coverage_gaps`, `failed`, `previous_run` |
| `fix_first` | `cluster`, `run`, `view`, `limit` | `items`, `total`, `truncated`, `no_fix`, `accepted` |
| `find_vulnerability` | `vuln_id`, `cluster`, `run`, `limit` | `packages`, `images`, `workloads`, `acceptance` |
| `workload` | `namespace`, `name`, `kind`, `cluster`, `run` | `containers` with `counts`, `facts`, `top_findings` |
| `list_findings` | `cluster`, `run`, the filters below, `page`, `per_page` | `items`, `total`, `truncated`, `page` |
| `attack_surface` | `cluster`, `run`, the filters below, `limit`, `offset` | `facts_collected`, `items`, `total` |
| `compare_runs` | `cluster`, `from_run`, `to_run`, `limit` | `from`, `to`, `new`, `gone`, `images_*`, `still_open` |
| `accepted_risks` | `cluster`, `state` | `state`, `entries` |

Argument values and defaults:

- `list_findings` filters: `severity`, `namespace`, `pkg_class`, `q`, `fixable`, `accepted`. It also returns
  `accepted_left_out`.
- `attack_surface` filters: `exposure`, `privileged`, `host`, `rights`, `min_severity`. It also returns `truncated`.
- `view` (`fix_first`): `fix` (default) or `image`.
- `pkg_class` (`list_findings`): `all` (default), `os` or `library`. `fixable`: `any` (default), `yes` or `no`.
  `accepted`: `hide` (default), `only` or `all`. `severity` is a list such as `["CRITICAL", "HIGH"]`.
- `min_severity` (`attack_surface`): `CRITICAL` or `HIGH`. `offset` skips items, for the next page.
- `state` (`accepted_risks`): `active` (default) or `all`.
- `list_clusters` returns, per cluster, `name`, `last_scan`, `status`, `stale` and `newest_run`.
- `workload` and `find_vulnerability` items carry `facts`, which is `null` when none were collected.

Notes on the tools:

- `workload` lists every kind that shares the name unless `kind` is given. `find_vulnerability` for an unknown CVE
  returns empty lists, not an error.
- `list_findings` is paged (`page` from 1). Risk-accepted findings are hidden unless `accepted` is `all` or `only`.
- `compare_runs` without `from_run` compares with the previous comparable run; without `to_run` it uses the newest.
- `attack_surface` ranks workload containers by exposure (external, unknown, cluster, none, then no facts), then by
  Critical and High counts. The filters combine with AND:
  - `exposure`: any of `external`, `cluster`, `none`, `unknown`.
  - `privileged` and `host`: `host` means host namespaces, a writable `hostPath` or a `SYS_ADMIN`-class capability.
  - `rights`: any of `cluster_admin`, `reads_secrets`, `creates_workloads`, `pod_exec`, `escalates`, `wildcard`. A
    workload whose rights are undetermined (`rights_status` is not `ok`) matches a `rights` filter, because it
    might hold the right.
  - A workload without facts never matches a facts filter, and its `facts`, `host_access` and `rights_status` are
    `null`. `facts_collected` says whether the run has any facts at all.
- Each run payload carries `fact_sources`, the status of each fact source per run (or `null`), so the agent can tell
  "not collected" from "unknown".

## Prompts

Prompts are fixed instructions that tell the agent which tools to call and how to report. They never contain scan data.

| Prompt | Arguments | What it asks |
| --- | --- | --- |
| `fix_first_briefing` | `cluster` | Brief me on what to fix first: the run's health, the top fixes, where each runs |
| `attack_paths` | `workload`, `cluster` | Trace attack paths from reachable workloads, or one `namespace/name` |
| `explain_cve` | `vuln_id`, `cluster` | What the CVE allows, where it runs, whether a fix exists and is accepted |

## Example questions

- What should I fix first in my-cluster?
- Which internet-facing workloads run a Critical with a fix?
- Walk me through how an attacker who owns web/frontend could move.
- What changed since the last scan, and which new findings are fixable?
- Is CVE-2024-12345 running anywhere, and has anyone accepted the risk?
- Which workloads with a ServiceAccount that can read Secrets also have a High finding?

## What the agent can and cannot see

- Only the local database. There is no live cluster, no Secret and no registry credential in it.
- Facts as of the run. The attack-surface facts (exposure, NetworkPolicy isolation, host access, ServiceAccount rights)
  are recorded at scan time, so they can be older than the cluster. See [Attack-surface facts](attack-surface.md).
- Unknown means possibly exposed. A fact of `null` or `"unknown"` means kubedelos could not read it, never that it is
  safe. The server's instructions and prompts tell the agent so.

## Security notes

- Names, image references, CVE titles and URLs come from the cluster and the vulnerability database. They are returned
  only as JSON fields, and the server and every tool description tell the agent to treat them as data, never as
  instructions.
- The server never writes: the database is opened read-only for each call, and every tool is annotated read-only.
- It runs with your file permissions and reads the same database `kubedelos ui` writes. Anyone who can start the
  command can read your scan results; the server adds no authentication of its own.
