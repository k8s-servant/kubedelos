# One cluster, one history: identify a cluster by its API server, not by its kube-context

Status: approved by the maintainer on 2026-11-23 (issue #92).

## Why

Two kubeconfig contexts often point at the same cluster with different credentials: an AKS user login and its
`--admin` login, or a personal and a break-glass identity. kubedelos stores every run under the context's name, so the
UI shows such a cluster twice. A scan through one context never appears under the other, which reads as "not scanned".
The maintainer wants one cluster with one shared history, whichever context scanned it.

## Goals

- Every context that points at the same API server shows the same runs, the same "last scanned" time, the same run
  numbers and the same accepted risks.
- Each run still records which context scanned it, so a narrower scan through a restricted login is visible as such.
- Existing databases keep their history: runs of contexts that are in today's kubeconfig join their cluster's history.

## Non-goals

- Recognising one cluster behind two different API server URLs (an AKS private endpoint and its public FQDN, say).
  They stay two clusters. A manual override can come later if it is needed.
- Changing `kubedelos serve`: it already names its one cluster with `clusterName`, and that stays its key.
- Redesigning the context switcher. It still lists contexts, because a scan runs through a context.

## Anti-goals

- Loading credentials, running login plugins or calling the cluster to work out the identity. Reading the kubeconfig
  file as data, as `list_contexts` does today, is the only allowed source.
- Losing or silently merging history that can't be matched: a context that is no longer in the kubeconfig keeps its
  own history under its own name.

## Approaches considered

1. **Record the cluster key next to the context (chosen).** Each run stores the cluster key (the API server URL) and
   keeps the context name it was scanned through. History, numbering, comparison, retention and accepted risks key on
   the cluster key. Keeps provenance and needs no new switcher.
2. **Store runs under the cluster key instead of the context.** Less code, but loses which context made a run, and the
   UI needs a new name to show for a cluster.
3. **Group contexts only when reading.** No migration, but two contexts would both have a run #1, an accepted risk
   scoped to one context would miss the other, and every query would need the grouping. Rejected as fragile.

## Design

**The key.** For a laptop scan the cluster key is the `server` of the kubeconfig cluster entry that the context
names, normalised: scheme and host lower-cased, a default port (`:443` for https) dropped, a trailing `/` dropped.
After it come `#sni=<tls-server-name>` when the entry sets `tls-server-name`, and `#ca=<fingerprint>` when its CA can
be read: the first 12 hex digits of the SHA-256 of the DER of the first certificate in `certificate-authority-data`,
else in the `certificate-authority` file (a relative path resolved against the kubeconfig that defines the entry, as
kubectl does). For example `https://127.0.0.1:6443#sni=api.example.com#ca=1a2b3c4d5e6f`. The fingerprint is taken
over the DER, so the same CA inline or as a file, with other line breaks, gives the same key; a CA that cannot be read
or parsed leaves the part out. The server alone would merge distinct clusters behind one URL (SSH tunnels to
`https://127.0.0.1:6443`, k3s and Rancher Desktop defaults, access proxies that pick the cluster by TLS server name)
on the first `kubedelos ui` start; the SNI and CA parts were the maintainer's decision after the final branch review.
The CA is public cluster data, not a credential. It is read from the same parsed kubeconfig as `list_contexts`, with no
credentials loaded, no login plugin run and no call to the cluster. When a context's cluster entry is missing or has
no `server` (a broken entry), the key falls back to the context name. For `kubedelos serve` the key is `clusterName`,
as today; the in-cluster fallback keeps its existing name.

**Storage.** A migration adds `scan_run.cluster` (the key) and keeps `scan_run.context` as the context the run went
through. Run numbers, the unique indexes on numbers, retention's grouping, `previous_comparable`, `newest_run` and the
other per-cluster queries move from `context` to `cluster`. `acceptance` gains a `cluster` column the same way (an
all-clusters entry stays NULL) and keeps `context` as the context shown when the entry was made, for display. Under
`serve` a run's context is `clusterName`, as today, so nothing changes there.

**Backfill.** The migration sets `cluster = context` for every existing row, so nothing moves on its own. On start,
`kubedelos ui` maps each context in the current kubeconfig to its key and rewrites the rows whose `cluster` equals that
context's name to the key, then renumbers each merged cluster's runs by id. It runs inside one transaction, is
idempotent, and logs one line per merged context. Contexts no longer in the kubeconfig keep their name as their key.

**UI.** The switcher keeps listing contexts. A context's history, run numbers and "last scanned" come from its
cluster key, so two contexts of one cluster show the same values. The run line and the Scans history say which
context a run went through when it differs from the context being viewed ("via aks-prod-admin").

**MCP.** `list_clusters` returns one entry per cluster key, named by the context of its newest run, with the other
contexts seen for it. The `cluster` argument accepts a context name or a key and resolves through the runs' context
column, so the MCP server still needs no kubeconfig.

## Left to the builder

- The exact normalisation function and its edge cases (IPv6 hosts, explicit `:443`), covered by tests, and the CA
  fingerprint's edge cases (no CA, an unreadable file, a bundle).
- Whether the renumbering on merge happens in SQL or Python, as long as numbers stay unique and ordered by id.
- The wording of the "via" note and where the Scans page shows it.
- Tests first, one test file per module, as AGENTS.md asks; a test that two contexts with one server share runs, and one
  that a context missing from the kubeconfig keeps its history.
