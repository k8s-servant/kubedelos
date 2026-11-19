# Attack-surface facts

Every scan records, for each workload container, a few facts about how exposed it is: what its pod spec lets it do on
the node, how far it can be reached, whether a NetworkPolicy isolates it, and what its ServiceAccount may do through
RBAC. They are stored next to the vulnerability findings, as versioned JSON on the workload row
(`workload.facts`), so a finding can later be weighed by the workload it sits in.

The facts are read-only observations of objects kubedelos has listed. Nothing in the cluster is changed, and **no Secret
is read**: `secret_refs` are the Secret names a pod spec refers to, never their contents.

## What is recorded

| Fact | What it says | Where it comes from | List calls it needs |
| --- | --- | --- | --- |
| `pod` | Privileged, privilege escalation, root user, read-only root filesystem, added capabilities, host network/PID/IPC, `hostPath` volumes (with read-only), ServiceAccount, token automount, `secret_refs` | The pod spec (already listed for the scan) and the ServiceAccount's `automountServiceAccountToken` | `serviceaccounts` per namespace, only for the automount default |
| `exposure` | How far the workload is reachable: `external`, `cluster`, `none` or `unknown`, with the Services, external IPs and hosts behind it | Services whose selector matches the pod, the Ingresses and Gateway API HTTPRoutes that route to them | `services`, `ingresses` and `httproutes` (`gateway.networking.k8s.io`), each per namespace |
| `network` | Whether NetworkPolicies isolate ingress and egress, and which policies select the pod | `networking.k8s.io/v1` NetworkPolicies | `networkpolicies` per namespace |
| `rights` | What the ServiceAccount may do through RBAC (flags below) and the bindings that grant it | Roles, ClusterRoles and their bindings | `roles` and `rolebindings` cluster-wide (falling back to one list per scanned namespace), `clusterroles` and `clusterrolebindings` |

All lists are read-only (`list`). kubedelos lists the namespaces the scan covers, so the namespaced calls run once per
scanned namespace.

### Pod

Taken from the pod spec of the container itself. A field the spec leaves out is recorded as `null` where the answer
is unknown (`runs_as_root`, `automount_token`), and as the riskier default where Kubernetes would allow it
(`allow_privilege_escalation` is true unless the spec sets it false). When the pods of one workload disagree, the
riskier value of each fact wins.

### Exposure

Levels, from most to least exposed: `external` > `cluster` > `none`, and `unknown` when the Services could not be
listed.

- `external`: a matching Service is a NodePort or a LoadBalancer that is not internal, or has `externalIPs`, or an
  Ingress or HTTPRoute routes to it.
- `cluster`: a Service selects the pod but nothing proves reach from outside the cluster.
- `none`: no Service selects the pod (a route needs a Service).
- `unknown`: Services could not be listed. A matched Service is also `unknown` when no signal proves external reach and
  Ingresses or HTTPRoutes could not be listed, because an unread one might have made it external.

Notes on the precision:

- A missing HTTPRoute CRD (Gateway API not installed) is harmless; it counts as no routes.
- HTTPRoutes are read from all scanned namespaces, since a route may point at a Service elsewhere. A cross-namespace
  `backendRef` counts without a ReferenceGrant check. That over-reports on purpose. Routes in namespaces outside the
  scan are not seen.
- A LoadBalancer Service is internal when the provider's annotation says so: `azure-load-balancer-internal: "true"`,
  `aws-load-balancer-internal: "true"` or `aws-load-balancer-scheme: internal`, `networking.gke.io/load-balancer-type:
  internal`, or the legacy `cloud.google.com/load-balancer-type: internal`. Where a provider has both a current and a
  legacy key, the current one decides alone. An AWS NLB with no scheme annotation counts as public, which over-reports.
  GKE's `spec.loadBalancerClass` for internal load balancers is not recognised yet.

### Network

`ingress_isolated` and `egress_isolated` are true when at least one NetworkPolicy selects the pod for that direction
and none of the selecting policies allows everyone in (or out). `null` means the policies could not be listed.

- Only core `networking.k8s.io/v1` policies are read. CNI-specific policies (Cilium, Calico, Antrea CRDs) are not.
- A policy with an allow-all rule does not isolate: an empty rule, an empty `from` or `to`, `0.0.0.0/0`, or an empty
  `namespaceSelector` with no pod selector. The policy's name is still listed.
- A policy that lists a type but has no rules for it is deny-all for that direction.

### Rights

`rights` is the reduction of the RBAC bindings that name the pod's ServiceAccount:

| Flag | Set when a rule grants |
| --- | --- |
| `cluster_admin` | the `cluster-admin` ClusterRole through a ClusterRoleBinding, or `*` on every verb, resource and group |
| `reads_secrets`, `reads_secrets_scope` | `get`, `list`, `watch` or `*` on `secrets` (scope: `cluster`, or the namespaces) |
| `creates_workloads` | `create` on pods, deployments, statefulsets, daemonsets, replicasets, jobs or cronjobs |
| `pod_exec` | `create` or `get` on `pods/exec`, `pods/attach`, `pods/portforward` or `nodes/proxy`, or `patch`/`update` on `pods/ephemeralcontainers` |
| `escalates` | `escalate`, `bind` or `impersonate`; `create`, `update` or `patch` on roles, clusterroles, rolebindings or clusterrolebindings; `create` on `serviceaccounts/token` |
| `wildcard` | `*` as a verb or a resource |
| `bindings` | the bindings that matched, as `ClusterRoleBinding/<name>` or `RoleBinding/<ns>/<name>` |

A binding names the ServiceAccount through the ServiceAccount subject itself, the username
`system:serviceaccount:<ns>:<sa>`, or the groups `system:serviceaccounts`, `system:serviceaccounts:<ns>` and
`system:authenticated`. `resourceNames` still count: a grant limited to one name is still a grant. Verbs, resources
and API groups match case-sensitively, as Kubernetes does, and a `*` verb is treated as covering `escalate`, `bind`
and `impersonate`, which overstates rather than understates.

## What "unknown" and "partial" mean

kubedelos never reports a fact as safe when it could not look.

- `exposure.level` `unknown`, and `ingress_isolated` or `egress_isolated` `null`: the lists they need were forbidden
  or failed. The scan still finishes.
- `rights.status` is `ok` when every Role and binding was listed, `partial` when only some were (or a bound Role was not
  listed), `unknown` when none were, and `off` when the facts are switched off. In a partial view the rights found are
  real but may be incomplete, and finding none means unknown, not none.

Each run also records the status of every fact source in `scan_run.fact_sources`, a JSON object with the keys
`pod_security`, `services`, `ingresses`, `httproutes`, `network_policies`, `service_accounts` and `rbac`. A source is
`ok`, `absent` (the kind is not installed), `partial`, `forbidden`, `error`, or `off`. A run that could not read a source adds a
warning, and the run line in the UI notes the incomplete facts.

## The switch

`KUBEDELOS_ATTACK_SURFACE` turns the facts on or off; it is on by default. When off, no extra list call is made: the
`pod` facts are still recorded from the pod spec, `exposure` is `unknown`, `network` is `null`, `rights.status` is `off`,
and every fact source other than `pod_security` is `off`.

The Helm chart sets it to `"false"` for now: it grants no RBAC for these lists yet, which is a follow-up. To use the
facts in a cluster before then, grant the list calls above to the kubedelos ServiceAccount and set the variable.

## The JSON (v1)

`workload.facts` holds one `WorkloadFacts` document. `v` is the schema version; a reader should check it.

```json
{
  "v": 1,
  "pod": {
    "privileged": false,
    "allow_privilege_escalation": true,
    "runs_as_root": null,
    "read_only_root_fs": false,
    "added_capabilities": [],
    "host_network": false,
    "host_pid": false,
    "host_ipc": false,
    "host_path_volumes": [{"path": "/var/log", "read_only": true}],
    "service_account": "default",
    "automount_token": true,
    "secret_refs": ["my-app-config"]
  },
  "exposure": {
    "level": "external",
    "services": [{"name": "web", "type": "NodePort", "internal_lb": false}],
    "external_ips": [],
    "hosts": ["app.example.com"]
  },
  "network": {
    "ingress_isolated": true,
    "egress_isolated": false,
    "ingress_policies": ["deny-ingress"],
    "egress_policies": []
  },
  "rights": {
    "status": "ok",
    "cluster_admin": false,
    "reads_secrets": false,
    "reads_secrets_scope": null,
    "creates_workloads": false,
    "pod_exec": false,
    "escalates": false,
    "wildcard": false,
    "bindings": ["RoleBinding/my-namespace/cleanup-view"]
  }
}
```

`runs_as_root`, `automount_token`, `ingress_isolated` and `egress_isolated` are true, false or `null` (unknown).
`reads_secrets_scope` is `"cluster"`, a list of namespaces, or `null`.
