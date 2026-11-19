# Attack-Surface Facts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every scan records each workload container's attack-surface facts (pod security, exposure, NetworkPolicy
coverage, ServiceAccount API rights), or "unknown" where they couldn't be read, so `kubedelos mcp` (PR 2) and the risk
score (PR 3) have something to work from.

**Architecture:**

- Pure extractors in `kubedelos/kube/facts.py` (pod security, exposure, NetworkPolicy, merging) and
  `kubedelos/kube/rbac.py` (bindings reduced to flags) turn Kubernetes objects into pydantic `WorkloadFacts`.
- `inventory.collect_inventory` makes the extra list calls when `KUBEDELOS_ATTACK_SURFACE` is on. It attaches facts to
  each `InventoryItem` keyed by `Workload` and returns the run's `fact_sources`.
- The repo writes the facts as JSON on each `workload` row (migration 12) and the sources on `scan_run`.

**Tech Stack:** Python 3.12+, kubernetes client 37, pydantic 2, SQLite, Jinja, Helm.

**Spec:** `docs/superpowers/specs/2026-11-19-attack-surface-mcp-risk-design.md`, "Step 1: attack-surface facts" and
Delivery item 1. Issue #63.

## Global Constraints

- Read-only cluster access. Only `list` calls are new, and **no Secret is read**. Secret names come from the pod spec
  only.
- Fact collection never fails a scan. Any `ApiException` (or urllib3 `HTTPError`) on a new list becomes unknown facts
  and a warning with `coverage=False`.
- `Workload` equality, and so the inventory dedupe, is unchanged. Facts live beside it (`InventoryItem.facts`), never on
  it.
- `facts` JSON is versioned: `{"v": 1, ...}`. NULL means not collected (old runs).
- A cached image result still gets fresh facts. Facts come from the inventory item, never from the image result or the
  cache.
- `KUBEDELOS_ATTACK_SURFACE` defaults to on. The chart sets it to `"false"`. When it is off, none of the new list calls
  are made and those sources are `off`. Pod-security facts are always recorded.
- `fact_sources` keys: `pod_security`, `services`, `ingresses`, `httproutes`, `network_policies`, `service_accounts`,
  `rbac`.
- `fact_sources` values: `ok`, `partial`, `forbidden`, `absent`, `off`, `error`.
  - Ruling: `error` was added for a non-403 failure such as a 500 or a timeout, so it isn't reported as forbidden.
  - `httproutes` answering 404 (CRD not installed) is `absent`, with no warning.
- AGENTS.md conventions:
  - TDD, one test file per module;
  - every module starts with a docstring;
  - ruff line length 120;
  - placeholders (`example.com`, `my-cluster`) in tests and docs;
  - Conventional Commits with lowercase subjects, no attribution lines;
  - the `## Unreleased` CHANGELOG entry.
- Every UI page still renders in under 300 ms on 1,000 images and 100,000 findings. `tests/web/test_perf.py` must stay
  green.

## Review Focus

1. **A Service with no selector, or of type ExternalName,** must match no pods. It must not match every pod. Test in
   Task 4.
2. **NetworkPolicy `podSelector: {}`** selects every pod in its namespace. `matchExpressions` with `In`, `NotIn`,
   `Exists` and `DoesNotExist` are honoured. A policy without `policyTypes` is Ingress, plus Egress when it has `egress`
   rules. Test in Task 4.
3. **One image in two namespaces** with different exposure: each workload keeps its own facts, with no bleed between
   them. Test in Task 6.
4. **A cache hit** still stores the run's facts on its workload rows. Test in Task 6.
5. **`serve` with the chart's default** (`attack_surface=False`) makes no new list calls and adds no warnings. Test in
   Task 6, by asserting that `FakeKubeApi` saw no calls to the new methods.

---

### Task 1: Facts models, migration 12 and persistence

**Files:**
- Modify: `kubedelos/models.py` (new fact models; `InventoryItem.facts`)
- Modify: `kubedelos/store/db.py` (append migration 12)
- Modify: `kubedelos/store/repo.py` (`add_result` writes facts; new `set_fact_sources`)
- Modify: `kubedelos/store/queries.py` (`Run.fact_sources`, filled in `_build`)
- Test: `tests/test_models.py`, `tests/store/test_repo.py`, `tests/store/test_queries.py`

**Interfaces:**
- Produces (all in `kubedelos/models.py`, all frozen pydantic models):
  - `Tri = bool | None` (None means unknown)
  - `HostPath(path: str, read_only: bool)`
  - `PodSecurity`:
    - `privileged: bool`, `allow_privilege_escalation: bool`, `runs_as_root: Tri`, `read_only_root_fs: bool`;
    - `added_capabilities: tuple[str, ...] = ()`;
    - `host_network: bool`, `host_pid: bool`, `host_ipc: bool`;
    - `host_path_volumes: tuple[HostPath, ...] = ()`;
    - `service_account: str`, `automount_token: Tri`;
    - `secret_refs: tuple[str, ...] = ()`.
  - `ExposedService(name: str, type: str, internal_lb: bool = False)`
  - `Exposure`:
    - `level: Literal["external", "cluster", "none", "unknown"]`;
    - `services: tuple[ExposedService, ...] = ()`, `external_ips: tuple[str, ...] = ()`, `hosts: tuple[str, ...] = ()`.
  - `Network`:
    - `ingress_isolated: Tri`, `egress_isolated: Tri`;
    - `ingress_policies: tuple[str, ...] = ()`, `egress_policies: tuple[str, ...] = ()`.
  - `Rights`:
    - `status: Literal["ok", "partial", "unknown", "off"]`;
    - `cluster_admin: bool = False`, `reads_secrets: bool = False`;
    - `reads_secrets_scope: Literal["cluster"] | tuple[str, ...] | None = None`;
    - `creates_workloads: bool = False`, `pod_exec: bool = False`, `escalates: bool = False`, `wildcard: bool = False`;
    - `bindings: tuple[str, ...] = ()`: `"ClusterRoleBinding/<name>"` or `"RoleBinding/<ns>/<name>"`.
  - `WorkloadFacts(v: Literal[1] = 1, pod: PodSecurity, exposure: Exposure, network: Network, rights: Rights)`
  - `InventoryItem.facts: dict[Workload, WorkloadFacts] = {}`
  - `FactSources = dict[str, str]` (a type alias)
- Produces (repo and queries):
  - `Repo.add_result` writes `item.facts.get(w)` as `model_dump_json()` into `workload.facts`, or NULL;
  - `Repo.set_fact_sources(run_id: int, sources: FactSources) -> None`;
  - `queries.Run.fact_sources: dict | None = None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_models.py
def test_workload_facts_round_trip_and_version():
    facts = WorkloadFacts(pod=PodSecurity(privileged=True, allow_privilege_escalation=True, runs_as_root=None,
                          read_only_root_fs=False, host_network=False, host_pid=False, host_ipc=False,
                          service_account="default", automount_token=True),
                          exposure=Exposure(level="unknown"), network=Network(ingress_isolated=None, egress_isolated=None),
                          rights=Rights(status="off"))
    data = json.loads(facts.model_dump_json())
    assert data["v"] == 1
    assert WorkloadFacts.model_validate_json(facts.model_dump_json()) == facts

def test_inventory_item_facts_do_not_change_workload_equality():
    w = Workload(namespace="web", kind="Deployment", name="web", container="app")
    assert w == Workload(namespace="web", kind="Deployment", name="web", container="app")
    assert hash(w) == hash(Workload(namespace="web", kind="Deployment", name="web", container="app"))

# tests/store/test_repo.py
def test_add_result_stores_facts_per_workload(repo, conn): ...
    # item with two workloads, facts for only the first:
    # SELECT facts FROM workload ORDER BY id -> [json with "v": 1, None]

def test_set_fact_sources_is_read_back_on_the_run(repo, conn): ...
    # set_fact_sources(run_id, {"services": "ok", "rbac": "partial"}); queries.get_run(...).fact_sources == that dict

def test_old_run_has_no_fact_sources(repo, conn): ...  # Run.fact_sources is None
```

- [ ] **Step 2: Run them; expect them to fail**

Run: `.venv/bin/pytest tests/test_models.py tests/store/test_repo.py tests/store/test_queries.py -q`
Expected: FAIL (ImportError on `WorkloadFacts`; missing column `facts`).

- [ ] **Step 3: Implement**

Migration 12 goes at the end of `MIGRATIONS`, with a comment in the style of the others:

```sql
ALTER TABLE workload ADD COLUMN facts TEXT;
ALTER TABLE scan_run ADD COLUMN fact_sources TEXT;
```

The comment says these are attack-surface facts per workload row, as versioned JSON (NULL when not collected), and each
fact source's status per run. They hold names only, never Secret contents.

`_build` parses `fact_sources` with `json.loads` when it is set. `failed_items` needs no change: `replace_result` leaves
the workload rows alone, so a retry keeps their facts. Add a one-line comment saying so at `replace_result`.

- [ ] **Step 4: Run the tests and the whole suite**

Run: `.venv/bin/pytest -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git commit -am "feat: store attack-surface facts per workload and fact sources per run (#63)"
```

### Task 2: Read-only list calls on `KubeApi`

**Files:**
- Modify: `kubedelos/kube/client.py`
- Modify: `tests/kube/fakes.py` (FakeKubeApi supports the new lists)
- Test: `tests/kube/test_client.py`

**Interfaces:**
- Produces (Protocol and `_RealKubeApi`). All take `_request_timeout=REQUEST_TIMEOUT`:
  - `list_services(ns: str) -> list`: `CoreV1Api.list_namespaced_service`
  - `list_service_accounts(ns: str) -> list`: `CoreV1Api.list_namespaced_service_account`
  - `list_ingresses(ns: str) -> list`: `NetworkingV1Api.list_namespaced_ingress`
  - `list_network_policies(ns: str) -> list`: `NetworkingV1Api.list_namespaced_network_policy`
  - `list_httproutes(ns: str) -> list[dict]`: `CustomObjectsApi.list_namespaced_custom_object("gateway.networking.k8s.io",
    "v1", ns, "httproutes")["items"]`
  - `list_roles(ns: str | None) -> list`: `list_namespaced_role(ns)`, or `list_role_for_all_namespaces()` when `ns` is
    None
  - `list_role_bindings(ns: str | None) -> list`: the same split
  - `list_cluster_roles() -> list`, `list_cluster_role_bindings() -> list`: `RbacAuthorizationV1Api`
- Produces (fakes):
  - `FakeKubeApi(..., services=, service_accounts=, ingresses=, network_policies=, httproutes=, roles=, role_bindings=,
    cluster_roles=, cluster_role_bindings=)`.
  - Dicts are keyed by namespace, or lists for the cluster-wide ones. `roles` and `role_bindings` with `ns=None` return
    every namespace's entries.
  - `forbidden_resources` gains the resource names `services`, `serviceaccounts`, `ingresses`, `networkpolicies`,
    `httproutes`, `roles` and `rolebindings`, plus `("clusterroles", "*")`, `("clusterrolebindings", "*")`, and
    `("roles", "*")` / `("rolebindings", "*")` for the all-namespaces call.
  - `missing: set[str]`: list methods that answer 404.
  - `calls: list[str]`: the method names called, for "no new calls" assertions.
  - Defaults are empty, so existing tests keep passing.
  - The kind-specific builders `service()`, `ingress()`, `network_policy()`, `httproute()`, `role()`, `cluster_role()`,
    `role_binding()`, `cluster_role_binding()` and `service_account()` go in `fakes.py`, next to `pod()`.

- [ ] **Step 1: Extend `test_real_api_sets_request_timeout_on_every_list`.** Also patch `NetworkingV1Api`,
  `RbacAuthorizationV1Api` and `CustomObjectsApi` with `Recorder`. `Recorder` returns `{"items": []}` for
  `list_namespaced_custom_object`. Call every new method, including both forms of `list_roles` and `list_role_bindings`,
  and assert every call carried the timeout. Add `test_list_roles_all_namespaces_uses_the_cluster_wide_call`, which
  asserts the recorded method name is `list_role_for_all_namespaces`.
- [ ] **Step 2: Run.** `.venv/bin/pytest tests/kube/test_client.py -q`. Expect FAIL with AttributeError.
- [ ] **Step 3: Implement** the methods and the fake support. The module docstring of `client.py` gains one sentence:
  the attack-surface lists are reads too, and no Secret is listed.
- [ ] **Step 4: Run.** `.venv/bin/pytest -q`. Expect everything to pass.
- [ ] **Step 5: Commit.** `feat: add read-only service, policy and rbac lists to the kube api (#63)`

### Task 3: Pod-security facts and merging

**Files:**
- Create: `kubedelos/kube/facts.py` (the pod part, plus `merge`)
- Test: `tests/kube/test_facts.py`

**Interfaces:**
- Produces:
  - `pod_security(pod_spec, container, sa_automount: dict[str, bool | None] | None) -> PodSecurity`.
    - `sa_automount` maps each ServiceAccount name in the namespace to its `automountServiceAccountToken`.
    - It is None when ServiceAccounts weren't listed (switch off, or forbidden).
  - `merge(a: WorkloadFacts, b: WorkloadFacts) -> WorkloadFacts`: the riskier value of each fact.

**The rules:**
- **Effective security context:** the container's `securityContext` field wins over the pod's for `runAsUser` and
  `runAsNonRoot`. `privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem` and `capabilities` are
  container-only.
- **`runs_as_root`:**
  - True when the effective `runAsUser == 0`;
  - False when the effective `runAsUser` is above 0, or when `runAsNonRoot` is true;
  - None otherwise.
- **`allow_privilege_escalation`:** True when the field is unset (the Linux default), or when `privileged` is set.
- **`read_only_root_fs`:** False when unset.
- **`host_path_volumes`:** the pod's hostPath volumes that this container mounts. `read_only` comes from the mount, and
  the list is sorted by path.
- **`secret_refs`:** sorted and unique. Sources:
  - secret volumes this container mounts (including `projected.sources[].secret`);
  - `env[].valueFrom.secretKeyRef.name`;
  - `envFrom[].secretRef.name`.
- **`service_account`:** `spec.service_account_name`, or `"default"`.
- **`automount_token`:**
  - the pod field when it is set;
  - else the ServiceAccount's value, when `sa_automount` is given and has the account;
  - else True when `sa_automount` is given but the account's value is None, or the account isn't listed (the
    Kubernetes default);
  - else None when `sa_automount` is None.
- **`merge`:**
  - bools: True wins;
  - `Tri`: True > None > False;
  - exposure level: `external` > `unknown` > `cluster` > `none`;
  - tuples: sorted union (`services` deduped by name; `host_path_volumes` by path, where read-only only if both are);
  - Rights: flags OR'd; status ranked `unknown` > `partial` > `ok` > `off`; `reads_secrets_scope`: `"cluster"` wins,
    otherwise the sorted union.

- [ ] **Step 1: Write the failing tests**, building pod specs with the `fakes.py` objects:
  - `test_container_context_overrides_pod_run_as_user`: the pod sets 0 and the container sets 1000, so False.
  - `test_runs_as_root_unknown_when_nothing_says`: None.
  - `test_run_as_non_root_means_not_root`: False.
  - `test_privileged_implies_privilege_escalation`.
  - `test_host_path_only_when_this_container_mounts_it`: two containers, one mount, read-only flag.
  - `test_secret_refs_from_volumes_env_envfrom_and_projected`: equals `("a", "b", "c", "d")`.
  - `test_automount`, parametrized over pod True/False/None × SA False/None/missing × `sa_automount` None:
    - pod False, SA anything → False;
    - pod None, SA False → False;
    - pod None, SA None → True;
    - pod None, SA missing → True;
    - pod None, `sa_automount` None → None.
  - `test_merge_takes_the_riskier_value`: runs_as_root True+False → True, None+False → None; exposure cluster+external
    → external; ingress_policies union.
- [ ] **Step 2: Run.** `.venv/bin/pytest tests/kube/test_facts.py -q`. Expect FAIL with ImportError.
- [ ] **Step 3: Implement** `facts.py`. Its module docstring says what the facts are, that they come only from objects
  already listed, and that no Secret is ever read.
- [ ] **Step 4: Run.** Expect PASS.
- [ ] **Step 5: Commit.** `feat: derive pod-security facts from pod specs (#63)`

### Task 4: Exposure and NetworkPolicy facts

**Files:**
- Modify: `kubedelos/kube/facts.py`
- Test: `tests/kube/test_facts.py`

**Interfaces:**
- Produces:
  - `selector_matches(selector, labels: dict[str, str]) -> bool`, for a `V1LabelSelector`.
  - `exposure(labels, services: list | None, ingresses: list | None, httproutes: list[dict] | None) -> Exposure`.
    - `None` for `services` means Services couldn't be listed, so the level is `unknown`.
    - `None` for ingresses or httproutes means those couldn't be listed or are absent. Exposure is then judged on what
      was read.
  - `network(labels, policies: list | None) -> Network`. `None` means NetworkPolicies couldn't be listed, so both
    isolation flags are None.
  - `INTERNAL_LB_ANNOTATIONS: dict[str, str]`, mapping an annotation key to its internal value (compared without
    regard to case):
    - `service.beta.kubernetes.io/azure-load-balancer-internal`: `"true"`
    - `service.beta.kubernetes.io/aws-load-balancer-internal`: `"true"`
    - `service.beta.kubernetes.io/aws-load-balancer-scheme`: `"internal"`
    - `networking.gke.io/load-balancer-type`: `"internal"`
    - `cloud.google.com/load-balancer-type`: `"internal"`

    The implementer checks each key against the vendor's current docs and puts the doc URLs in a comment.

**The rules:**
- **Which Services match:** a Service matches when its `spec.selector` is non-empty and every pair is in the pod's
  labels. ExternalName Services and Services without a selector never match.
- **Ingress backends:** an Ingress counts when its `spec.defaultBackend.service.name` or any
  `rules[].http.paths[].backend.service.name` names a matched Service.
- **HTTPRoute backends:** an HTTPRoute counts when any `spec.rules[].backendRefs[]` entry with kind `Service` (the
  default) and group `""` (the default) names a matched Service in the same namespace.
- **`hosts`:** the sorted union of the Ingress rule hosts and the HTTPRoute hostnames of the backends that count.
- **Level:**
  - `external` when any matched Service is a NodePort, any LoadBalancer is not internal, any has `externalIPs`, or any
    Ingress or HTTPRoute counts;
  - else `cluster` when any Service matched;
  - else `none`;
  - `unknown` only when `services` is None.
- **Selected policies:** a policy selects the pod when `selector_matches(spec.pod_selector, labels)` holds. An empty
  selector selects every pod.
- **Policy types:** `policyTypes` when set. Otherwise `["Ingress"]`, plus `"Egress"` when `spec.egress` is non-empty.
- **Isolation:** `ingress_isolated` is whether `ingress_policies` is non-empty; `egress_isolated` the same for egress.
  Both are None when `policies` is None.

- [ ] **Step 1: Write the failing tests:**
  - `test_selectorless_and_externalname_services_match_nothing` (Review Focus 1)
  - `test_clusterip_is_cluster_nodeport_is_external`
  - `test_internal_load_balancer_is_cluster`: parametrize over the five annotations
  - `test_ingress_and_httproute_backends_make_external_and_collect_hosts`
  - `test_httproute_to_other_kind_is_ignored`: a `backendRefs` entry of kind `ServiceImport`
  - `test_services_unlistable_is_unknown`
  - `test_empty_pod_selector_selects_everything` (Review Focus 2)
  - `test_match_expressions_operators`: parametrize over In, NotIn, Exists and DoesNotExist
  - `test_policy_types_default_from_rules`
  - `test_policies_unlistable_is_unknown_isolation`
- [ ] **Step 2: Run.** Expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expect PASS.
- [ ] **Step 5: Commit.** `feat: derive exposure and networkpolicy facts (#63)`

### Task 5: RBAC reduction

**Files:**
- Create: `kubedelos/kube/rbac.py`
- Test: `tests/kube/test_rbac.py`

**Interfaces:**
- Produces:
  - `class RbacIndex`:
    - `RbacIndex.load(api: KubeApi, namespaces: list[str]) -> tuple[RbacIndex, str]`. The second value is the
      `rbac` source status.
    - `index.rights(ns: str, service_account: str) -> Rights`.
  - `RbacIndex.off() -> RbacIndex`, whose `rights()` returns `Rights(status="off")`.

**Loading:**
- First try the four cluster-wide lists: `list_cluster_roles()`, `list_cluster_role_bindings()`, `list_roles(None)` and
  `list_role_bindings(None)`. If all four succeed, the status is `ok`.
- If any of them fails with 403, fall back:
  - `list_roles(ns)` and `list_role_bindings(ns)` for each scanned namespace;
  - plus whichever cluster-wide lists did succeed.

  The status is then `partial` when anything at all was read, and `forbidden` when nothing was.
- A non-403 `ApiException` behaves the same, but the status it ends with is `error`, not `forbidden`.

**Rights for one ServiceAccount:**
- **Which subjects apply:**
  - `kind: ServiceAccount` with the same name and namespace;
  - `kind: Group` named `system:serviceaccounts`, `system:serviceaccounts:<ns>` or `system:authenticated`.
- **Which rules apply:**
  - a ClusterRoleBinding applies its ClusterRole cluster-wide;
  - a RoleBinding applies its Role, or a ClusterRole, in the binding's own namespace.
- **Flags.** A rule with `resourceNames` still counts. Ruling: be conservative, since a narrow grant is still a grant.
  - `cluster_admin`: a ClusterRoleBinding to `cluster-admin`, or a cluster-wide rule with `*` in verbs, resources and
    apiGroups.
  - `reads_secrets`: `get`, `list`, `watch` or `*` on `secrets` or `*`, in apiGroup `""` or `*`.
    - The scope is `"cluster"` when the grant comes through a ClusterRoleBinding.
    - Otherwise it is the sorted namespaces of the RoleBindings that grant it.
  - `creates_workloads`: `create` or `*` on any of `pods`, `deployments`, `statefulsets`, `daemonsets`, `replicasets`,
    `jobs`, `cronjobs` or `*`.
  - `pod_exec`: `create`, `get` or `*` on `pods/exec`, `pods/attach` or `*`.
  - `escalates`: the verbs `escalate`, `bind` or `impersonate` on anything; or `create`, `update`, `patch` or `*` on
    `roles`, `clusterroles`, `rolebindings` or `clusterrolebindings`.
  - `wildcard`: `*` appears in any applying rule's verbs or resources.
- **Unresolvable roleRefs.** A roleRef whose role wasn't listed (partial view) can't be resolved. A ClusterRoleBinding
  or RoleBinding to `cluster-admin` still sets `cluster_admin` (within that namespace for a RoleBinding: ruling, it sets
  `wildcard` and `reads_secrets` scoped to that namespace). Any other unresolved ref makes the result `partial`.
- **Status:**
  - `ok` with a full view;
  - `partial` with a partial view or an unresolved ref;
  - `unknown` when the index status is `forbidden` or `error`.
- **`bindings`:** the sorted names of the applying bindings.

- [ ] **Step 1: Write the failing tests:**
  - `test_cluster_admin_binding`
  - `test_group_subjects_apply`: parametrize over the three groups
  - `test_rolebinding_to_clusterrole_is_namespaced`: `reads_secrets_scope == ("web",)`
  - `test_secret_read_in_another_namespace_counts`: a RoleBinding in `ops` names `web/sa`, so the scope is `("ops",)`
  - `test_resource_names_still_count`
  - `test_pod_exec_and_escalation_flags`
  - `test_wildcard_flag`
  - `test_no_bindings_full_view_is_ok_and_clean`: status `ok`, every flag False
  - `test_cluster_lists_forbidden_falls_back_per_namespace`: the status is `partial`; flags found in a namespaced Role
    still count
  - `test_nothing_listable_is_unknown`: status `forbidden`; `rights().status == "unknown"`
  - `test_server_error_is_error_not_forbidden`
  - `test_off_index`
- [ ] **Step 2: Run.** `.venv/bin/pytest tests/kube/test_rbac.py -q`. Expect FAIL.
- [ ] **Step 3: Implement.** Each list is called once per scan. The module docstring says that only Roles and bindings
  are listed, never Secrets.
- [ ] **Step 4: Run.** Expect PASS.
- [ ] **Step 5: Commit.** `feat: reduce serviceaccount rbac bindings to rights flags (#63)`

### Task 6: Collect facts in the inventory and wire the scan

**Files:**
- Modify: `kubedelos/config.py` (`attack_surface: bool = True`)
- Modify: `kubedelos/kube/inventory.py` (`collect_inventory`; `collect` keeps its signature)
- Modify: `kubedelos/scan/service.py` (calls `collect_inventory` and records `fact_sources`)
- Test: `tests/test_config.py`, `tests/kube/test_inventory.py`, `tests/scan/test_service.py`

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces:
  - `@dataclass(frozen=True) class Inventory(items: list[InventoryItem], warnings: list[InventoryWarning],
    fact_sources: FactSources)`;
  - `collect_inventory(api, settings) -> Inventory`;
  - `collect(api, settings)` returns `(inv.items, inv.warnings)` as before.

**The rules:**
- **Per namespace, with `attack_surface` on:**
  - list services, ingresses, httproutes, network_policies and service_accounts once each;
  - build `RbacIndex.load(api, [scanned namespace names])` once per scan;
  - with `attack_surface` off: none of these calls; use `RbacIndex.off()` and pass `None` everywhere, so exposure and
    network are unknown and `automount_token` is unknown unless the pod sets it.
- **Facts for each pod container, and for each template container** (scaled-to-zero Deployments and StatefulSets,
  CronJobs):
  - pod security from `pod_security(spec, c, sa_automount)`;
  - exposure and network from the pod's own labels; templates use `template.metadata.labels`;
  - rights from `index.rights(ns, service_account)`.

  Store them in `item.facts[workload]`, merging with `merge` when the workload is already there.
- **`fact_sources`:**
  - `pod_security` is always `ok`. With the switch off, every other source is `off`.
  - Per namespaced source: `ok` when every namespace answered; `partial` when some did; `forbidden` or `error` when none
    did.
  - `httproutes`: `absent` when every failure was a 404.
  - `rbac` is the index status.
- **Warnings** (`coverage=False`): at most one per source that isn't `ok`, `absent` or `off`, for example
  `attack-surface: cannot list networkpolicies in 3 namespaces (forbidden); their facts are unknown`.
- **Scan service:** `run_scan` uses `collect_inventory` and calls `repo.set_fact_sources(run_id, inv.fact_sources)`
  right after `add_warnings`. `retry_failed` is unchanged.

- [ ] **Step 1: Write the failing tests:**
  - `test_attack_surface_setting_defaults_on_and_reads_env` (test_config): `KUBEDELOS_ATTACK_SURFACE=false` gives False.
  - `test_facts_attached_per_workload`: a Deployment pod with labels, a NodePort Service, a NetworkPolicy and a
    RoleBinding. Assert `exposure.level == "external"`, `network.ingress_isolated is True` and
    `rights.creates_workloads`.
  - `test_same_image_two_namespaces_keeps_separate_facts` (Review Focus 3).
  - `test_template_workloads_use_template_labels`: a CronJob selected by a ClusterIP Service gives `cluster`.
  - `test_rollout_pods_merge_to_the_riskier_facts`: two pods of one Deployment, one privileged, so privileged.
  - `test_switch_off_makes_no_new_calls` (Review Focus 5): `api.calls` holds none of the new method names; every
    source except `pod_security` is `off`; no new warnings.
  - `test_forbidden_policies_in_some_namespaces_is_partial_with_one_warning`.
  - `test_httproute_crd_absent_is_absent_without_warning`.
  - `test_collect_still_returns_two_values`.
  - `test_cache_hit_still_stores_facts` (test_service, Review Focus 4): seed the cache, run, and assert
    `workload.facts` is not NULL and `scan_run.fact_sources` is set.
- [ ] **Step 2: Run.** `.venv/bin/pytest tests/test_config.py tests/kube/test_inventory.py tests/scan/test_service.py -q`.
  Expect FAIL.
- [ ] **Step 3: Implement.** The new lists are wrapped in a small helper next to `_list_or_warn`, in the same style. It
  returns `None` on `ApiException` or urllib3 `HTTPError` and records the status. The `Settings` field gets a comment in
  the style of its neighbours.
- [ ] **Step 4: Run.** `.venv/bin/pytest -q`. Expect everything to pass, including `tests/web/test_perf.py` when run with
  `-m perf`.
- [ ] **Step 5: Commit.** `feat: collect attack-surface facts with each scan (#63)`

### Task 7: Run-line note and chart default

**Files:**
- Modify: `kubedelos/web/templates/partials/run_line.html`
- Modify: `charts/kubedelos/templates/configmap.yaml` (`KUBEDELOS_ATTACK_SURFACE: "false"`)
- Test: `tests/web/test_dashboard.py` (where the gaps callout is tested), `tests/chart/test_chart.py`

**The rules:**
- **When the note shows:** when `run.fact_sources` has any value of `forbidden`, `partial` or `error`.
- **What it is:** a second `<details class="callout">` after the gaps callout. The summary reads
  `attack-surface facts incomplete: <n> <source|sources> could not be fully read`, and the list has one line per source,
  such as `networkpolicies: partial`. Source keys are shown with `_` replaced by a space, so `network policies`.
- **When it doesn't show:** when every source is `off`, which is `serve` with the chart's defaults, and for old runs with
  `fact_sources` None.
- **Escaping:** the callout escapes as usual. No new CSS.

- [ ] **Step 1: Write the failing tests:**
  - `test_run_line_notes_incomplete_fact_sources`;
  - `test_run_line_quiet_when_sources_off_or_missing`;
  - a chart test that the default render has `KUBEDELOS_ATTACK_SURFACE: "false"` in the ConfigMap.
- [ ] **Step 2: Run.** Expect FAIL.
- [ ] **Step 3: Implement.** The chart line goes next to the other `KUBEDELOS_` keys, with a comment: the chart grants no
  RBAC for these lists yet (a follow-up issue).
- [ ] **Step 4: Run.** `.venv/bin/pytest -q && KUBEDELOS_REQUIRE_HELM=1 .venv/bin/pytest tests/chart -q`. Expect
  everything to pass.
- [ ] **Step 5: Commit.** `feat: note incomplete attack-surface facts on the run line; off in the chart (#63)`

### Task 8: kind e2e, docs and changelog

**Files:**
- Modify: `scripts/e2e-kind.sh`, `tests/e2e/test_kind_scan.py`
- Create: `docs/attack-surface.md`
- Modify: `README.md`, `CHANGELOG.md` (`## Unreleased`), `docs/in-cluster.md` (one line: off in the chart, follow-up)

**The rules:**
- **e2e script.** After the existing setup, add:
  - `kc -n web expose deployment web --type=NodePort --port=80`;
  - a NetworkPolicy in `web` with `podSelector: {matchLabels: {app: web}}` and `policyTypes: [Ingress]`, applied from a
    heredoc;
  - `kc -n jobs create rolebinding cleanup-view --clusterrole=view --serviceaccount=jobs:default`.

  The scan's `Settings` stays the same (`attack_surface` defaults on).
- **e2e test.** It reads `workload.facts` for `web` and `jobs` and asserts:
  - web: `exposure.level == "external"`, `network.ingress_isolated is True`, `rights.status == "ok"`;
  - jobs: `exposure.level == "none"`, and `"RoleBinding/jobs/cleanup-view"` in `rights.bindings`;
  - `scan_run.fact_sources["rbac"] == "ok"`.
- **`docs/attack-surface.md`:**
  - what each fact means and where it comes from (a table of facts, sources and the list call each needs);
  - what "unknown" and "partial" mean;
  - the switch;
  - that no Secret is read;
  - that the chart turns it off for now;
  - the facts JSON shape (v1). PR 2's `docs/mcp.md` will link here.
- **README:** a short "Attack-surface facts" paragraph linking to the doc.
- **CHANGELOG:** one bullet under Features.

- [ ] **Step 1: Write the failing e2e assertions** (in test_kind_scan.py).
- [ ] **Step 2: Run** `.venv/bin/pytest tests/e2e/test_kind_scan.py -m e2e -q` (needs kind and docker). Expect it to fail
  before the script changes and pass after. This test is not in CI (only `e2e-chart` is), so it must be run locally. If kind isn't available, say so in the report and the controller runs it before the PR.
- [ ] **Step 3: Write the script changes and the docs.**
- [ ] **Step 4: Run** `.venv/bin/pytest -q && .venv/bin/ruff check . && .venv/bin/ruff format --check . &&
  .venv/bin/pre-commit run --all-files`. Expect it to be clean.
- [ ] **Step 5: Commit.** `test: cover attack-surface facts on kind; docs: document the facts (#63)`
