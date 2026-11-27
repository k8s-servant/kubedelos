# Changelog

## [0.5.0](https://github.com/k8s-servant/kubedelos/compare/v0.4.0...v0.5.0) (2026-11-27)


### Features

* back off after a failed threat feed download ([#103](https://github.com/k8s-servant/kubedelos/issues/103)) ([dd7b676](https://github.com/k8s-servant/kubedelos/commit/dd7b676d1e574c63ea2daaa3bd32fa4b73ce0fad))
* use kev, epss and the risk score in the explain_cve prompt ([#102](https://github.com/k8s-servant/kubedelos/issues/102)) ([0cc7075](https://github.com/k8s-servant/kubedelos/commit/0cc70752abeedb3c49ecdbef5f89dd88dbe5112c))

## [0.4.0](https://github.com/k8s-servant/kubedelos/compare/v0.3.1...v0.4.0) (2026-11-25)


### Features

* record the trivy db each run scanned with and warn when it was out of date ([#99](https://github.com/k8s-servant/kubedelos/issues/99)) ([8d46952](https://github.com/k8s-servant/kubedelos/commit/8d46952bbc5fe4cf2241c63e5176d7f6c6c6002b))
* say when a threat feed copy is more than three days old ([#100](https://github.com/k8s-servant/kubedelos/issues/100)) ([89234eb](https://github.com/k8s-servant/kubedelos/commit/89234ebb3f4ff9090b80512f9c31ff9e781bd048))

## [0.3.1](https://github.com/k8s-servant/kubedelos/compare/v0.3.0...v0.3.1) (2026-11-25)


### Bug fixes

* match image exclusions per container so a shared digest no longer depends on pod order ([#97](https://github.com/k8s-servant/kubedelos/issues/97)) ([56983af](https://github.com/k8s-servant/kubedelos/commit/56983afef1117bff9ff6bd37a69e474a0003589a))

## [0.3.0](https://github.com/k8s-servant/kubedelos/compare/v0.2.0...v0.3.0) (2026-11-23)


### Features

* share one history between kube-contexts of the same cluster ([#94](https://github.com/k8s-servant/kubedelos/issues/94)) ([b22802b](https://github.com/k8s-servant/kubedelos/commit/b22802be1b1d482de6a8cb6107f6a8918854e252))

## [0.2.0](https://github.com/k8s-servant/kubedelos/compare/v0.1.1...v0.2.0) (2026-11-23)


### Features

* describe kubedelos mcp for the mcp registry ([#91](https://github.com/k8s-servant/kubedelos/issues/91)) ([7365359](https://github.com/k8s-servant/kubedelos/commit/73653591d06585e5133279cc40bb61bf6e2abc9a))


### Documentation

* add the artifact hub badge and link the chart's package page ([#90](https://github.com/k8s-servant/kubedelos/issues/90)) ([9d17408](https://github.com/k8s-servant/kubedelos/commit/9d17408e887b24090a296096d7c2ecfd2d1a1d8a))
* prepare the chart for artifact hub and add pypi and release badges ([#88](https://github.com/k8s-servant/kubedelos/issues/88)) ([859b54e](https://github.com/k8s-servant/kubedelos/commit/859b54e75f1ea39dbe6509e2552943352c5f8e31))

## [0.1.1](https://github.com/k8s-servant/kubedelos/compare/v0.1.0...v0.1.1) (2026-11-22)


### Documentation

* tidy the 0.1.0 changelog and install from the release ([#84](https://github.com/k8s-servant/kubedelos/issues/84)) ([d3ff2f2](https://github.com/k8s-servant/kubedelos/commit/d3ff2f2b44db99dd32673dca6ae1c5b2959eede9))


### Build

* run the image on python 3.14, the newest version ci tests ([#86](https://github.com/k8s-servant/kubedelos/issues/86)) ([610bfb3](https://github.com/k8s-servant/kubedelos/commit/610bfb3966ad6624b74c6f60051912661d463012)), closes [#70](https://github.com/k8s-servant/kubedelos/issues/70)

## 0.1.0 (2026-11-22)


### Features

* accept findings as risk and take them off the ui work lists ([#38](https://github.com/k8s-servant/kubedelos/issues/38)) ([c9661cb](https://github.com/k8s-servant/kubedelos/commit/c9661cb5d616d1e6d9900063793dafe52e26cab1))
* add --pkg-types to choose os packages, libraries or both ([#25](https://github.com/k8s-servant/kubedelos/issues/25)) ([18573d4](https://github.com/k8s-servant/kubedelos/commit/18573d4b06af17964077a136761c44a657e90d00))
* add a namespaces page to the ui ([#37](https://github.com/k8s-servant/kubedelos/issues/37)) ([fbbf4a6](https://github.com/k8s-servant/kubedelos/commit/fbbf4a6374e131cb291d160b2497501df9689497))
* add a read-only settings page that says where each value came from ([#47](https://github.com/k8s-servant/kubedelos/issues/47)) ([9adadab](https://github.com/k8s-servant/kubedelos/commit/9adadab332743fec972b263ca56bbe04f54caa98))
* add a reports page that picks a run for the print report or the findings csv ([#46](https://github.com/k8s-servant/kubedelos/issues/46)) ([c334d4f](https://github.com/k8s-servant/kubedelos/commit/c334d4f8e803a3d9c58d9c594140b04bad4d571f))
* add an about page that says how fresh the trivy dbs and the newest scan are ([#51](https://github.com/k8s-servant/kubedelos/issues/51)) ([d552c82](https://github.com/k8s-servant/kubedelos/commit/d552c821ab075cc7aee88c88dbd6230b7e0f4f6a))
* add kubedelos mcp, a read-only mcp server over the local database ([#63](https://github.com/k8s-servant/kubedelos/issues/63)) ([#69](https://github.com/k8s-servant/kubedelos/issues/69)) ([773929e](https://github.com/k8s-servant/kubedelos/commit/773929ecf57ba9652004b8e9bc94248e17fe36c4))
* add kubedelos registry test and registry login hints ([#6](https://github.com/k8s-servant/kubedelos/issues/6)) ([818f93e](https://github.com/k8s-servant/kubedelos/commit/818f93edb65f1e89f63ef1a38b8a20f3477a88aa))
* add kubedelos serve with scheduled sweeps, a scan queue and retention ([#61](https://github.com/k8s-servant/kubedelos/issues/61)) ([e42b83a](https://github.com/k8s-servant/kubedelos/commit/e42b83a27f2bb24e937a9cf54d6faabcca80cd45))
* add kubedelos ui with the dashboard and findings pages ([#29](https://github.com/k8s-servant/kubedelos/issues/29)) ([a84eb88](https://github.com/k8s-servant/kubedelos/commit/a84eb88f984bec6c2f8ab496bf564a08be161224))
* add label selectors and image exclusion to scan ([#26](https://github.com/k8s-servant/kubedelos/issues/26)) ([f3e92aa](https://github.com/k8s-servant/kubedelos/commit/f3e92aa6184253d531d9ca823914aa0e54b51a05))
* add the container image and helm chart for kubedelos serve ([#64](https://github.com/k8s-servant/kubedelos/issues/64)) ([1bb46b9](https://github.com/k8s-servant/kubedelos/commit/1bb46b91ec52c53bcc74021fa04904b0556dd30e))
* bootstrap repo and add kubedelos scan ([#1](https://github.com/k8s-servant/kubedelos/issues/1)) ([c5bc930](https://github.com/k8s-servant/kubedelos/commit/c5bc93096dfbb1e458f9735dba7acd35454bcf89))
* chart values for the attack-surface facts and the threat feeds ([#78](https://github.com/k8s-servant/kubedelos/issues/78)) ([ef6b192](https://github.com/k8s-servant/kubedelos/commit/ef6b19231a720da57beacc970375d40609169093))
* compare two runs of a cluster in the ui ([#42](https://github.com/k8s-servant/kubedelos/issues/42)) ([715eefd](https://github.com/k8s-servant/kubedelos/commit/715eefd938a62c5e578a0c850048268812707656))
* count failed images by kind on the dashboard and shorten the failures page ([#45](https://github.com/k8s-servant/kubedelos/issues/45)) ([adf16cc](https://github.com/k8s-servant/kubedelos/commit/adf16cc411eeb512c58495e57355f04b99ca5385))
* download the findings view as csv and print a run report ([#43](https://github.com/k8s-servant/kubedelos/issues/43)) ([973eb62](https://github.com/k8s-servant/kubedelos/commit/973eb62afa7e1849ddec04594ba8af98269a6249))
* keep each parallel scan's trivy layer cache on disk between runs ([#49](https://github.com/k8s-servant/kubedelos/issues/49)) ([8ac8a0b](https://github.com/k8s-servant/kubedelos/commit/8ac8a0b3fd42cc3c17bd397b8020769ca7de0c5b))
* let one scan skip the result cache and rescan every image ([#54](https://github.com/k8s-servant/kubedelos/issues/54)) ([01d7342](https://github.com/k8s-servant/kubedelos/commit/01d7342f38236d365fde0d7d96d7de0882b2d4a9))
* number runs per cluster in the ui ([#39](https://github.com/k8s-servant/kubedelos/issues/39)) ([0f8246b](https://github.com/k8s-servant/kubedelos/commit/0f8246baa04d2657af5c636b48eff08653a9dfe2))
* open writes in kubedelos serve with an optional read-only mode ([#62](https://github.com/k8s-servant/kubedelos/issues/62)) ([b4ade8c](https://github.com/k8s-servant/kubedelos/commit/b4ade8c1f5981eddf11947f6d2d70fe08293d8c0))
* rank fix-first by a risk score from threat feeds and exposure ([#63](https://github.com/k8s-servant/kubedelos/issues/63)) ([#72](https://github.com/k8s-servant/kubedelos/issues/72)) ([83141d6](https://github.com/k8s-servant/kubedelos/commit/83141d608ba6e191f9195d404101eae1e399d472))
* record attack-surface facts for every workload (pr 1 of [#63](https://github.com/k8s-servant/kubedelos/issues/63)) ([#68](https://github.com/k8s-servant/kubedelos/issues/68)) ([509da80](https://github.com/k8s-servant/kubedelos/commit/509da807f302f202131cad4cd3a6ba3b5d36a881))
* registry login for kubedelos serve (cloud identity, docker configs, pod pull secrets) ([#67](https://github.com/k8s-servant/kubedelos/issues/67)) ([5a6024e](https://github.com/k8s-servant/kubedelos/commit/5a6024eda7338f1568d30b4026f6c128c769f432))
* restyle kubedelos ui with a sidebar, radar logo and worst images panel ([#30](https://github.com/k8s-servant/kubedelos/issues/30)) ([38935df](https://github.com/k8s-servant/kubedelos/commit/38935df1c57ef04234db7d907160a4958427d49a))
* retry a run's failed images in place with a longer time limit ([#44](https://github.com/k8s-servant/kubedelos/issues/44)) ([fbca8f5](https://github.com/k8s-servant/kubedelos/commit/fbca8f59537064b071619bfa4541d180efc6cfd7))
* retry failed images by kind and line up the retry form ([#50](https://github.com/k8s-servant/kubedelos/issues/50)) ([6df3de9](https://github.com/k8s-servant/kubedelos/commit/6df3de98e209a37a86b3909a7f6a97157ff1202a))
* show every failed image of a run, live and on its own page, and retry passing errors once ([#40](https://github.com/k8s-servant/kubedelos/issues/40)) ([52187fe](https://github.com/k8s-servant/kubedelos/commit/52187fefcca2a7fd91e96aed19bfa1b2a301b07f))
* start, follow and cancel scans from the ui ([#32](https://github.com/k8s-servant/kubedelos/issues/32)) ([e9bb7c7](https://github.com/k8s-servant/kubedelos/commit/e9bb7c7121941981844463cdf5d1201b4de4c7b8))
* switch between kube-contexts and scan any of them from the ui ([#36](https://github.com/k8s-servant/kubedelos/issues/36)) ([a2e564f](https://github.com/k8s-servant/kubedelos/commit/a2e564f68e59dcc06eb14291f7a514752e1fa67a))
* time each image's scan and show where a run's time went ([#48](https://github.com/k8s-servant/kubedelos/issues/48)) ([f320489](https://github.com/k8s-servant/kubedelos/commit/f32048942cb967d45b1d94c7f2e12eacdd179de5))


### Bug fixes

* accept the namespaces form's any-severity value and keep the context on 400 pages ([#41](https://github.com/k8s-servant/kubedelos/issues/41)) ([94fe85b](https://github.com/k8s-servant/kubedelos/commit/94fe85b3bb0858bfacb6b03adbc4f611faa7ba14))
* cache images without a registry digest by their local image id ([#33](https://github.com/k8s-servant/kubedelos/issues/33)) ([099e805](https://github.com/k8s-servant/kubedelos/commit/099e8050d64a636ea88350a43d80e4433c725e2a))
* fail a scan whose scope selects nothing or is forbidden everywhere ([#79](https://github.com/k8s-servant/kubedelos/issues/79)) ([34a1f33](https://github.com/k8s-servant/kubedelos/commit/34a1f33112c006a1bcf59fc2470799aeeb75d4e9))
* line up the scans start form and style its number input ([#59](https://github.com/k8s-servant/kubedelos/issues/59)) ([20db244](https://github.com/k8s-servant/kubedelos/commit/20db24410dcf8d1fd929ce31d227946fb1ffeee5))
* line up the values of the about and settings cards ([#52](https://github.com/k8s-servant/kubedelos/issues/52)) ([b56c855](https://github.com/k8s-servant/kubedelos/commit/b56c85596805f6ea520249b255808af826f2b2f4))
* show the cause of trivy errors instead of their first 200 characters ([#27](https://github.com/k8s-servant/kubedelos/issues/27)) ([cf176f6](https://github.com/k8s-servant/kubedelos/commit/cf176f6632cef353acf3def2d55f4ba14ffdc645))
* show the findings risk column first and wrap long installed versions ([#81](https://github.com/k8s-servant/kubedelos/issues/81)) ([ed277a1](https://github.com/k8s-servant/kubedelos/commit/ed277a141bc313f740fabd3bb4f8c7646583e985))


### Documentation

* add an install guide and a docs index, and slim the readme to an overview ([#77](https://github.com/k8s-servant/kubedelos/issues/77)) ([248c95e](https://github.com/k8s-servant/kubedelos/commit/248c95e65087590cb638d2bb57fbd1e51d8a9e58))
* design the in-cluster mode (serve, schedule, chart, registry login) ([#60](https://github.com/k8s-servant/kubedelos/issues/60)) ([1b932b5](https://github.com/k8s-servant/kubedelos/commit/1b932b5a663cdfdff31966ba313a4dd46f552c88))
* explain how a scan works, with every cache, db and limit ([#53](https://github.com/k8s-servant/kubedelos/issues/53)) ([d10a1a5](https://github.com/k8s-servant/kubedelos/commit/d10a1a57da47fefe4ef2ac9d6538da439efd1c31))
* explain why kubedelos exists, add a compatibility table and credit trivy ([#34](https://github.com/k8s-servant/kubedelos/issues/34)) ([82480fa](https://github.com/k8s-servant/kubedelos/commit/82480fad7798651851b9b7717f93715e71d8bbe7))
* show the dashboard, a scan and the fix-first list in the readme ([#82](https://github.com/k8s-servant/kubedelos/issues/82)) ([4a6b653](https://github.com/k8s-servant/kubedelos/commit/4a6b653182e0e97cabe77681c414d45ac932b5a0))


### Build

* install the image's python packages from hashed lock files ([#80](https://github.com/k8s-servant/kubedelos/issues/80)) ([98b8e7a](https://github.com/k8s-servant/kubedelos/commit/98b8e7ae469420b2cf146046178c64091a70efa8))

### In detail

The notes kept by hand before the first release, with more detail than the list above.

#### Features

- Risk score: the dashboard's fix-first lists, the findings page (sort by `risk`), the print report and the CSV show a
  0-100 score per finding with the factors behind it. It is hidden for a run with no attack-surface facts while no
  threat feed has been downloaded, and the page says what is missing. The MCP tools `fix_first` and
  `find_vulnerability` return the score and its factors too, plus a `risk` object and the CVE's KEV and EPSS data.
  The findings table's accepted column is now called Status. See [Risk score](docs/risk-score.md).
- Threat feeds: CISA KEV (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) and
  EPSS (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`) are downloaded at most once a day, before a
  scan and when `kubedelos ui` starts (in the background), with plain HTTPS GETs (a redirect that leaves HTTPS is refused) that send nothing about the cluster. A
  broken, oversized or sharply smaller copy is refused and the stored one kept; a feed never fails a scan or the UI.
  `KUBEDELOS_THREAT_FEEDS=false` turns them off; the chart's `threatFeeds.enabled` is `false` by default because many
  clusters give pods no egress. The Settings page shows when each feed was last fetched. Schema migration 13 adds the `threat_intel` and
  `threat_feed` tables and `workload.risk_points` (each workload's exposure, host and rights points), filled in for the
  rows already stored.
- `kubedelos mcp`: a read-only MCP server over stdio, so your own agent can query the local scan database. It opens
  the database read-only, never reaches the cluster and calls no LLM. Tools so far: `list_clusters`, `run_summary`,
  `fix_first`, `find_vulnerability`, `workload`, `list_findings`, `attack_surface`, `compare_runs` and
  `accepted_risks`. Prompts: `fix_first_briefing`, `attack_paths` and `explain_cve`, fixed instructions that never
  contain scan data. `attack_surface` reports `host_access` and `rights_status` as null for a workload without facts.
  `python -m kubedelos` now works too. See [Ask your agent](docs/mcp.md).
- Attack-surface facts: each scan records, per workload container, its pod security settings, exposure (hostPorts,
  Services, Ingresses, Gateway API HTTPRoutes), NetworkPolicy isolation and ServiceAccount RBAC rights as versioned
  JSON on the workload, plus the status of each source per run. Anything it could not list is reported as unknown or
  partial, never as safe, and no Secret is read. `KUBEDELOS_ATTACK_SURFACE=false` turns it off. The chart's
  `attackSurface.enabled` (on by default) sets it and grants the ClusterRole the `list` calls the facts need (services,
  serviceaccounts, ingresses, networkpolicies, httproutes, roles, rolebindings, clusterroles and clusterrolebindings). See [Attack-surface facts](docs/attack-surface.md).
- Settings page: a Registries card (cloud identity and the hosts it covers, mounted Docker config Secret names,
  pull-secret namespaces) and, in `kubedelos serve`, a "Test an image" form that scans one image with the cloud identity
  and the mounted Docker configs (not pod pull secrets: there is no pod; an auth error on a host known only from the
  newest run says so). The AWS hosts cover every ECR endpoint form Trivy accepts (FIPS, `on.aws`, `.amazonaws.com.cn`,
  `sc2s.sgov.gov`, `c2s.ic.gov`). It refuses a host that is not in a mounted Docker config, not covered by the
  configured cloud provider and not used by an image in the cluster's newest run, and in read-only mode. New settings
  `KUBEDELOS_CLOUD_PROVIDER` and `KUBEDELOS_CLOUD_IDENTITY` (display only).
- Cloud presets: the chart's `cloud.provider` (`azure`, `aws`, `gcp`) with `cloud.azure.clientId`, `cloud.aws.roleArn`
  or `cloud.gcp.serviceAccount` annotates the ServiceAccount for workload identity (and labels the pod on Azure), so
  Trivy logs in to ACR, ECR and Artifact Registry/GCR itself. The render fails when the id is missing. The cloud-side
  role stays yours to create; see [ACR](docs/registries/acr.md), [ECR](docs/registries/ecr.md) and
  [GAR](docs/registries/gar.md).
- Mounted Docker configs: `registries.dockerConfigSecrets` mounts `kubernetes.io/dockerconfigjson` Secrets from the
  release namespace (`KUBEDELOS_DOCKER_CONFIGS`), the first match per host wins, and no Secret RBAC is needed.
- Opt-in pod pull secrets: `registries.podPullSecrets` with `registries.podPullSecretNamespaces`
  (`KUBEDELOS_POD_PULL_SECRET_NAMESPACES`) makes a scan read the `imagePullSecrets` of pods in those namespaces, through
  a Role with `get` on `secrets` in each (nothing cluster-wide). kubedelos gets each Secret a pod names, once per run (a
  failed read counts as empty until the next run); one that is not `dockerconfigjson` is discarded without its data
  being decoded, used or logged, only the entries for the image's host are used, and they override the mounted configs.
  This is an exception to "never read Secrets"; see [Pull secrets](docs/registries/pull-secrets.md) for what it permits.
- Secrets volume: each scan's Docker config is written to a temporary directory under `KUBEDELOS_SECRETS_DIR` (the chart
  mounts a 16Mi memory-backed `emptyDir` at `/run/kubedelos`), mode 0700, and removed when the scan ends; `serve`
  removes leftover per-scan configs (`kubedelos-docker-*`) from it at start. It must be a different directory from the
  data and cache directories. With it unset, as on a laptop, nothing is written and your own Docker login applies.
- Retries keep pull secrets: the names of the Secrets an image's pods used are stored with its result (schema migration
  11, `image_result.pull_secrets`), so a retry of an auth failure reads the same Secrets again. Contents are never
  stored.
- Helm chart `charts/kubedelos` installs `kubedelos serve`: one hardened replica (Recreate, non-root, read-only root filesystem), a PVC, a Service, a ConfigMap of `KUBEDELOS_*` settings and a read-only ClusterRole. `clusterName` is required and a values schema rejects unknown keys. A NetworkPolicy admits only `networkPolicy.ingressFrom` (nothing by default). An optional Ingress or Gateway API HTTPRoute adds its hosts to `KUBEDELOS_ALLOWED_HOSTS`, which the chart fills with the Service's DNS names, `localhost` and `127.0.0.1` (so `kubectl port-forward` works), the Ingress and HTTPRoute hosts and `extraAllowedHosts`.
- Chart guards: with `auth.trustProxyHeaders` on, the chart refuses to render unless the NetworkPolicy is on and `ingressFrom` names a source that does not admit every pod (`{}`, an entry with no selector or `ipBlock`, a selector with no `matchLabels` or `In` expression, an empty `namespaceSelector`, one naming only the release namespace with no `podSelector`, an `ipBlock` with prefix 0). Wildcard Ingress hosts and HTTPRoute hostnames are refused, and an enabled Ingress needs a host and an enabled HTTPRoute a `parentRefs` entry. The guard catches common mistakes and is not a proof: `ipBlock` ranges, other NetworkPolicies, `kubectl port-forward`, `hostNetwork` traffic and a CNI that does not enforce NetworkPolicy are the operator's to check. NOTES.txt warns when the UI is exposed or writable without sign-in and, with trust on, names those bypasses.
- Container image: a multi-arch `Dockerfile` (python alpine, pinned by digest) bundles the pinned Trivy, checksum-verified at build time, so the pod downloads nothing. It runs `kubedelos serve` as user 65532 and writes only `/data` and `/tmp`; `scripts/image-smoke.sh IMAGE` checks it.
- Release: the image (amd64 and arm64, with SBOM and provenance) and the Helm chart are pushed to `ghcr.io/k8s-servant`
  on each release and signed keylessly with cosign, each in its own job; verify them with the identity of
  `release-please.yml` on `main`. CI lints and renders the chart, builds, smoke-tests and scans the image with the
  pinned Trivy (failing only on fixable `CRITICAL` findings), and installs every downloaded tool by its pinned SHA-256.
  A kind end-to-end job (`scripts/e2e-chart.sh`) installs the chart with the built image and waits for the first
  scheduled sweep, which also scans images in a private `registry:2` through a mounted docker config and pod pull
  secrets (the cloud presets are not run in CI).
- `KUBEDELOS_SECURE_COOKIES=true` marks the `serve` CSRF cookie `Secure` (the chart sets it by default, `secureCookies`); `KUBEDELOS_TRIVY_DIR` names a directory holding `<version>/trivy`, used before the cache and never downloaded over.
- `kubedelos serve` runs kubedelos in a cluster: the UI of one cluster (`KUBEDELOS_CLUSTER_NAME`) on `0.0.0.0:8080`, with `/healthz`. Only one `serve` can use a data directory. Anyone who can reach it can read the whole inventory and, unless read-only, write, so expose it only through an authenticating proxy or keep it cluster-internal.
- Writes in `kubedelos serve`: UI scans, retries and cancels go through the queue and stay within the configured scope (a scan can only narrow it). Writes need an allowed `Origin` and a CSRF token.
- `KUBEDELOS_READ_ONLY=true` makes `serve` refuse every write; the pages hide their forms and show a notice.
- `KUBEDELOS_TRUST_PROXY_HEADERS` and `KUBEDELOS_IDENTITY_HEADER` (default `X-Auth-Request-Email`) take the user's name from a trusted proxy header; the Scans page shows it in the By column (`schedule` or `anonymous` otherwise).
- Risk acceptances default their owner to that name.
- Scheduled sweeps: `serve` queues a sweep on a cron schedule (`KUBEDELOS_SWEEP_SCHEDULE`, default `0 3 * * *`, in `KUBEDELOS_SWEEP_TIMEZONE`; `KUBEDELOS_SWEEP_ENABLED=false` turns it off) and a worker runs the queue one scan at a time. A sweep skips the 24-hour result cache, so findings match the current Trivy DB.
- Retention: `serve` deletes runs older than `KUBEDELOS_RETENTION_DAYS` (default 180, `0` keeps all) and expired image-cache rows.
- Scan queue: schema migration 10 adds the `scan_request` table that holds queued, started and cancelled requests.
- Rescan every image: a box on the Scans form skips the 24-hour result cache for one scan, so every image is matched against the current Trivy DB. Fresh results still go into the cache.
- A guide, [How a scan works](docs/how-scans-work.md), explains each step of a scan, the result cache, the Trivy DBs and the layer cache (what, where, why and how long), parallelism and time limits, failure kinds and retries, how to speed up a slow scan, and what is kept on disk.
- Package skeleton with the `kubedelos` entrypoint.
- An About page (last in the sidebar) says how fresh the data is: when Trivy built the vulnerability and Java DBs in use, whether a newer one is out (the next scan downloads it) and when the shown context was last scanned. It also names the kubedelos, Trivy and Python versions, the license, the project links with the security policy, and what kubedelos never does.
- Layer cache: each parallel scan keeps Trivy's layer cache on disk between runs, in a slot of its own (Trivy locks the cache for a whole scan), so a rescan only analyses layers it has not seen; a warm rescan of a JDK image took 1.8 s instead of 11 s. A slot another `kubedelos ui` is using is skipped, a scan with no free slot keeps its cache in memory as before, each repository goes back to its own slot (one of 32, at most 128 MB each, emptied when over), and `KUBEDELOS_LAYER_CACHE=false` turns it off.
- Retry by kind: the retry form ticks a box per kind of failure, with its count, so a retry can skip images that will fail again. Every kind but `not_found` is ticked at first (only the shown kind when the page is narrowed), and the note a retry leaves counts only the images it retried. The form's limits and button now line up on one row.
- Scans start from the web UI; there is no `kubedelos scan` command, since CI gating is left to plain Trivy.
- Scan times: each image's scan is timed and stored with its result (schema migration 9). A page per run lists the slowest images and how the time was spent, linked from each run's duration in the Scans history and from the failures page, which shows each failure's time.
- A Settings page lists every setting the UI started with, its value and where it came from (flag, environment or default), plus the database file, data and cache directories, the Trivy in use and the log level. It is read-only and lists no credentials.
- A Reports page in the sidebar picks a run and opens its print report, or picks a run and the findings filters and downloads the CSV.
- Reports: the findings page downloads its view as a formula-safe CSV (every row, streamed), and a print sheet of a run gives its numbers, fix-first list and failed images for printing or saving as PDF.
- Compare: a Compare page shows what changed between two runs of a cluster (new findings, fixed or gone, images added, gone and changed), matching images by repository so a tag bump does not read as everything fixed and everything new. It names scope differences, failed images and coverage gaps above the numbers.
- Retry failed images: the newest partial run of a cluster can scan its failed images again from the failures page, with a longer time limit and fewer parallel images, and the results go into the same run, which becomes `ok` once nothing fails. The cluster is not read, and each retry leaves a note on the run.
- Failed images read at a glance: the dashboard's card counts the failures by kind, one line each with what the kind means and a link to just those images, plus a Retry button where the run can be retried. The failures page names each image short (the full ref is folded away), gives the cause in a few words, and narrows to one kind with `?kind=`.
- Failed images: a page per run lists every image that failed to scan with its cause, linked from the Scans history, the dashboard and the progress readout, which also shows the newest failures while a scan runs. An image that fails with a passing network error (such as "unexpected EOF" mid-download) is retried once.
- Runs are numbered per cluster: each cluster's first run is Run 1, wherever the UI names a run. URLs keep the run id. Schema migration 8 numbers existing runs.
- Accepted risk: accept a CVE from any findings row (for one cluster or all, optionally narrowed to a namespace, an image repository or a package, with a reason, an owner and an expiry of at most a year). Accepted findings leave the fix-first list and the findings page until they expire or are revoked, and each list says how many it left out; counts never change. The Accepted page lists every entry with its state, days left and what it covers. Schema migration 7 adds the `acceptance` table.
- A Namespaces page lists each namespace of the dashboard's run, worst first, with owner, team, counts per severity and images; every column sorts, it filters by text and by severity, and each count links to exactly its findings.
- The UI shows every kube-context: the sidebar's context card opens a list of the kubeconfig's contexts (read on each page) and those in the scan history, with when each was last scanned. The shown context travels in the URL (`?context=`), and the Scans page scans it; one scan runs at a time across contexts.
- `kubedelos trivy install` downloads the pinned Trivy v0.76.1 release and checks it against an embedded, Sigstore-verified SHA-256. A scan runs one standalone Trivy per image and stops them when `kubedelos ui` exits on Ctrl-C or SIGTERM; `registry test` also stops on SIGHUP.
- A scan inventories a kube-context (running pods with their init and ephemeral containers, plus the templates of CronJobs and of workloads scaled to zero) and scans every unique image with Trivy.
- Digest cache so unchanged images are not rescanned.
- A namespace selector and a pod/workload label selector narrow a scan (kubectl syntax, applied by the API server), and image globs skip images before scanning. Each run records its scope.
- `KUBEDELOS_PKG_TYPES` (or the Scans form) chooses OS packages, application libraries or both (the default). Each finding records its package class, OS-only scans skip the Java DB, and cached results are kept per scan level.
- `kubedelos registry test <image>` checks that an image is readable with your current registry login, and the dashboard shows a login hint for registries that refuse access.
- Parallel scans, and scans from several `kubedelos ui` processes at once, share one Trivy DB cache safely; no local Trivy server or port is used.
- Owner attribution from the `kubedelos.io/owner-email` namespace annotation, recorded with every finding.
- RBAC-aware inventory: namespaces you may not list are skipped with a warning, and the run is marked incomplete.
- Images are shown as `repo:tag` plus a short digest.
- Environment variables are documented, including the JSON list format.
- `kubedelos ui` serves a local web UI (dashboard, findings and scans, with a sidebar layout, the radar logo, a light and dark theme, a Worst images panel and a sidebar footer naming the Trivy version of the shown run) on loopback only. The Scans page starts a scan of the UI's context, one at a time, with a form for the scope, the image exclusions, the parallel image count and the package types, with live progress (phase, image counts, the last finished image and an estimate), cancel, and a paged run history; Ctrl-C on `kubedelos ui` cancels a running UI scan and, after 10 seconds, kills any Trivy still running. The printed URL carries a token that is swapped for a session cookie and stays valid until the server stops (a restart prints a new one); `KUBEDELOS_LOG_LEVEL=info` prints an access line per request on stderr.
- The UI pages render in under 300 ms on a database of 1,000 images and 100,000 findings; schema migration 5 adds the indexes they need.
- Each scan run stores the namespaces and resources the inventory could not list, so the UI marks such runs incomplete.
- Each scan run holds an owner lock file while it runs. `kubedelos ui` closes runs left `running` with no live owner as `failed` at startup (printing, for example, `note: closed 2 interrupted runs`) and before each UI scan; a scan running in another process is never closed.

#### Documentation

- The README opens with a dashboard screenshot (light and dark), shows a scan as a short GIF and the fix-first list with
  the factors behind a score; the UI guide shows the findings page sorted by risk. All come from a real scan of a
  throwaway kind cluster running old public images; `scripts/demo/` recreates them.
- The docs have an index ([docs/README.md](docs/README.md)) and an [install guide](docs/install.md): requirements,
  installing from GitHub until the first release, cluster permissions, registry logins, the chart from a clone, where
  files are kept, upgrading and uninstalling. The README has a table of contents and stays an overview; the page-by-page
  UI description moved to [docs/ui.md](docs/ui.md), every setting to [docs/configuration.md](docs/configuration.md), and
  the scan scope details to [How a scan works](docs/how-scans-work.md#what-a-scan-covers). Each guide ends with related
  guides.
- Guides for private registries in the in-cluster mode: [ACR from AKS](docs/registries/acr.md), [ECR from
  EKS](docs/registries/ecr.md), [Artifact Registry from GKE](docs/registries/gar.md) and [pull secrets and Docker
  configs](docs/registries/pull-secrets.md). They say which hosts Trivy v0.76.1 uses the cloud identity for and that the
  identity is tried before a Docker config.
- Guides for the in-cluster mode: [Running kubedelos in a cluster](docs/in-cluster.md) (install, every chart value, storage, exposure, the security model and verifying the signed release) and [oauth2-proxy behind Envoy Gateway](docs/exposure-oauth2-proxy-envoy-gateway.md), a worked example.
- The README leads with the web UI, explains why kubedelos exists next to plain Trivy, has a compatibility table (Python, operating systems, Trivy, Kubernetes, image platforms, registries) and credits Trivy.
- The README names the oldest Trivy a custom `KUBEDELOS_TRIVY_PATH` can be: v0.54.0, the first with `--pkg-types`.

#### Build

- The release workflow pushes the image and the chart to the GHCR namespace of the repository that runs it, so a
  release dry run on a fork works without editing the workflow.
- The container image installs every Python package from hashed lock files (`requirements/image.txt` for the runtime
  dependencies, `requirements/build.txt` for setuptools), generated by `scripts/lock-image.sh`. Two builds of one commit
  install the same files, a changed hash fails the build, and `pip check` fails it if the lock misses a dependency.
  Dependabot updates the locks, and a test fails when they no longer satisfy `pyproject.toml`.

#### Bug Fixes

- The findings page shows the Risk column first, as the dashboard does; it was second to last and scrolled out of view
  at 1280 px. A long installed version in the dashboard's fix list wraps instead of running into the Fixed in column.
- A scan whose scope selects no namespace, or where every namespace refuses the pod list, now ends `failed` with a note
  instead of an `ok` run with no images that read as "no findings". The run is recorded before the cluster is listed,
  so a selector the API server rejects or an unreachable cluster also leaves a `failed` run with its reason (an API
  error is stored as its status and reason only). The Scans history shows that reason, and the note on a run closed
  because no live process owned it, under the run's status.
- The Scans form lines up: the parallel images box is styled like the other inputs (as are the retry form's number boxes), inputs, pills and the Scan button share one height and top edge, and the rescan hint fits on one line.
- Two kubedelos processes opening the same new or older database at once no longer fail with "duplicate column name" or "database is locked": each migration runs under the write lock and is skipped when the other process has already applied it.
- Image exclusions match images whose registry host is written in uppercase or as `index.docker.io`, the way image names are normalised.
- A run's scope ignores repeated namespaces and image exclusions, so such runs still compare with the same scope written once.
- `kubedelos registry test --platform` must be `os/arch[/variant]`; anything else is refused before Trivy runs.
- UI polish: the KPI tiles put the change line right under the number instead of at the tile bottom; the findings table names each image short (the full ref is its tooltip), so rows stay one line high; installed versions, with their "+N", never wrap; status chips use the mockup grey.
- The About and Settings pages give their label column one width on wide screens, so the values line up from card to card.
- The namespaces filter no longer answers 400 "invalid parameter: has" when "any severity" is selected, and a 400 page keeps the cluster it was shown for.
- Static files are served under a content-hashed URL, so a browser never pairs a new page with a stylesheet it cached from an older release.
- Images with no registry digest, such as kind's preloaded images, are now cached by their local image ID when Trivy scanned that exact image, so a repeat scan of a kind cluster takes seconds instead of rescanning every image.
- The local UI keeps at most 64 sessions, so repeated token visits no longer grow its memory.
- Restarting `kubedelos ui` on macOS no longer fails with 'port in use' while the previous run's connections close.
- Valid image refs with an uppercase or IPv6 registry host, repeated separators or a non-sha256 digest are no longer rejected.
- Locally loaded images (kind's `import-<date>` imageID) are scanned by their tag instead of a digest that no registry has.
- SIGTERM no longer leaves Trivy scans running and the run stuck in `running`.
- `--context` no longer falls back to the in-cluster config when the context does not exist.
- Kubernetes API calls time out instead of hanging.
- Pods on Windows nodes are scanned for `windows/<arch>` instead of `linux/<arch>`.
- A cached result that no longer validates is rescanned instead of failing the run.
- Results from a custom Trivy (`KUBEDELOS_TRIVY_PATH`) no longer enter the cache under the pinned Trivy version.
- Failed images, `registry test` and Trivy DB download errors show the cause Trivy reports (`MANIFEST_UNKNOWN`, `DENIED`, `no such host`) instead of the first 200 characters of its generic `FATAL` wrapper, and multi-line errors print on one line. Before Trivy errors are stored or printed, URL query strings and `user:password@`, bearer tokens and `token=`/`password=`-style values are redacted, so a signed storage URL doesn't leak its signature. This is best effort: other credential shapes aren't recognised.
- Error redaction also covers `Basic` and bare `Authorization` header values, JWT-shaped values, and colon forms such as `token: ...`, `password: ...`, `secret: ...` and `api-key: ...`, including JSON-quoted keys. Errors shown in the UI go through the same redaction.
