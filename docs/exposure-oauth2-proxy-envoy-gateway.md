# Example: oauth2-proxy behind Envoy Gateway

This is a worked example, not part of the chart: the chart forces no proxy or gateway, and the manifests below are yours
to adapt and keep up to date. It puts kubedelos behind [Envoy Gateway](https://gateway.envoyproxy.io/) with external
authorization against [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/), so only members of one group can open
the UI and kubedelos learns who they are. Read [the security model](in-cluster.md#security-model) first.

Placeholders: `kubedelos.example.com` is the UI, `auth.example.com` is your OpenID Connect issuer. Everything else
(namespaces, Gateway name, group, Secret names) is an assumption you must change. It was written against oauth2-proxy
v7.15.6.

How it fits together:

1. A browser asks the Gateway for `https://kubedelos.example.com/`.
2. Envoy asks oauth2-proxy whether the request is allowed. With no valid session, oauth2-proxy answers with a redirect
   to sign in, and Envoy hands that to the browser.
3. After sign-in, oauth2-proxy accepts the request and returns `X-Auth-Request-Email`. Envoy sets that header on the
   request to kubedelos, replacing any copy the client sent.
4. kubedelos, with `auth.trustProxyHeaders` on, reads the header. Only the Envoy proxy pods may reach it.

## Does `headersToBackend` overwrite a client's header?

Yes, for the headers it names. Envoy Gateway documents the field as
"authorization response headers that will be added to the original client request before sending it to the backend
server. Note that coexisting headers will be overridden"
(`api/v1alpha1/ext_auth_types.go`, field `HeadersToBackend`, in
[envoyproxy/gateway](https://github.com/envoyproxy/gateway)). The translator
(`internal/xds/translator/extauth.go`) turns each name into an exact, case-insensitive matcher in Envoy's
`ext_authz` `authorization_response.allowed_upstream_headers`, which is the Envoy option that sets those headers on the
upstream request. This was read from the Envoy Gateway `main` branch (v1.10.0 is the latest release at the time of
writing); check the field's comment in the version you run.

One case remains: the header is replaced only when the authorization response contains it. If oauth2-proxy accepted a
request without returning `X-Auth-Request-Email`, a client's own copy of the header would reach kubedelos. With
`--set-xauthrequest` and a sign-in that yields an email, oauth2-proxy returns it on every accepted request, but test it, as step 2
below does, rather than rely on this page.

## oauth2-proxy

Run it in the `auth` namespace, with the client secret and the cookie secret in a Secret you create (not shown). The
arguments that matter:

```yaml
containers:
  - name: oauth2-proxy
    image: quay.io/oauth2-proxy/oauth2-proxy:v7.15.6
    args:
      - --provider=oidc
      - --oidc-issuer-url=https://auth.example.com
      - --client-id=kubedelos
      - --redirect-url=https://kubedelos.example.com/oauth2/callback
      - --http-address=0.0.0.0:4180
      - --upstream=static://200        # accept the request; Envoy sends it on to kubedelos
      - --email-domain=*               # the group check below is the restriction
      - --allowed-group=kubedelos-users
      - --oidc-groups-claim=groups
      - --scope=openid email profile groups
      - --set-xauthrequest=true        # return X-Auth-Request-Email on accepted requests
      - --cookie-secure=true
      - --cookie-domain=kubedelos.example.com
      - --reverse-proxy=true
      - --trusted-proxy-ip=10.0.0.0/8  # the Envoy proxy pods' network; use your pod CIDR
    env:
      - name: OAUTH2_PROXY_CLIENT_SECRET
        valueFrom: {secretKeyRef: {name: oauth2-proxy, key: client-secret}}
      - name: OAUTH2_PROXY_COOKIE_SECRET
        valueFrom: {secretKeyRef: {name: oauth2-proxy, key: cookie-secret}}
```

`--allowed-group` is what restricts the UI to one group; without it, everyone your issuer signs in can open kubedelos
(and, by default, write). Put a Service named `oauth2-proxy` on port 4180 in front of it. `--set-xauthrequest` makes
oauth2-proxy return `X-Auth-Request-User`, `-Email`, `-Groups` and `-Preferred-Username`; only the email is passed on
below.

## Envoy Gateway

Assuming a Gateway named `eg` in `envoy-gateway-system` with an HTTPS listener for `kubedelos.example.com`. The
HTTPRoute below is the one you could also create from the chart's `httpRoute` values; it is shown here so the pieces
sit together. Two routes: the OAuth callback and sign-in paths go to oauth2-proxy (no ext auth, or nobody could sign
in), and everything else goes to kubedelos.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: oauth2-proxy, namespace: auth}
spec:
  parentRefs: [{name: eg, namespace: envoy-gateway-system}]
  hostnames: [kubedelos.example.com]
  rules:
    - matches: [{path: {type: PathPrefix, value: /oauth2}}]
      backendRefs: [{name: oauth2-proxy, port: 4180}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: kubedelos, namespace: kubedelos}
spec:
  parentRefs: [{name: eg, namespace: envoy-gateway-system}]
  hostnames: [kubedelos.example.com]
  rules:
    - backendRefs: [{name: <release>-kubedelos, port: 80}]   # the Service name: <release>-kubedelos, or the release name if it contains kubedelos
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata: {name: kubedelos-auth, namespace: kubedelos}
spec:
  targetRefs:
    - {group: gateway.networking.k8s.io, kind: HTTPRoute, name: kubedelos}
  extAuth:
    failOpen: false                       # if oauth2-proxy is down, deny; never let requests through
    http:
      backendRefs: [{name: oauth2-proxy, namespace: auth, port: 4180}]
      headersToBackend: [X-Auth-Request-Email]
```

No `http.path` is set, on purpose. Envoy Gateway then sends the authorization request to oauth2-proxy with the original
request path (`api/v1alpha1/ext_auth_types.go`, field `Path`), for example `/scans`. oauth2-proxy handles that in its
proxy mode (`Proxy` in `oauthproxy.go`, v7.15.6): an unauthenticated browser gets the sign-in page or a redirect to the
identity provider, which Envoy passes to the client, and an authenticated request goes to the `static://200` upstream
with `X-Auth-Request-Email` set on the response by `--set-xauthrequest`. The alternative, `http.path: /oauth2/auth`,
is oauth2-proxy's auth-only endpoint (`AuthOnly`): it sets the same headers and returns 202, but answers an
unauthenticated browser with a bare 401 and no sign-in, which is the wrong experience for a UI. The example uses proxy
mode's 200, so it does not depend on how Envoy treats a 202.

Two standard Gateway API rules are not shown: the Gateway's listener must allow routes from the `auth` and `kubedelos`
namespaces (`allowedRoutes`), and the `SecurityPolicy` reaches a Service in another namespace only with a
`ReferenceGrant` in `auth`. `failOpen: false` is also the default; it is written out so a reader sees
the choice.

## kubedelos

```yaml
clusterName: my-cluster
auth:
  trustProxyHeaders: true
  identityHeader: X-Auth-Request-Email
extraAllowedHosts: [kubedelos.example.com]   # the chart does not know the host: this HTTPRoute is not its own
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: envoy-gateway-system}
      podSelector:
        matchLabels:
          app.kubernetes.io/name: envoy
          gateway.envoyproxy.io/owning-gateway-name: eg
```

Check the pod labels on your Envoy Gateway version before you rely on them:
`kubectl get pods -n envoy-gateway-system --show-labels`. The guard refuses an entry that does not narrow, but it cannot
tell whether your labels select the proxy pods and nothing else.

If you create the HTTPRoute from the chart instead (`httpRoute.enabled`, `parentRefs`, `hostnames`), the chart adds the
hostname to the allowed hosts itself and `extraAllowedHosts` is not needed.

## Check it works

1. Open `https://kubedelos.example.com/` in a private window. You should be sent to sign in, and after it the Scans page
   should show your email in the By column once you start a scan.
2. Send a forged header through the Gateway with a valid session cookie. The new-acceptance form prefills its Owner
   field from the identity header the proxy set, so it must show your own email and not the forged one:

   ```bash
   curl -s -b 'cookie from your browser' -H 'X-Auth-Request-Email: someone-else@example.com' \
     https://kubedelos.example.com/accepted/new > form.html
   grep -c someone-else form.html      # must print 0
   grep -c 'name="owner" value="you@example.com"' form.html   # must print 1 (your signed-in email)
   ```

3. From another pod in the cluster, call the kubedelos Service directly with the header. It must time out, because the
   NetworkPolicy admits only the Envoy proxy pods:

   ```bash
   kubectl run probe --rm -it --restart=Never --image=busybox -- \
     wget -T 5 -qO- --header 'X-Auth-Request-Email: someone-else@example.com' http://<release>-kubedelos.kubedelos/
   ```
