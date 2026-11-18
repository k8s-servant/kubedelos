{{/*
Checks that fail the render.

With auth.trustProxyHeaders on, kubedelos believes the identity header of any request that reaches it, so every pod
that can reach the pod could claim to be anyone. The NetworkPolicy is what limits that to the sign-in proxy: it must be
on, name at least one source, and no source may admit every pod.

An enabled Ingress or HTTPRoute must also be usable: kubedelos compares the Host header exactly, so it needs the hosts
listed one by one, and an HTTPRoute needs a Gateway to attach to.
*/}}
{{- define "kubedelos.validate" -}}
{{- include "kubedelos.validateTrust" . -}}
{{- include "kubedelos.validateExposure" . -}}
{{- end -}}

{{- define "kubedelos.validateTrust" -}}
{{- if .Values.auth.trustProxyHeaders -}}
{{- $np := .Values.networkPolicy -}}
{{- $why := "auth.trustProxyHeaders needs networkPolicy.enabled and a networkPolicy.ingressFrom that names only the sign-in proxy" -}}
{{- if not $np.enabled -}}
{{- fail (printf "%s, but networkPolicy.enabled is false" $why) -}}
{{- end -}}
{{- if empty $np.ingressFrom -}}
{{- fail (printf "%s, but networkPolicy.ingressFrom is empty" $why) -}}
{{- end -}}
{{- range $i, $peer := $np.ingressFrom -}}
{{- if eq (include "kubedelos.peerAdmitsEveryPod" (dict "peer" $peer "namespace" $.Release.Namespace)) "true" -}}
{{- fail (printf "%s, but networkPolicy.ingressFrom[%d] admits every pod: %s" $why $i (toJson $peer)) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kubedelos.validateExposure" -}}
{{- $wildcard := "wildcard hosts are not supported, because kubedelos compares the Host header exactly: list each host, or add it to extraAllowedHosts" -}}
{{- if .Values.ingress.enabled -}}
{{- if empty .Values.ingress.hosts -}}
{{- fail "ingress.enabled needs at least one ingress.hosts entry" -}}
{{- end -}}
{{- range .Values.ingress.hosts -}}
{{- if hasPrefix "*" .host -}}
{{- fail (printf "ingress.hosts has %q: %s" .host $wildcard) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if .Values.httpRoute.enabled -}}
{{- if empty .Values.httpRoute.parentRefs -}}
{{- fail "httpRoute.enabled needs at least one httpRoute.parentRefs entry naming the Gateway" -}}
{{- end -}}
{{- range .Values.httpRoute.hostnames -}}
{{- if hasPrefix "*" . -}}
{{- fail (printf "httpRoute.hostnames has %q: %s" . $wildcard) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
"true" when a label selector selects everything. Only matchLabels and an In expression narrow a selector; Exists,
DoesNotExist and NotIn can all match every object (a key nobody sets, a value nobody uses), so a selector with neither
matchLabels nor an In expression counts as empty. A null or non-map selector is empty too.
*/}}
{{- define "kubedelos.selectorIsEmpty" -}}
{{- $narrows := false -}}
{{- if kindIs "map" . -}}
{{- if not (empty (get . "matchLabels")) -}}{{- $narrows = true -}}{{- end -}}
{{- range (get . "matchExpressions" | default list) -}}
{{- if and (kindIs "map" .) (eq (toString (get . "operator")) "In") -}}{{- $narrows = true -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- if $narrows -}}false{{- else -}}true{{- end -}}
{{- end -}}

{{/*
"true" when a namespace selector could pick the release namespace through its kubernetes.io/metadata.name label, by
matchLabels or by an In expression.
*/}}
{{- define "kubedelos.selectorNamesNamespace" -}}
{{- $sel := .selector -}}
{{- $found := false -}}
{{- if kindIs "map" $sel -}}
{{- if eq (toString (get (get $sel "matchLabels" | default dict) "kubernetes.io/metadata.name")) .namespace -}}
{{- $found = true -}}
{{- end -}}
{{- range (get $sel "matchExpressions" | default list) -}}
{{- if and (kindIs "map" .) (eq (toString (get . "key")) "kubernetes.io/metadata.name") (eq (toString (get . "operator")) "In") (has $.namespace (get . "values" | default list)) -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $found -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/*
"true" when a NetworkPolicy peer (.peer, in release namespace .namespace) admits every pod. A null field counts as
absent, as Kubernetes reads it. The peer admits every pod when it:
- names none of podSelector, namespaceSelector and ipBlock (this covers {});
- has an empty namespaceSelector (every namespace);
- has an empty or absent podSelector and either no namespaceSelector or one that names the release namespace (every
  pod of the release namespace);
- is an ipBlock whose prefix length is 0 (0.0.0.0/0, ::/0, 0.0.0.0/00), whatever it excepts.
*/}}
{{- define "kubedelos.peerAdmitsEveryPod" -}}
{{- $peer := .peer -}}
{{- if not (kindIs "map" $peer) -}}
true
{{- else -}}
{{- $nsSel := index $peer "namespaceSelector" -}}
{{- $podSel := index $peer "podSelector" -}}
{{- $ipBlock := index $peer "ipBlock" -}}
{{- $hasNs := not (kindIs "invalid" $nsSel) -}}
{{- $hasIp := not (kindIs "invalid" $ipBlock) -}}
{{- $podEmpty := eq (include "kubedelos.selectorIsEmpty" $podSel) "true" -}}
{{- if and (not $hasNs) (kindIs "invalid" $podSel) (not $hasIp) -}}
true
{{- else if and $hasNs (eq (include "kubedelos.selectorIsEmpty" $nsSel) "true") -}}
true
{{- else if and $podEmpty (not $hasNs) (not $hasIp) -}}
true
{{- else if and $podEmpty $hasNs (eq (include "kubedelos.selectorNamesNamespace" (dict "selector" $nsSel "namespace" .namespace)) "true") -}}
true
{{- else if $hasIp -}}
{{- $cidr := "" -}}
{{- if kindIs "map" $ipBlock -}}{{- $cidr = toString (get $ipBlock "cidr") | trim -}}{{- end -}}
{{- $parts := splitList "/" $cidr -}}
{{- if or (ne (len $parts) 2) (not (regexMatch "^[0-9]+$" (last $parts))) (eq (atoi (last $parts)) 0) -}}
true
{{- else -}}
false
{{- end -}}
{{- else -}}
false
{{- end -}}
{{- end -}}
{{- end -}}
