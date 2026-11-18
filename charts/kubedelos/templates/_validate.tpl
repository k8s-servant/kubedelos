{{/*
Checks that fail the render. With auth.trustProxyHeaders on, kubedelos believes the identity header of any request that
reaches it, so every pod that can reach the pod could claim to be anyone. The NetworkPolicy is what limits that to the
sign-in proxy: it must be on, name at least one source, and no source may admit every pod.
*/}}
{{- define "kubedelos.validate" -}}
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
{{- if eq (include "kubedelos.peerAdmitsEveryPod" $peer) "true" -}}
{{- fail (printf "%s, but networkPolicy.ingressFrom[%d] admits every pod: %s" $why $i (toJson $peer)) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
"true" when a selector selects everything: it is not a map, or has neither matchLabels nor matchExpressions entries.
A null selector counts as empty too.
*/}}
{{- define "kubedelos.selectorIsEmpty" -}}
{{- if and (kindIs "map" .) (or (not (empty (get . "matchLabels"))) (not (empty (get . "matchExpressions")))) -}}
false
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
"true" when a NetworkPolicy peer admits every pod: it names none of podSelector, namespaceSelector and ipBlock (this
covers {}), has an empty namespaceSelector (every namespace), has an empty podSelector and no namespaceSelector (every
pod of the release namespace), or is an ipBlock with a /0 prefix (0.0.0.0/0, ::/0), whatever it excepts.
*/}}
{{- define "kubedelos.peerAdmitsEveryPod" -}}
{{- $peer := . | default dict -}}
{{- if not (kindIs "map" $peer) -}}
true
{{- else if not (or (hasKey $peer "podSelector") (hasKey $peer "namespaceSelector") (hasKey $peer "ipBlock")) -}}
true
{{- else if and (hasKey $peer "namespaceSelector") (eq (include "kubedelos.selectorIsEmpty" $peer.namespaceSelector) "true") -}}
true
{{- else if and (hasKey $peer "podSelector") (not (hasKey $peer "namespaceSelector")) (eq (include "kubedelos.selectorIsEmpty" $peer.podSelector) "true") -}}
true
{{- else if hasKey $peer "ipBlock" -}}
{{- $cidr := "" -}}
{{- if kindIs "map" $peer.ipBlock -}}{{- $cidr = toString (get $peer.ipBlock "cidr") | trim -}}{{- end -}}
{{- if or (not $cidr) (hasSuffix "/0" $cidr) -}}
true
{{- else -}}
false
{{- end -}}
{{- else -}}
false
{{- end -}}
{{- end -}}
