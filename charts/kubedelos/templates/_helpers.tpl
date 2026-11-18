{{/* The release's resource name: the release name, prefixed by the chart name unless it already holds it. */}}
{{- define "kubedelos.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kubedelos.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kubedelos.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "kubedelos.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
The Host header values the UI answers to, as a comma list without repeats: the Service's names, then localhost and
127.0.0.1 (for kubectl port-forward), then the Ingress hosts and the HTTPRoute hostnames (when they are enabled), then
extraAllowedHosts.
*/}}
{{- define "kubedelos.allowedHosts" -}}
{{- $name := include "kubedelos.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $hosts := list $name (printf "%s.%s" $name $ns) (printf "%s.%s.svc" $name $ns) (printf "%s.%s.svc.%s" $name $ns .Values.clusterDomain) "localhost" "127.0.0.1" -}}
{{- if .Values.ingress.enabled -}}
{{- range .Values.ingress.hosts -}}
{{- $hosts = append $hosts .host -}}
{{- end -}}
{{- end -}}
{{- if .Values.httpRoute.enabled -}}
{{- $hosts = concat $hosts .Values.httpRoute.hostnames -}}
{{- end -}}
{{- concat $hosts .Values.extraAllowedHosts | uniq | join "," -}}
{{- end -}}

{{- define "kubedelos.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{- define "kubedelos.claimName" -}}
{{- .Values.persistence.existingClaim | default (include "kubedelos.fullname" .) -}}
{{- end -}}
