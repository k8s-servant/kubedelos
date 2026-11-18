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

{{/* The Host header values the UI answers to, as a comma list: the Service's names, then extraAllowedHosts. */}}
{{- define "kubedelos.allowedHosts" -}}
{{- $name := include "kubedelos.fullname" . -}}
{{- $hosts := list $name (printf "%s.%s" $name .Release.Namespace) (printf "%s.%s.svc" $name .Release.Namespace) (printf "%s.%s.svc.%s" $name .Release.Namespace .Values.clusterDomain) -}}
{{- concat $hosts .Values.extraAllowedHosts | join "," -}}
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
