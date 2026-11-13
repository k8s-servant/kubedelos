"""Resolve the owner and team a namespace's workloads are attributed to."""

from kubernetes.client import V1Namespace

from kubedelos.config import Settings


def resolve(ns: V1Namespace, settings: Settings) -> tuple[str | None, str | None]:
    """Return ``(owner, team)`` from the configured namespace annotation and label."""
    meta = ns.metadata
    annotations = (meta.annotations if meta else None) or {}
    labels = (meta.labels if meta else None) or {}
    return annotations.get(settings.owner_annotation) or None, labels.get(settings.team_label) or None
