"""Domain models shared by inventory, scanning and storage."""

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_REF_LEN = 512
# A conservative OCI reference: optional host[:port]/, lowercase path components, optional tag and/or digest.
_HOST = (
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"  # DNS name
    r"|\[[0-9A-Fa-f:]+\])"  # or a bracketed IPv6 address
    r"(?::[0-9]+)?/"  # optional port; a host is always followed by a path
)
_PATH = r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*"
_TAG = r":[A-Za-z0-9_][A-Za-z0-9._-]{0,127}"
_DIGEST = r"@[a-z0-9]+(?:[+._-][a-z0-9]+)*:[0-9a-fA-F]{32,}"  # OCI digest grammar: algorithm ":" hex
_REF_RE = re.compile(rf"(?:{_HOST})?{_PATH}(?:{_TAG})?(?:{_DIGEST})?")


def is_digest(value: str) -> bool:
    """True only for a complete ``sha256:<64 lowercase hex>`` digest."""
    return _DIGEST_RE.fullmatch(value) is not None


def is_valid_ref(ref: str) -> bool:
    """True for a plausible image reference that is safe to hand to Trivy as an argument.

    Refs come from cluster-controlled pod specs, so anything with whitespace, control characters or a leading ``-``
    (which a CLI could read as a flag) is rejected, as is anything over 512 characters.
    """
    if not ref or len(ref) > _MAX_REF_LEN or ref.startswith("-"):
        return False
    if any(ch.isspace() or not ch.isprintable() for ch in ref):
        return False
    return _REF_RE.fullmatch(ref) is not None


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}[self.value]


class ImageRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    ref: str  # what is passed to trivy
    repo: str
    tag: str | None = None
    digest: str | None = None

    @property
    def key(self) -> str:
        """Cache and dedupe key."""
        return self.digest or self.ref


def registry_host(image: ImageRef) -> str:
    """The registry host of ``image``, e.g. ``docker.io`` or ``registry.example:5000``, from its normalised repo."""
    return image.repo.split("/", 1)[0]


class Workload(BaseModel):
    model_config = ConfigDict(frozen=True)

    namespace: str
    kind: str
    name: str
    container: str
    owner: str | None = None
    team: str | None = None


class InventoryItem(BaseModel):
    image: ImageRef
    platform: str  # e.g. "linux/amd64"
    workloads: list[Workload] = []


class Finding(BaseModel):
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: Severity
    title: str | None = None
    primary_url: str | None = None
    target: str
    pkg_type: str

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)


class ImageResult(BaseModel):
    image: ImageRef
    platform: str
    status: Literal["ok", "error", "cached"]
    error_kind: Literal["auth", "not_found", "timeout", "trivy", "unknown"] | None = None
    error: str | None = None
    findings: list[Finding] = []
    os_family: str | None = None
