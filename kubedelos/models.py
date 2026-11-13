"""Domain models shared by inventory, scanning and storage."""

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def is_digest(value: str) -> bool:
    """True only for a complete ``sha256:<64 lowercase hex>`` digest."""
    return _DIGEST_RE.fullmatch(value) is not None


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
