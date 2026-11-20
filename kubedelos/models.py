"""Domain models shared by inventory, scanning and storage."""

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

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


class ImageRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    ref: str  # what is passed to trivy
    repo: str
    tag: str | None = None
    digest: str | None = None
    # The node's local image ID (a hash of the image config) when the runtime reports no registry digest, as kind does
    # for its preloaded images. It names the content the pod runs, so a scan of exactly that content can be cached.
    image_id: str | None = None

    @property
    def key(self) -> str:
        """Dedupe and storage key."""
        return self.digest or self.ref

    @property
    def cache_key(self) -> str | None:
        """The result cache key, or None when only a tag names the image: a tag can be pushed again."""
        if self.digest:
            return self.digest
        return f"image-id@{self.image_id}" if self.image_id else None


def registry_host(image: ImageRef) -> str:
    """The registry host of ``image``, e.g. ``docker.io`` or ``registry.example:5000``, from its normalised repo."""
    return image.repo.split("/", 1)[0]


Tri = bool | None  # None means unknown


class Workload(BaseModel):
    model_config = ConfigDict(frozen=True)

    namespace: str
    kind: str
    name: str
    container: str
    owner: str | None = None
    team: str | None = None


class HostPath(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    read_only: bool


class PodSecurity(BaseModel):
    """What a workload's pod spec lets its containers do on the node; None means the spec did not say."""

    model_config = ConfigDict(frozen=True)

    privileged: bool
    allow_privilege_escalation: bool
    runs_as_root: Tri
    read_only_root_fs: bool
    added_capabilities: tuple[str, ...] = ()
    host_network: bool
    host_pid: bool
    host_ipc: bool
    host_path_volumes: tuple[HostPath, ...] = ()
    service_account: str
    automount_token: Tri
    secret_refs: tuple[str, ...] = ()  # names only, never contents


class ExposedService(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    type: str
    internal_lb: bool = False


class Exposure(BaseModel):
    """How far the workload is reachable from outside its pod."""

    model_config = ConfigDict(frozen=True)

    level: Literal["external", "cluster", "none", "unknown"]
    services: tuple[ExposedService, ...] = ()
    external_ips: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    host_ports: tuple[int, ...] = ()  # the container's hostPorts: reachable on the node's IP


class Network(BaseModel):
    """Whether NetworkPolicies isolate the workload's pods; None means unknown."""

    model_config = ConfigDict(frozen=True)

    ingress_isolated: Tri
    egress_isolated: Tri
    ingress_policies: tuple[str, ...] = ()
    egress_policies: tuple[str, ...] = ()


class Rights(BaseModel):
    """What the workload's service account may do through RBAC; ``status`` says how far that could be worked out."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok", "partial", "unknown", "off"]
    cluster_admin: bool = False
    reads_secrets: bool = False
    reads_secrets_scope: Literal["cluster"] | tuple[str, ...] | None = None  # "cluster" or the namespaces
    creates_workloads: bool = False
    pod_exec: bool = False
    escalates: bool = False
    wildcard: bool = False
    bindings: tuple[str, ...] = ()  # "ClusterRoleBinding/<name>" or "RoleBinding/<ns>/<name>"


class WorkloadFacts(BaseModel):
    """The attack-surface facts of one workload, stored as versioned JSON (``v``) on its workload row."""

    model_config = ConfigDict(frozen=True)

    v: Literal[1] = 1
    pod: PodSecurity
    exposure: Exposure
    network: Network
    rights: Rights


def parse_facts(text: str | None) -> WorkloadFacts | None:
    """The facts stored on a workload row, or None for NULL, invalid JSON, a validation error or another version."""
    if not text:
        return None
    try:
        facts = WorkloadFacts.model_validate_json(text)
    except ValidationError:
        return None
    return facts if facts.v == 1 else None


FactSources = dict[str, str]  # fact source name -> status, per run


class InventoryItem(BaseModel):
    image: ImageRef
    platform: str  # e.g. "linux/amd64"
    workloads: list[Workload] = []
    pull_secrets: list[tuple[str, str]] = []  # (namespace, name) of the imagePullSecrets pods name, first seen first
    facts: dict[Workload, WorkloadFacts] = {}


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
    pkg_class: Literal["os", "library"] | None = None  # from Trivy's result Class; None for unknown or old rows

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
    scanned_image_id: str | None = None  # Trivy's Metadata.ImageID: the config hash of the image it actually scanned
    duration_s: float | None = None  # wall time of this image's scan, retry included; None for a cached result
