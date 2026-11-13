"""Turn a Trivy JSON report into findings."""

from typing import Any, Literal

from kubedelos.models import Finding, Severity


def _severity(raw: object) -> Severity:
    try:
        return Severity(str(raw).upper())
    except ValueError:
        return Severity.UNKNOWN


_PKG_CLASS: dict[str, Literal["os", "library"]] = {"os-pkgs": "os", "lang-pkgs": "library"}


def parse_report(data: dict[str, Any]) -> tuple[list[Finding], str | None]:
    """Return ``(findings, os_family)``.

    Images with no packages Trivy understands (distroless, scratch) report ``Results`` as null or
    results without ``Vulnerabilities``; both yield no findings.
    """
    os_family = ((data.get("Metadata") or {}).get("OS") or {}).get("Family") or None
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        pkg_type = result.get("Type", "")
        pkg_class = _PKG_CLASS.get(result.get("Class", ""))
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    vuln_id=vuln["VulnerabilityID"],
                    pkg_name=vuln["PkgName"],
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion") or None,
                    severity=_severity(vuln.get("Severity")),
                    title=vuln.get("Title") or None,
                    primary_url=vuln.get("PrimaryURL") or None,
                    target=target,
                    pkg_type=pkg_type,
                    pkg_class=pkg_class,
                )
            )
    return findings, os_family
