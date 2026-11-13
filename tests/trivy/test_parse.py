import json
from pathlib import Path

from kubedelos.models import Severity
from kubedelos.trivy.parse import parse_report

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def test_parse_alpine_counts():
    findings, os_family = parse_report(load("alpine.json"))
    assert os_family == "alpine"
    assert len(findings) == 26
    assert sum(f.severity == Severity.CRITICAL for f in findings) == 0
    assert sum(f.severity == Severity.HIGH for f in findings) == 6
    first = findings[0]
    assert first.vuln_id == "CVE-2025-15467"
    assert first.pkg_name == "libcrypto3"
    assert first.installed_version == "3.0.15-r0"
    assert first.fixed_version == "3.0.19-r0"
    assert first.primary_url == "https://avd.aquasec.com/nvd/cve-2025-15467"
    assert first.title


def test_parse_empty_results():
    findings, os_family = parse_report(load("distroless_empty.json"))
    assert findings == []
    assert os_family == "debian"
    findings, os_family = parse_report(load("null_results.json"))
    assert findings == []
    assert os_family is None


def test_parse_multi_target_sets_target_and_pkg_type():
    findings, os_family = parse_report(load("multi_target.json"))
    assert os_family == "debian"
    assert len(findings) == 24
    os_findings = [f for f in findings if f.pkg_type == "debian"]
    lang_findings = [f for f in findings if f.pkg_type == "python-pkg"]
    assert len(os_findings) == 18
    assert len(lang_findings) == 6
    assert {f.target for f in os_findings} == {"python:3.12-slim (debian 13.7)"}
    assert {f.target for f in lang_findings} == {"Python"}
    # debian "affected" vulnerabilities carry no FixedVersion
    assert all(f.fixed_version is None for f in os_findings)
    assert all(f.fixed_version for f in lang_findings)


def test_parse_unknown_severity_maps_to_unknown():
    data = {
        "Metadata": {},
        "Results": [
            {
                "Target": "t",
                "Type": "alpine",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "a", "InstalledVersion": "1", "Severity": "BOGUS"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "b", "InstalledVersion": "1", "FixedVersion": ""},
                ],
            }
        ],
    }
    findings, os_family = parse_report(data)
    assert os_family is None
    assert [f.severity for f in findings] == [Severity.UNKNOWN, Severity.UNKNOWN]
    assert [f.fixed_version for f in findings] == [None, None]
    assert findings[0].title is None
    assert findings[0].primary_url is None


def test_parse_result_without_vulnerabilities():
    data = {"Results": [{"Target": "a", "Type": "x", "Vulnerabilities": None}, {"Target": "b", "Type": "y"}]}
    assert parse_report(data) == ([], None)


def _report(cls):
    result = {"Target": "app", "Type": "jar", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "Severity": "HIGH"}
    ]}  # fmt: skip
    if cls is not None:
        result["Class"] = cls
    return {"Results": [result]}


def test_parse_records_pkg_class():
    findings, _ = parse_report(load("alpine.json"))
    assert {f.pkg_class for f in findings} == {"os"}
    assert parse_report(_report("lang-pkgs"))[0][0].pkg_class == "library"
    assert parse_report(_report(None))[0][0].pkg_class is None
    assert parse_report(_report("custom"))[0][0].pkg_class is None
