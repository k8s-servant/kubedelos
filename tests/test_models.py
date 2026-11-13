from kubedelos.models import Finding, ImageRef, Severity


def test_severity_rank_order():
    assert [s.rank for s in Severity] == [4, 3, 2, 1, 0]


def test_imageref_key_prefers_digest():
    with_digest = ImageRef(ref="nginx:1.25", repo="nginx", tag="1.25", digest="sha256:abc")
    assert with_digest.key == "sha256:abc"
    without = ImageRef(ref="nginx:1.25", repo="nginx", tag="1.25", digest=None)
    assert without.key == "nginx:1.25"


def _finding(fixed):
    return Finding(
        vuln_id="CVE-1",
        pkg_name="p",
        installed_version="1.0",
        fixed_version=fixed,
        severity=Severity.HIGH,
        title=None,
        primary_url=None,
        target="t",
        pkg_type="os",
    )


def test_finding_fixable():
    assert _finding("").fixable is False
    assert _finding(None).fixable is False
    assert _finding("1.2").fixable is True
