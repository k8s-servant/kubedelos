import pytest

from kubedelos.kube.inventory import parse_image_id
from kubedelos.models import Finding, ImageRef, Severity, is_digest, is_valid_ref, registry_host

D = "sha256:" + "a" * 64


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


@pytest.mark.parametrize(
    "ref",
    ["ghcr.io/a/b:1", f"localhost:5000/x@{D}", "docker.io/library/nginx:1.19", "nginx", "localhost/app",
     f"reg.io/app:1.2@{D}", "reg.io/my_team/app__x:v1-rc.1", "MyRegistry.example.com/app:1",
     "reg.example.com/a__b:1", "a--b.example.com/x:1", "[::1]:5000/app:1", f"reg.example.com/app@sha512:{'b' * 128}",
     "reg.example.com/app@sha256:" + "A" * 64],
)  # fmt: skip
def test_is_valid_ref_accepts(ref):
    assert is_valid_ref(ref)


@pytest.mark.parametrize(
    "ref",
    ["-oyaml", "nginx --help", "nginx:1\n", "nginx\n:1", "reg.io/" + "a" * 520, "", "Reg.io/App:1", "nginx\t",
     "a/-b", "nginx:-tag", f"nginx@{D}\n", "nginx@sha256:abc", "nginx:" + "t" * 129, "nginx\x00",
     "reg.example.com/App:1", "[::1/app:1", "-reg.example.com/app:1", "reg.example.com/app@sha256:" + "g" * 64,
     "reg.example.com/app@:" + "a" * 64],
)  # fmt: skip
def test_is_valid_ref_rejects(ref):
    assert not is_valid_ref(ref)


def test_is_digest_rejects_trailing_newline():
    assert is_digest(D)
    assert not is_digest(D + "\n")


@pytest.mark.parametrize("image", ["nginx", "library/nginx:1.19", "docker.io/library/nginx"])
def test_registry_host_of_short_names(image):
    assert registry_host(parse_image_id(image, "")) == "docker.io"


def test_registry_host_keeps_port():
    assert registry_host(parse_image_id("registry.example:5000/team/app:1", "")) == "registry.example:5000"
