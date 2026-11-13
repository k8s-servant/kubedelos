"""The Trivy release kubedelos runs, with the SHA-256 of each supported platform's tarball.

The hashes below were copied from ``trivy_0.76.1_checksums.txt`` only after its Sigstore bundle
verified (cosign v3.1.4, 2026-11-13):

    cosign verify-blob \\
      --bundle trivy_0.76.1_checksums.txt.sigstore.json \\
      --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/\\.github/workflows/' \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
      trivy_0.76.1_checksums.txt
    Verified OK

Signing identity: https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.1
Each tarball was also downloaded and its SHA-256 recomputed locally; all four matched.

To bump the version, repeat that verification for the new release and replace every value here.
Never fill these from an unverified checksums file.
"""

TRIVY_VERSION = "0.76.1"

# (os, arch) -> (release asset filename, SHA-256 of that asset)
ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("linux", "amd64"): (
        "trivy_0.76.1_Linux-64bit.tar.gz",
        "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
    ),
    ("linux", "arm64"): (
        "trivy_0.76.1_Linux-ARM64.tar.gz",
        "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    ),
    ("darwin", "amd64"): (
        "trivy_0.76.1_macOS-64bit.tar.gz",
        "7aa762eacd582052d053b62dcf972a1ab058abe39a57ccae234ed8894945b6b7",
    ),
    ("darwin", "arm64"): (
        "trivy_0.76.1_macOS-ARM64.tar.gz",
        "11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5",
    ),
}
