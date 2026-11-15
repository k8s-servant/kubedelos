"""The vendored front-end assets, pinned by version and SHA-256 so a test notices any change to the file on disk.

``static/htmx.min.js`` is htmx 2.0.4, taken unmodified from ``package/dist/htmx.min.js`` in the npm tarball
``https://registry.npmjs.org/htmx.org/-/htmx.org-2.0.4.tgz``. Before extracting it, the tarball's SHA-512 was checked
against the registry's ``dist.integrity``
(``sha512-HLxMCdfXDOJirs3vBZl/ZLoY+c7PfM4Ahr2Ad4YXh6d22T5ltbTXFFkpx9Tgb2vvmWFMbIc3LqN2ToNkZJvyYQ==``). htmx is under
the Zero-Clause BSD licence (``"license": "0BSD"`` in the package's ``package.json``), which asks for no notice.

The file has no trailing newline, so the pre-commit hooks that rewrite whitespace skip it. The scans page loads it with
the CSP nonce and configures it to inject no styles and to evaluate nothing, so the CSP stays as it is.
"""

HTMX_VERSION = "2.0.4"
HTMX_SHA256 = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"
