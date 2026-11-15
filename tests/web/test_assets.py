"""Tests for the vendored front-end assets: the htmx file on disk is the one whose SHA-256 was pinned."""

import hashlib
from pathlib import Path

from kubedelos.web import assets

STATIC = Path(assets.__file__).parent / "static"


def test_htmx_matches_its_pinned_sha256():
    data = (STATIC / "htmx.min.js").read_bytes()
    assert hashlib.sha256(data).hexdigest() == assets.HTMX_SHA256
    assert f'version:"{assets.HTMX_VERSION}"' in data.decode()


def test_htmx_version_is_pinned():
    assert assets.HTMX_VERSION == "2.0.4"
