"""Fixtures for every test: the threat feeds are off, so no test downloads CISA KEV or EPSS.

A test of the feeds turns them on itself and hands ``threatintel`` a client over ``httpx.MockTransport``.
"""

import pytest


@pytest.fixture(autouse=True)
def _no_threat_feeds(monkeypatch):
    monkeypatch.setenv("KUBEDELOS_THREAT_FEEDS", "false")
