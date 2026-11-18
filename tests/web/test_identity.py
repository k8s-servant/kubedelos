import pytest

from kubedelos.web.identity import clean_identity


def test_clean_identity_strips_control_characters():
    assert clean_identity("a@example.com\r\nX-Evil: 1") == "a@example.comX-Evil: 1"


def test_clean_identity_caps_length():
    assert len(clean_identity("a" * 10_000)) == 256


@pytest.mark.parametrize("raw", [None, "", "   ", "\x00\x1b"])
def test_clean_identity_blank_means_none(raw):
    assert clean_identity(raw) is None


def test_clean_identity_keeps_unicode_names():
    assert clean_identity("  Jūratė@example.com ") == "Jūratė@example.com"
