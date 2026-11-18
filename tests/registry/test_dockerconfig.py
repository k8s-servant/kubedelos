"""Tests for kubedelos.registry.dockerconfig: parsing, merging and writing docker config files."""

import json
import logging
import os
import stat

import pytest

from kubedelos.registry import dockerconfig


def _cfg(**auths) -> bytes:
    return json.dumps({"auths": auths}).encode()


def test_parse_keeps_only_auths():
    raw = json.dumps(
        {
            "auths": {"registry.example.com": {"auth": "abc"}},
            "credHelpers": {"registry.example.com": "ecr-login"},
            "credsStore": "desktop",
            "HttpHeaders": {"User-Agent": "x"},
        }
    ).encode()
    assert dockerconfig.parse(raw) == {"registry.example.com": {"auth": "abc"}}


def test_parse_drops_entries_without_credentials():
    raw = _cfg(
        **{
            "a.example.com": {"email": "x"},
            "b.example.com": {"username": "u"},
            "c.example.com": {"username": "u", "password": "p"},
            "d.example.com": {"auth": 5},
            "e.example.com": "nope",
        }
    )
    assert dockerconfig.parse(raw) == {"c.example.com": {"username": "u", "password": "p"}}


def test_docker_hub_keys_normalise(tmp_path):
    for key in ("index.docker.io", "registry-1.docker.io", "https://index.docker.io/v1/", "docker.io"):
        assert dockerconfig.normalise_host(key) == "docker.io"
        assert dockerconfig.parse(_cfg(**{key: {"auth": "abc"}})) == {"docker.io": {"auth": "abc"}}
    with dockerconfig.temp_config(tmp_path, {"docker.io": {"auth": "abc"}}) as directory:
        written = json.loads((directory / "config.json").read_text())
    assert written == {"auths": {"https://index.docker.io/v1/": {"auth": "abc"}}}


def test_host_with_port_kept():
    assert dockerconfig.normalise_host("https://Registry.Example.com:5000/v2/") == "registry.example.com:5000"
    assert dockerconfig.parse(_cfg(**{"registry.example.com:5000": {"auth": "a"}})) == {
        "registry.example.com:5000": {"auth": "a"}
    }


def test_first_mounted_config_wins(tmp_path):
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    first.write_bytes(_cfg(**{"registry.example.com": {"auth": "first"}}))
    second.write_bytes(_cfg(**{"registry.example.com": {"auth": "second"}, "other.example.com": {"auth": "o"}}))
    assert dockerconfig.load_mounted([first, second]) == {
        "registry.example.com": {"auth": "first"},
        "other.example.com": {"auth": "o"},
    }


def test_bad_mounted_config_skipped(tmp_path, caplog):
    empty, junk, good = tmp_path / "empty.json", tmp_path / "junk.json", tmp_path / "good.json"
    empty.write_bytes(b"")
    junk.write_bytes(b"not json s3cr3t")
    good.write_bytes(_cfg(**{"registry.example.com": {"auth": "a"}}))
    missing = tmp_path / "missing.json"
    with caplog.at_level(logging.WARNING):
        auths = dockerconfig.load_mounted([missing, empty, junk, good])
    assert auths == {"registry.example.com": {"auth": "a"}}
    for path in (missing, empty, junk):
        assert str(path) in caplog.text
    assert "s3cr3t" not in caplog.text and "not json" not in caplog.text


def test_for_host_returns_only_that_host():
    auths = {"a.example.com": {"auth": "a"}, "b.example.com": {"auth": "b"}}
    assert dockerconfig.for_host(auths, "a.example.com") == {"a.example.com": {"auth": "a"}}
    assert dockerconfig.for_host(auths, "c.example.com") == {}


def test_temp_config_modes_and_removal(tmp_path):
    with dockerconfig.temp_config(tmp_path, {"registry.example.com": {"auth": "a"}}) as directory:
        assert directory.parent == tmp_path
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(directory / "config.json").st_mode) == 0o600
        assert json.loads((directory / "config.json").read_text()) == {"auths": {"registry.example.com": {"auth": "a"}}}
    assert not directory.exists()


def test_temp_config_removed_on_exception(tmp_path):
    with (
        pytest.raises(RuntimeError),
        dockerconfig.temp_config(tmp_path, {"registry.example.com": {"auth": "a"}}) as directory,
    ):
        raise RuntimeError("boom")
    assert not directory.exists()


def test_clear_empties_dir_keeps_it(tmp_path):
    (tmp_path / "kubedelos-docker-sub").mkdir()
    (tmp_path / "kubedelos-docker-sub" / "config.json").write_text("{}")
    dockerconfig.clear(tmp_path)
    assert tmp_path.is_dir() and list(tmp_path.iterdir()) == []
    dockerconfig.clear(tmp_path / "absent")


def test_parse_error_message_has_no_content():
    with pytest.raises(ValueError) as info:
        dockerconfig.parse(b'{"auths": {"x": s3cr3t')
    assert "s3cr3t" not in str(info.value)
    with pytest.raises(ValueError):
        dockerconfig.parse(b'["not an object"]')


def test_clear_removes_only_its_own_directories(tmp_path, caplog):
    ours = tmp_path / "kubedelos-docker-abc"
    ours.mkdir()
    (ours / "config.json").write_text("{}")
    db = tmp_path / "kubedelos.db"
    db.write_text("data")
    other = tmp_path / "keep-me"
    other.mkdir()
    dockerconfig.clear(tmp_path)
    assert not ours.exists()
    assert db.read_text() == "data" and other.is_dir()


def test_clear_warns_and_goes_on_when_an_entry_cannot_be_removed(tmp_path, monkeypatch, caplog):
    bad, good = tmp_path / "kubedelos-docker-bad", tmp_path / "kubedelos-docker-good"
    bad.mkdir()
    good.mkdir()
    real = dockerconfig.shutil.rmtree

    def rmtree(path, *a, **kw):
        if path == bad:
            raise PermissionError("no")
        real(path, *a, **kw)

    monkeypatch.setattr(dockerconfig.shutil, "rmtree", rmtree)
    with caplog.at_level("WARNING"):
        dockerconfig.clear(tmp_path)
    assert not good.exists() and bad.exists()
    assert "kubedelos-docker-bad" in caplog.text


def test_temp_config_directory_has_the_fixed_prefix(tmp_path):
    with dockerconfig.temp_config(tmp_path, {}) as directory:
        assert directory.name.startswith("kubedelos-docker-")
