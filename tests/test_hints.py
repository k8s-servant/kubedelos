"""Tests for kubedelos.hints: one case per registry family."""

import pytest

from kubedelos.hints import login_hint


@pytest.mark.parametrize(
    ("host", "command"),
    [
        ("myreg.azurecr.io", "az acr login --name myreg"),
        ("gcr.io", "gcloud auth configure-docker gcr.io"),
        ("eu.gcr.io", "gcloud auth configure-docker eu.gcr.io"),
        ("europe-docker.pkg.dev", "gcloud auth configure-docker europe-docker.pkg.dev"),
        ("123456789012.dkr.ecr.eu-west-1.amazonaws.com", "--region eu-west-1"),
        ("registry.example.com", "docker login registry.example.com"),
        ("registry.example.com:5000", "docker login registry.example.com:5000"),
    ],
)
def test_login_hint_per_registry(host, command):
    hint = login_hint(host)
    assert command in hint
    assert hint.startswith(f"log in to {host} first")
    assert hint.endswith("kubedelos uses the same Docker credentials")


def test_login_hints_for_refs_name_each_registry_once():
    from kubedelos.hints import login_hint, login_hints_for

    refs = ["reg.example.com/a:1", "reg.example.com/b@sha256:" + "a" * 64, "myacr.azurecr.io/x:2"]
    assert login_hints_for(refs) == [login_hint("myacr.azurecr.io"), login_hint("reg.example.com")]
    assert login_hints_for([]) == []
