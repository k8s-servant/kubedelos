import json
import logging
import threading
import time

from kubernetes.client import V1ObjectMeta, V1Secret
from urllib3.exceptions import ReadTimeoutError

from kubedelos.registry.dockerconfig import normalise_host
from kubedelos.registry.pullsecrets import PullSecrets
from tests.kube.fakes import FakeKubeApi, secret


def _config(host: str, user: str = "u", password: str = "p-sentinel") -> bytes:  # noqa: S107
    return json.dumps({"auths": {host: {"username": user, "password": password}}}).encode()


def _docker(ns, name, host="registry.example.com"):
    return secret(name, ns, {".dockerconfigjson": _config(host)})


def test_auths_for_returns_the_entry_of_the_image_host():
    api = FakeKubeApi(secrets={("web", "regcred"): _docker("web", "regcred")})
    got = PullSecrets(api, ["web"]).auths_for([("web", "regcred")], "registry.example.com")
    assert got == {"registry.example.com": {"username": "u", "password": "p-sentinel"}}


def test_only_the_image_host_is_kept():
    raw = json.dumps(
        {"auths": {"registry.example.com": {"auth": "YTpi"}, "other.example.com": {"auth": "Yzpk"}}}
    ).encode()
    api = FakeKubeApi(secrets={("web", "regcred"): secret("regcred", "web", {".dockerconfigjson": raw})})
    got = PullSecrets(api, ["web"]).auths_for([("web", "regcred")], "registry.example.com")
    assert list(got) == ["registry.example.com"]
    assert PullSecrets(api, ["web"]).auths_for([("web", "regcred")], "nothing.example.com") == {}


def test_docker_hub_host_matches_its_config_spelling():
    api = FakeKubeApi(secrets={("web", "hub"): _docker("web", "hub", "https://index.docker.io/v1/")})
    got = PullSecrets(api, ["web"]).auths_for([("web", "hub")], "docker.io")
    assert list(got) == [normalise_host("docker.io")]


def test_first_ref_wins():
    api = FakeKubeApi(
        secrets={
            ("web", "a"): secret("a", "web", {".dockerconfigjson": _config("registry.example.com", "first")}),
            ("web", "b"): secret("b", "web", {".dockerconfigjson": _config("registry.example.com", "second")}),
        }
    )
    got = PullSecrets(api, ["web"]).auths_for([("web", "a"), ("web", "b")], "registry.example.com")
    assert got["registry.example.com"]["username"] == "first"


def test_non_docker_secret_dropped_unread(caplog):
    class Booby(V1Secret):
        @property
        def data(self):
            raise AssertionError("data of a non docker secret was read")

        @data.setter
        def data(self, value):
            pass

    opaque = Booby(metadata=V1ObjectMeta(name="tok", namespace="web"), type="Opaque")
    api = FakeKubeApi(secrets={("web", "tok"): opaque})
    with caplog.at_level(logging.DEBUG):
        assert PullSecrets(api, ["web"]).auths_for([("web", "tok")], "registry.example.com") == {}
    assert caplog.records == []  # dropped silently: not even its name is logged


def test_missing_or_forbidden_secret_is_skipped(caplog):
    api = FakeKubeApi(secret_status={("web", "regcred"): 403})
    with caplog.at_level(logging.DEBUG, logger="kubedelos.registry.pullsecrets"):
        pulls = PullSecrets(api, ["web"])
        assert pulls.auths_for([("web", "regcred"), ("web", "gone")], "registry.example.com") == {}
    assert "web/regcred" in caplog.text and "web/gone" in caplog.text
    assert "p-sentinel" not in caplog.text


def test_bad_content_is_skipped_without_logging_it(caplog):
    api = FakeKubeApi(
        secrets={
            ("web", "junk"): secret("junk", "web", {".dockerconfigjson": b"{not json p-sentinel"}),
            ("web", "empty"): secret("empty", "web", {}),
            ("web", "nodata"): secret("nodata", "web", None),
        }
    )
    with caplog.at_level(logging.DEBUG, logger="kubedelos.registry.pullsecrets"):
        got = PullSecrets(api, ["web"]).auths_for(
            [("web", "junk"), ("web", "empty"), ("web", "nodata")], "registry.example.com"
        )
    assert got == {}
    assert "web/junk" in caplog.text and "p-sentinel" not in caplog.text


def test_secret_read_once_per_run():
    api = FakeKubeApi(secrets={("web", "regcred"): _docker("web", "regcred")})
    pulls = PullSecrets(api, ["web"])
    pulls.auths_for([("web", "regcred")], "registry.example.com")
    pulls.auths_for([("web", "regcred")], "other.example.com")
    assert api.secret_reads == [("web", "regcred")]


def test_unlisted_namespace_never_read():
    api = FakeKubeApi(secrets={("jobs", "regcred"): _docker("jobs", "regcred")})
    assert PullSecrets(api, ["web"]).auths_for([("jobs", "regcred")], "registry.example.com") == {}
    assert PullSecrets(api, []).auths_for([("jobs", "regcred")], "registry.example.com") == {}
    assert api.secret_reads == []


def test_pull_secrets_from_two_namespaces():
    api = FakeKubeApi(
        secrets={
            ("web", "a"): _docker("web", "a", "one.example.com"),
            ("ops", "b"): _docker("ops", "b", "two.example.com"),
        }
    )
    pulls = PullSecrets(api, ["web", "ops"])
    assert list(pulls.auths_for([("web", "a"), ("ops", "b")], "two.example.com")) == ["two.example.com"]
    assert list(pulls.auths_for([("web", "a"), ("ops", "b")], "one.example.com")) == ["one.example.com"]


def test_server_error_and_transport_error_are_skipped_not_cached(caplog):
    api = FakeKubeApi(
        secrets={("web", "ok"): _docker("web", "ok")},
        secret_status={("web", "busy"): 500, ("web", "slow"): 429},
        secret_errors={("web", "down"): ReadTimeoutError(None, "https://api.example.com", "timed out")},
    )
    pulls = PullSecrets(api, ["web"])
    refs = [("web", "busy"), ("web", "slow"), ("web", "down"), ("web", "ok")]
    with caplog.at_level(logging.DEBUG, logger="kubedelos.registry.pullsecrets"):
        got = pulls.auths_for(refs, "registry.example.com")
    assert list(got) == ["registry.example.com"]  # the readable Secret after the failures still counts
    for name in ("busy", "slow", "down"):
        assert f"web/{name}" in caplog.text
    assert "HTTP 500" in caplog.text and "ReadTimeoutError" in caplog.text
    api.secrets[("web", "busy")] = _docker("web", "busy", "other.example.com")
    api.secret_status.clear()
    assert list(pulls.auths_for([("web", "busy")], "other.example.com")) == ["other.example.com"]  # retried


def test_plain_os_error_is_skipped():
    api = FakeKubeApi(secret_errors={("web", "a"): OSError("connection reset")})
    assert PullSecrets(api, ["web"]).auths_for([("web", "a")], "registry.example.com") == {}


def test_concurrent_workers_read_a_secret_once():
    api = FakeKubeApi(secrets={("web", "regcred"): _docker("web", "regcred")})
    real = api.read_secret

    def slow(ns, name):
        time.sleep(0.2)
        return real(ns, name)

    api.read_secret = slow
    pulls = PullSecrets(api, ["web"])
    got = []
    threads = [
        threading.Thread(target=lambda: got.append(pulls.auths_for([("web", "regcred")], "registry.example.com")))
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert api.secret_reads == [("web", "regcred")]
    assert len(got) == 2 and got[0] == got[1] != {}
