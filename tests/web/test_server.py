import errno
import socket
import sys

import pytest
import uvicorn

from kubedelos.web import server


def test_bind_port_in_use_raises():
    first = server.bind("127.0.0.1", 0)
    try:
        port = first.getsockname()[1]
        with pytest.raises(server.PortInUse) as exc:
            server.bind("127.0.0.1", port)
        assert exc.value.port == port
    finally:
        first.close()


def test_url_forms():
    assert server.url("127.0.0.1", 9370, "tok") == "http://127.0.0.1:9370/?token=tok"
    assert server.url("::1", 9370, "tok") == "http://[::1]:9370/?token=tok"
    assert server.url("localhost", 9370, "tok") == "http://localhost:9370/?token=tok"


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6")
def test_bind_ipv6_loopback():
    sock = server.bind("::1", 0)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


def test_localhost_binds_the_ipv4_loopback():
    sock = server.bind("localhost", 0)
    try:
        assert sock.getsockname()[0] == "127.0.0.1"
    finally:
        sock.close()


def test_serve_turns_the_access_log_off_so_the_token_is_never_logged(monkeypatch):
    seen = {}

    class FakeServer:
        def __init__(self, config):
            seen["config"] = config

        def run(self, sockets=None):
            seen["sockets"] = sockets

    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    sentinel = object()
    server.serve(object(), sentinel)  # type: ignore[arg-type]
    assert seen["config"].access_log is False
    assert seen["config"].workers == 1
    assert seen["sockets"] == [sentinel]


def test_bind_detects_a_wildcard_listener_on_the_same_port():
    wildcard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        wildcard.bind(("0.0.0.0", 0))  # noqa: S104 - the point of the test
        wildcard.listen()
        port = wildcard.getsockname()[1]
        with pytest.raises(server.PortInUse):
            server.bind("127.0.0.1", port)
    finally:
        wildcard.close()


def test_bind_reuses_a_port_left_in_time_wait():
    first = server.bind("127.0.0.1", 0)
    port = first.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    conn, _ = first.accept()
    # Closing the server side first leaves its end of the connection in TIME_WAIT.
    conn.close()
    first.close()
    client.close()
    again = server.bind("127.0.0.1", port)
    again.close()


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="the probe runs on macOS/BSD only")
@pytest.mark.parametrize("result", [errno.ETIMEDOUT, errno.EHOSTUNREACH, 0])
def test_bind_treats_an_unclear_probe_as_in_use(monkeypatch, result):
    monkeypatch.setattr(server, "_probe", lambda family, address, port: result)
    with pytest.raises(server.PortInUse):
        server.bind("127.0.0.1", 9370)
