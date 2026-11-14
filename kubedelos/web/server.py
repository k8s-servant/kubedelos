"""The loopback socket and the uvicorn server behind ``kubedelos ui``.

The socket is bound here, before the URL is printed, so a busy port is reported cleanly and the browser never opens
on a dead address. uvicorn's own access log is off because it prints the full request target, ``?token=`` included.
"""

import errno
import socket
import sys

import uvicorn
from fastapi import FastAPI

# Each accepted --host value and the address it binds. "localhost" binds IPv4 so the printed URL always works.
LOOPBACK = {"127.0.0.1": "127.0.0.1", "::1": "::1", "localhost": "127.0.0.1"}


class PortInUse(Exception):
    def __init__(self, port: int) -> None:
        super().__init__(f"port {port} is in use")
        self.port = port


def _probe(family: int, address: str, port: int) -> int:
    """The errno of a short TCP connect to ``address:port`` (0 when something accepted it)."""
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        return probe.connect_ex((address, port))


def bind(host: str, port: int) -> socket.socket:
    """A listening socket on the loopback address for ``host``."""
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        # SO_REUSEADDR skips TIME_WAIT, so a restart works. On macOS/BSD it also lets this bind succeed beside a
        # 0.0.0.0 listener, so probe first: the port counts as free only when the connect is refused outright (as
        # TIME_WAIT is); an answer, a timeout or any other error counts as in use.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probed = port and not sys.platform.startswith("linux")  # port 0 asks the OS for a free one
        if probed and _probe(family, LOOPBACK[host], port) != errno.ECONNREFUSED:
            raise PortInUse(port)
        sock.bind((LOOPBACK[host], port))
        sock.listen()
    except OSError as exc:
        sock.close()
        if exc.errno == errno.EADDRINUSE:
            raise PortInUse(port) from exc
        raise
    return sock


def url(host: str, port: int, token: str) -> str:
    """The address to open, with the startup token."""
    shown = f"[{host}]" if host == "::1" else host
    return f"http://{shown}:{port}/?token={token}"


def serve(app: FastAPI, sock: socket.socket) -> None:
    """Run ``app`` on ``sock`` until Ctrl-C (uvicorn handles the signal)."""
    config = uvicorn.Config(app, workers=1, access_log=False, log_level="warning", lifespan="off")
    uvicorn.Server(config).run(sockets=[sock])
