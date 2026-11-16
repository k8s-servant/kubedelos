"""Human hints shared by the CLI and the web UI, so that both tell the user the same thing.

Today that is how to log in to a registry whose images failed with an authentication error.
"""

from collections.abc import Iterable

from kubedelos.kube.inventory import parse_image_id
from kubedelos.models import registry_host


def login_hint(host: str) -> str:
    """How to log in to ``host`` so that Docker, and with it kubedelos, can read it."""
    name = host.split(":", 1)[0]
    if name.endswith(".azurecr.io"):
        command = f"az acr login --name {name.split('.', 1)[0]}"
    elif name == "gcr.io" or name.endswith((".gcr.io", "-docker.pkg.dev")):
        command = f"gcloud auth configure-docker {host}"
    elif ".dkr.ecr." in name and name.endswith(".amazonaws.com"):
        region = name.split(".dkr.ecr.", 1)[1].removesuffix(".amazonaws.com")
        command = f"aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {host}"
    else:
        command = f"docker login {host}"
    return f"log in to {host} first, e.g. `{command}`; kubedelos uses the same Docker credentials"


def login_hints_for(refs: Iterable[str]) -> list[str]:
    """One login hint per registry of ``refs`` (image refs that failed auth), sorted by registry."""
    return [login_hint(host) for host in sorted({registry_host(parse_image_id(ref, "")) for ref in refs})]
