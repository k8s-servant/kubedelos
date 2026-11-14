"""Human hints shared by the CLI and the web UI, so that both tell the user the same thing.

Today that is how to log in to a registry whose images failed with an authentication error.
"""


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
