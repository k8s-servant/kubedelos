"""Run the CLI with ``python -m kubedelos``, the same entry point as the ``kubedelos`` console script.

An MCP client can then start the server with the interpreter it already has, without finding the script on PATH.
"""

from kubedelos.cli import app

app()
