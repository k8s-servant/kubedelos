"""Run the CLI with ``python -m kubedelos``, the same entry point as the ``kubedelos`` console script.

The guard keeps a plain import of this module (by a tool that walks the package, say) from running the CLI.
"""

from kubedelos.cli import app

if __name__ == "__main__":
    app()
