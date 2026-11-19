"""The read-only MCP server behind ``kubedelos mcp``.

It lets an engineer's own agent query the local scan database (clusters, runs, findings, attack-surface facts) over
stdio. It never writes the database, never loads a kubeconfig and never calls an LLM or the network.
"""
