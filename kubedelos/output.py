"""Render finding rows (as returned by ``Repo.run_findings``) as a table, JSON, CSV or SARIF."""

import csv
import io
import json
from collections.abc import Mapping, Sequence
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from kubedelos import __version__

Row = Mapping[str, Any]

CSV_COLUMNS = [
    "namespace", "kind", "workload", "container", "image", "vuln_id", "severity", "pkg_name", "pkg_class",
    "installed_version", "fixed_version", "owner", "team",
]  # fmt: skip
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}


def _plain(rows: Sequence[Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def _table_image(r: Row) -> str:
    """``repo:tag`` plus a short digest: what people recognise, where the full ref is 64 hex characters long."""
    if not r["repo"]:
        return r["image"]
    name = f"{r['repo']}:{r['tag']}" if r["tag"] else r["repo"]
    return f"{name}@{r['digest'][:15]}" if r["digest"] else name  # "sha256:" + 8 hex


def render_table(rows: Sequence[Row]) -> str:
    table = Table()
    for col in ("Namespace/Workload", "Image", "Vulnerability", "Severity", "Installed", "Fixed"):
        table.add_column(col, overflow="fold")
    for r in rows:
        cells = (
            f"{r['namespace']}/{r['workload']}",
            _table_image(r),
            r["vuln_id"],
            r["severity"],
            r["installed_version"],
            r["fixed_version"] or "",
        )
        table.add_row(
            *(Text("" if c is None else str(c)) for c in cells)
        )  # Text, not str: cluster-controlled values must not be parsed as markup
    buf = io.StringIO()
    Console(file=buf, color_system=None, force_terminal=False, width=160).print(table)
    return buf.getvalue()


def render_json(rows: Sequence[Row]) -> str:
    return json.dumps(_plain(rows), indent=2)


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formulas (CWE-1236) in cells that come from cluster and Trivy data."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_csv(rows: Sequence[Row]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for r in rows:
        writer.writerow([_csv_safe(r[c]) for c in CSV_COLUMNS])
    return buf.getvalue()


def render_sarif(rows: Sequence[Row]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for r in rows:
        level = _SARIF_LEVEL.get(r["severity"], "note")
        rule = rules.setdefault(
            r["vuln_id"],
            {
                "id": r["vuln_id"],
                "shortDescription": {"text": r["title"] or r["vuln_id"]},
                "defaultConfiguration": {"level": level},
            },
        )
        if r["primary_url"]:
            rule["helpUri"] = r["primary_url"]
        fixed = r["fixed_version"] or "none"
        results.append(
            {
                "ruleId": r["vuln_id"],
                "level": level,
                "message": {
                    "text": f"{r['pkg_name']} {r['installed_version']} is vulnerable (fixed: {fixed}) "
                    f"in {r['namespace']}/{r['workload']}"
                },
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["image"]}}}],
                "properties": {"namespace": r["namespace"], "workload": r["workload"], "severity": r["severity"]},
            }
        )
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "kubedelos", "version": __version__, "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


RENDERERS = {"table": render_table, "json": render_json, "csv": render_csv, "sarif": render_sarif}
