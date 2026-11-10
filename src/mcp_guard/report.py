"""Output formats: human text, JSON, and SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import List

from . import __version__
from .model import Finding, Severity
from .rules import RULES
from .scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def render_text(result: ScanResult, findings: List[Finding], color: bool) -> str:
    def c(sev: Severity, text: str) -> str:
        return f"{_COLORS[sev]}{text}{_RESET}" if color else text

    lines = [
        f"mcp-guard {__version__}: scanned {len(result.files)} file(s), "
        f"{len(result.servers)} server(s), {len(result.tools)} tool(s)",
        "",
    ]
    for err in result.errors:
        lines.append(f"  ! {err}")
    if result.errors:
        lines.append("")
    if not findings:
        lines.append("No findings at or above the selected severity. ✔")
        return "\n".join(lines)
    for f in findings:
        where = " / ".join(x for x in (f.server and f"server={f.server}", f.tool and f"tool={f.tool}") if x)
        lines.append(f"{c(f.severity, f.severity.label.upper()):<10} {f.rule_id}  {f.message}")
        lines.append(f"           {f.title}")
        lines.append(f"           at {os.path.relpath(f.source) if os.path.isabs(f.source) else f.source}"
                     + (f"  ({where})" if where else ""))
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
        if f.remediation:
            lines.append(f"           fix: {f.remediation}")
        lines.append("")
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in sorted(counts, reverse=True))
    lines.append(f"{len(findings)} finding(s): {summary}")
    return "\n".join(lines)


def render_json(result: ScanResult, findings: List[Finding]) -> str:
    return json.dumps(
        {
            "tool": "mcp-guard",
            "version": __version__,
            "files": result.files,
            "servers": len(result.servers),
            "tools": len(result.tools),
            "errors": result.errors,
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
        ensure_ascii=False,
    )


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_sarif(result: ScanResult, findings: List[Finding]) -> str:
    rules = [
        {
            "id": rid,
            "name": meta["title"],
            "shortDescription": {"text": meta["title"]},
            "fullDescription": {"text": meta["help"]},
            "helpUri": f"https://github.com/tulaneadam/mcp-guard#{rid.lower()}",
            "properties": {"tags": ["security", "mcp", "ai-agents"]},
        }
        for rid, meta in sorted(RULES.items())
    ]
    results = []
    for f in findings:
        uri = os.path.relpath(f.source) if os.path.isabs(f.source) else f.source
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message + (f" Fix: {f.remediation}" if f.remediation else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri.replace(os.sep, "/")}}}],
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "server": f.server,
                    "tool": f.tool,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-guard",
                        "version": __version__,
                        "informationUri": "https://github.com/tulaneadam/mcp-guard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
