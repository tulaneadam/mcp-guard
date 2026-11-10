"""Glue: load files, run rules, compare against a lockfile."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .loader import LoadError, classify, parse_servers, parse_tools, read_json
from .model import Finding, Server, Severity, Tool
from .rules import RULES, run_rules

RULES["MCG020"] = {
    "title": "Tool definition changed since it was pinned (possible rug pull)",
    "help": "A server's tool name, description or schema no longer matches the hash recorded in the lockfile. "
    "Servers can change their tool descriptions after you approve them; review the diff before trusting it.",
}
RULES["MCG021"] = {
    "title": "New tool appeared since it was pinned",
    "help": "A server now exposes a tool that was not present when the lockfile was created.",
}


@dataclass
class ScanResult:
    files: List[str] = field(default_factory=list)
    servers: List[Server] = field(default_factory=list)
    tools: List[Tool] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def filtered(self, min_severity: Severity, ignore: Sequence[str]) -> List[Finding]:
        ign = {i.upper() for i in ignore}
        return [f for f in self.findings if f.severity >= min_severity and f.rule_id not in ign]


def tool_fingerprint(tool: Tool) -> str:
    canonical = json.dumps(
        {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_lock(tools: List[Tool]) -> Dict:
    lock: Dict[str, Dict[str, str]] = {}
    for t in tools:
        lock.setdefault(t.server, {})[t.name] = tool_fingerprint(t)
    return {"version": 1, "servers": {k: dict(sorted(v.items())) for k, v in sorted(lock.items())}}


def compare_lock(tools: List[Tool], lock: Dict) -> List[Finding]:
    pinned = lock.get("servers", {})
    findings = []
    for t in tools:
        server_pins = pinned.get(t.server)
        if server_pins is None:
            continue  # server not pinned at all: nothing to compare
        expected = server_pins.get(t.name)
        if expected is None:
            findings.append(
                Finding(
                    rule_id="MCG021",
                    title=RULES["MCG021"]["title"],
                    severity=Severity.MEDIUM,
                    message=f"Server '{t.server}' now exposes tool '{t.name}', which is not in the lockfile.",
                    source=t.source,
                    server=t.server,
                    tool=t.name,
                    remediation="Review the new tool, then re-run `mcp-guard pin` to accept it.",
                )
            )
        elif expected != tool_fingerprint(t):
            findings.append(
                Finding(
                    rule_id="MCG020",
                    title=RULES["MCG020"]["title"],
                    severity=Severity.HIGH,
                    message=f"Tool '{t.name}' on server '{t.server}' changed since it was pinned.",
                    source=t.source,
                    server=t.server,
                    tool=t.name,
                    evidence=f"expected {expected[:19]}…, got {tool_fingerprint(t)[:19]}…",
                    remediation="Diff the new definition against the reviewed one; re-pin only if the change is benign.",
                )
            )
    return findings


def load_paths(paths: Sequence[Path], result: Optional[ScanResult] = None) -> ScanResult:
    result = result or ScanResult()
    for path in paths:
        files = sorted(p for p in path.rglob("*.json")) if path.is_dir() else [path]
        for f in files:
            try:
                doc = read_json(f)
            except LoadError as exc:
                result.errors.append(str(exc))
                continue
            kind = classify(doc)
            if kind == "config":
                result.servers.extend(parse_servers(doc, str(f)))
                result.files.append(str(f))
            elif kind == "tools":
                result.tools.extend(parse_tools(doc, str(f), default_server=f.stem))
                result.files.append(str(f))
            elif not path.is_dir():
                result.errors.append(f"{f}: not an MCP config or tools/list dump (skipped)")
    return result


def scan(paths: Sequence[Path], lock: Optional[Dict] = None) -> ScanResult:
    result = load_paths(paths)
    result.findings.extend(run_rules(result.servers, result.tools))
    if lock is not None:
        result.findings.extend(compare_lock(result.tools, lock))
    result.findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.server or "", f.tool or ""))
    return result
