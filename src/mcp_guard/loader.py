"""Load MCP client configs and tool-definition dumps from disk.

Supported config shapes:
  * {"mcpServers": {...}}               Claude Desktop, Claude Code, Cursor, Windsurf, Cline
  * {"servers": {...}}                  VS Code (.vscode/mcp.json)
  * {"mcp": {"servers": {...}}}         VS Code settings.json
  * {"context_servers": {...}}          Zed

Supported tool dumps (output of an MCP tools/list call):
  * {"tools": [...]}                    single server
  * [ {...}, {...} ]                    bare list of tools
  * {"<server>": {"tools": [...]}}      several servers keyed by name
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .model import Server, Tool

# Where popular MCP clients keep their configuration.
DEFAULT_CONFIG_LOCATIONS = [
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.config/Claude/claude_desktop_config.json",
    "%APPDATA%/Claude/claude_desktop_config.json",
    "~/.claude.json",
    "~/.cursor/mcp.json",
    "~/.codeium/windsurf/mcp_config.json",
    "~/.config/zed/settings.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
]


class LoadError(Exception):
    pass


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code / Zed allow JSONC)."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(ch)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LoadError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return json.loads(_strip_jsonc(text))
        except json.JSONDecodeError as exc:
            raise LoadError(f"{path} is not valid JSON: {exc}") from exc


def _server_maps(doc: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(doc.get("mcpServers"), dict):
        yield "mcpServers", doc["mcpServers"]
    if isinstance(doc.get("servers"), dict):
        yield "servers", doc["servers"]
    if isinstance(doc.get("mcp"), dict) and isinstance(doc["mcp"].get("servers"), dict):
        yield "mcp.servers", doc["mcp"]["servers"]
    if isinstance(doc.get("context_servers"), dict):
        yield "context_servers", doc["context_servers"]
    # Claude Code keeps per-project servers under projects.<path>.mcpServers
    if isinstance(doc.get("projects"), dict):
        for proj, cfg in doc["projects"].items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                yield f"projects[{proj}].mcpServers", cfg["mcpServers"]


def _as_str_dict(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def parse_servers(doc: Any, source: str) -> List[Server]:
    servers: List[Server] = []
    if not isinstance(doc, dict):
        return servers
    for _, mapping in _server_maps(doc):
        for name, entry in mapping.items():
            if not isinstance(entry, dict):
                continue
            # Zed nests the launch command one level down.
            cmd_block = entry.get("command")
            if isinstance(cmd_block, dict):
                command = cmd_block.get("path")
                args = cmd_block.get("args", [])
                env = cmd_block.get("env", {})
            else:
                command = cmd_block
                args = entry.get("args", [])
                env = entry.get("env", {})
            url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
            servers.append(
                Server(
                    name=str(name),
                    source=source,
                    command=str(command) if command else None,
                    args=[str(a) for a in args] if isinstance(args, list) else [],
                    env=_as_str_dict(env),
                    url=str(url) if url else None,
                    headers=_as_str_dict(entry.get("headers")),
                    transport=entry.get("type") or entry.get("transport"),
                    raw=entry,
                )
            )
    return servers


def _tools_from_list(items: Any, server: str, source: str) -> List[Tool]:
    tools = []
    if not isinstance(items, list):
        return tools
    for item in items:
        if not isinstance(item, dict) or "name" not in item:
            continue
        tools.append(
            Tool(
                name=str(item["name"]),
                server=server,
                source=source,
                description=str(item.get("description") or ""),
                input_schema=item.get("inputSchema") or item.get("input_schema") or {},
                raw=item,
            )
        )
    return tools


def parse_tools(doc: Any, source: str, default_server: str) -> List[Tool]:
    if isinstance(doc, list):
        return _tools_from_list(doc, default_server, source)
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get("tools"), list):
        server = str(doc.get("server") or doc.get("serverName") or default_server)
        return _tools_from_list(doc["tools"], server, source)
    # MCP JSON-RPC response envelope
    if isinstance(doc.get("result"), dict) and isinstance(doc["result"].get("tools"), list):
        return _tools_from_list(doc["result"]["tools"], default_server, source)
    tools: List[Tool] = []
    for name, value in doc.items():
        if isinstance(value, dict) and isinstance(value.get("tools"), list):
            tools.extend(_tools_from_list(value["tools"], str(name), source))
    return tools


def classify(doc: Any) -> str:
    """Return 'config', 'tools', or 'unknown' for a parsed JSON document."""
    if isinstance(doc, dict) and any(True for _ in _server_maps(doc)):
        return "config"
    if parse_tools(doc, "", "x"):
        return "tools"
    return "unknown"


def discover_default_configs(cwd: Path = None) -> List[Path]:
    cwd = cwd or Path.cwd()
    found = []
    for loc in DEFAULT_CONFIG_LOCATIONS:
        expanded = os.path.expandvars(os.path.expanduser(loc))
        p = Path(expanded)
        if not p.is_absolute():
            p = cwd / p
        if "%" not in expanded and p.is_file():
            found.append(p)
    return found
