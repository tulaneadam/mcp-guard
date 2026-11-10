"""Core data types: servers, tools and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (choose from {choices})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Server:
    """One MCP server entry from a client configuration file."""

    name: str
    source: str  # file the entry came from
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    transport: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_remote(self) -> bool:
        return self.url is not None


@dataclass
class Tool:
    """One tool definition, as returned by an MCP server's tools/list."""

    name: str
    server: str
    source: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    def text_fields(self) -> List[tuple]:
        """Every human/model-readable string in the definition, with a label.

        Tool poisoning often hides in parameter descriptions rather than the
        top-level description, so walk the whole input schema.
        """
        out = [("name", self.name), ("description", self.description or "")]

        def walk(node: Any, path: str) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    child = f"{path}.{key}" if path else key
                    if key in ("description", "title", "default", "examples") and isinstance(value, str):
                        out.append((f"inputSchema.{child}", value))
                    elif key == "enum" and isinstance(value, list):
                        for i, item in enumerate(value):
                            if isinstance(item, str):
                                out.append((f"inputSchema.{child}[{i}]", item))
                    else:
                        walk(value, child)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]")

        walk(self.input_schema, "")
        return out


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    source: str
    server: Optional[str] = None
    tool: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "message": self.message,
            "source": self.source,
            "server": self.server,
            "tool": self.tool,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
