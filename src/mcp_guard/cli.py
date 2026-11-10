"""Command-line interface.

    mcp-guard scan [PATHS...] [--tools DUMP.json] [--lock mcp-guard.lock]
                   [--format text|json|sarif] [--min-severity low] [--fail-on high]
    mcp-guard pin TOOLS.json [...] [-o mcp-guard.lock]
    mcp-guard rules
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .loader import discover_default_configs
from .model import Severity
from .report import render_json, render_sarif, render_text
from .rules import RULES
from .scanner import build_lock, load_paths, scan


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.paths] + [Path(p) for p in (args.tools or [])]
    if not paths:
        paths = discover_default_configs()
        if not paths:
            print("No paths given and no MCP client configs found in the usual locations.", file=sys.stderr)
            return 2
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"Path(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    lock = None
    if args.lock:
        lock_path = Path(args.lock)
        if not lock_path.exists():
            print(f"Lockfile not found: {lock_path}", file=sys.stderr)
            return 2
        lock = json.loads(lock_path.read_text(encoding="utf-8"))

    result = scan(paths, lock=lock)
    findings = result.filtered(Severity.parse(args.min_severity), args.ignore or [])

    if args.format == "json":
        out = render_json(result, findings)
    elif args.format == "sarif":
        out = render_sarif(result, findings)
    else:
        color = sys.stdout.isatty() and not args.no_color
        out = render_text(result, findings, color=color)

    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        if args.format != "text":
            print(render_text(result, findings, color=False))
    else:
        print(out)

    fail_on = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= fail_on for f in findings) else 0


def _cmd_pin(args: argparse.Namespace) -> int:
    result = load_paths([Path(p) for p in args.tools])
    if not result.tools:
        print("No tool definitions found to pin.", file=sys.stderr)
        return 2
    lock = build_lock(result.tools)
    Path(args.output).write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    n = sum(len(v) for v in lock["servers"].values())
    print(f"Pinned {n} tool(s) across {len(lock['servers'])} server(s) to {args.output}")
    return 0


def _cmd_rules(_: argparse.Namespace) -> int:
    for rid, meta in sorted(RULES.items()):
        print(f"{rid}  {meta['title']}\n        {meta['help']}\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Static security scanner for MCP (Model Context Protocol) client configs and tool definitions.",
    )
    p.add_argument("--version", action="version", version=f"mcp-guard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan MCP configs and/or tools/list dumps")
    s.add_argument("paths", nargs="*", help="config files, tool dumps or directories (default: known client config locations)")
    s.add_argument("--tools", action="append", metavar="FILE", help="tools/list JSON dump to scan (repeatable)")
    s.add_argument("--lock", metavar="FILE", help="compare tool definitions against a lockfile from `mcp-guard pin`")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("-o", "--output", metavar="FILE", help="write the report to a file")
    s.add_argument("--min-severity", default="low", help="hide findings below this level (default: low)")
    s.add_argument("--fail-on", default="high", help="exit 1 if any finding is at or above this level (default: high)")
    s.add_argument("--ignore", action="append", metavar="RULE", help="suppress a rule ID, e.g. MCG011 (repeatable)")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    pin = sub.add_parser("pin", help="record hashes of tool definitions to detect later changes (rug pulls)")
    pin.add_argument("tools", nargs="+", help="tools/list JSON dumps")
    pin.add_argument("-o", "--output", default="mcp-guard.lock")
    pin.set_defaults(func=_cmd_pin)

    r = sub.add_parser("rules", help="list all rules")
    r.set_defaults(func=_cmd_rules)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
