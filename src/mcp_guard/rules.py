"""Security checks for MCP servers and tool definitions.

Each rule is a small function that yields Findings. Rule IDs are stable so
they can be suppressed (--ignore MCG004) and tracked in SARIF/code scanning.
"""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from typing import Callable, Dict, Iterable, Iterator, List
from urllib.parse import urlparse

from .model import Finding, Server, Severity, Tool

RULES: Dict[str, Dict[str, str]] = {}


def _rule(rule_id: str, title: str, help_text: str):
    def wrap(fn: Callable):
        RULES[rule_id] = {"title": title, "help": help_text}
        fn.rule_id = rule_id
        fn.title = title
        return fn

    return wrap


def _clip(text: str, start: int, end: int, pad: int = 40) -> str:
    a, b = max(0, start - pad), min(len(text), end + pad)
    snippet = text[a:b].replace("\n", " ")
    return ("…" if a else "") + snippet + ("…" if b < len(text) else "")


# --------------------------------------------------------------------------- #
# Tool-definition rules (tool poisoning / rug pulls / shadowing)
# --------------------------------------------------------------------------- #

INJECTION_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts|rules)", "overrides prior instructions"),
    (r"disregard (all |any )?(previous|prior|above|the) (instructions|rules|system)", "overrides prior instructions"),
    (r"(do not|don't|never) (tell|inform|mention|reveal|notify|alert|show)( this)?( to)? (the )?user", "asks the model to hide behaviour from the user"),
    (r"without (telling|informing|notifying|asking) the user", "asks the model to hide behaviour from the user"),
    (r"<\s*(important|system|instructions?|secret|hidden)\s*>", "pseudo-system tag used to smuggle instructions"),
    (r"\b(before|prior to) (using|calling|invoking) (this|any other|any) tool,? (you must|always|first)", "pre-call instruction aimed at the model"),
    (r"(you are now|from now on,? you|act as|new instructions:)", "role/instruction reassignment"),
    (r"(system prompt|developer message|hidden instructions)", "references the model's hidden instructions"),
    (r"(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.netrc|\.npmrc|\.pypirc|\.git-credentials|/etc/passwd|keychain)", "references credential or secret files"),
    (r"(send|upload|exfiltrate|forward|post|pass|include|attach|leak)[^.\n]{0,60}(credentials?|api[_ ]?keys?|access tokens?|auth tokens?|secrets?|passwords?|private keys?|ssh keys?|session cookies?)", "asks the model to send sensitive data"),
    (r"\b(read|open|cat|load)\b[^.\n]{0,80}\b(and|then)\b[^.\n]{0,30}\b(pass|send|include|put|add|attach|append|forward)\b[^.\n]{0,30}\b(contents?|it|them|the (file|data|result))", "chains a read with sending the data elsewhere"),
    (r"when (the user|someone) (asks|requests)[^.\n]{0,80}(instead|also|secretly)", "conditional behaviour change"),
    (r"(this is|it is) (very |extremely )?important[^.\n]{0,40}(not|never|always)", "pressure language typical of injected instructions"),
]
_INJECTION_RES = [(re.compile(p, re.IGNORECASE), why) for p, why in INJECTION_PATTERNS]

# Characters that are invisible or re-order text: used to hide payloads.
_INVISIBLE = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\u2061", "\u2062", "\u2063", "\u2064", "\ufeff", "\u00ad", "\u180e",
}
_BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u200e", "\u200f"}


def _hidden_chars(text: str) -> List[str]:
    hits = []
    for ch in text:
        cp = ord(ch)
        if ch in _INVISIBLE or ch in _BIDI or 0xE0000 <= cp <= 0xE007F:  # Unicode tag block
            hits.append(f"U+{cp:04X} {unicodedata.name(ch, 'UNNAMED')}")
    return hits


def _decode_tag_chars(text: str) -> str:
    """ASCII smuggled via the Unicode 'tags' block (U+E0020–U+E007E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


@_rule(
    "MCG001",
    "Tool poisoning: instructions aimed at the model",
    "A tool's name, description or parameter descriptions contain language that instructs the model "
    "(override instructions, hide actions from the user, read secrets). Models read these fields as "
    "trusted context, so a malicious or compromised server can hijack the agent without the tool ever being called.",
)
def check_tool_poisoning(tools: List[Tool]) -> Iterator[Finding]:
    for tool in tools:
        for label, text in tool.text_fields():
            smuggled = _decode_tag_chars(text)
            for candidate in (text, smuggled):
                if not candidate:
                    continue
                for rx, why in _INJECTION_RES:
                    m = rx.search(candidate)
                    if m:
                        yield Finding(
                            rule_id="MCG001",
                            title=check_tool_poisoning.title,
                            severity=Severity.CRITICAL if "secret" in why or "hide" in why else Severity.HIGH,
                            message=f"Tool '{tool.name}' {label} {why}.",
                            source=tool.source,
                            server=tool.server,
                            tool=tool.name,
                            evidence=_clip(candidate, m.start(), m.end()),
                            remediation="Remove the server or pin a reviewed version. Tool metadata should describe "
                            "what the tool does, never tell the model what to do.",
                        )
                        break  # one finding per field is enough


@_rule(
    "MCG002",
    "Hidden or invisible characters in tool metadata",
    "Zero-width, bidirectional-override or Unicode 'tag' characters can hide text from a human reviewer "
    "while the model still reads it.",
)
def check_hidden_chars(tools: List[Tool]) -> Iterator[Finding]:
    for tool in tools:
        for label, text in tool.text_fields():
            hits = _hidden_chars(text)
            if hits:
                smuggled = _decode_tag_chars(text)
                yield Finding(
                    rule_id="MCG002",
                    title=check_hidden_chars.title,
                    severity=Severity.HIGH,
                    message=f"Tool '{tool.name}' {label} contains {len(hits)} invisible/bidi character(s).",
                    source=tool.source,
                    server=tool.server,
                    tool=tool.name,
                    evidence=(f"decoded hidden text: {smuggled!r}" if smuggled else ", ".join(sorted(set(hits))[:5])),
                    remediation="Treat as malicious until reviewed; legitimate tool descriptions have no reason to contain these.",
                )


_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
_EXFIL_HOSTS = re.compile(
    r"(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|burpcollaborator|oast\.(pro|fun|live|site|me)|"
    r"hookbin|beeceptor|requestcatcher|discord(app)?\.com/api/webhooks|hooks\.slack\.com|pastebin\.com|transfer\.sh|"
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)


@_rule(
    "MCG003",
    "Tool metadata references an exfiltration-style endpoint",
    "Tool descriptions that point at request-capture services, raw IPs or chat webhooks are a common way to "
    "make an agent send data to an attacker.",
)
def check_exfil_urls(tools: List[Tool]) -> Iterator[Finding]:
    for tool in tools:
        for label, text in tool.text_fields():
            for m in _URL_RE.finditer(text):
                if _EXFIL_HOSTS.search(m.group(0)):
                    yield Finding(
                        rule_id="MCG003",
                        title=check_exfil_urls.title,
                        severity=Severity.HIGH,
                        message=f"Tool '{tool.name}' {label} links to {urlparse(m.group(0)).netloc}.",
                        source=tool.source,
                        server=tool.server,
                        tool=tool.name,
                        evidence=m.group(0),
                        remediation="Confirm why a tool description needs this URL; remove the server if you cannot.",
                    )


@_rule(
    "MCG004",
    "Tool name shadowing across servers",
    "Two servers expose a tool with the same name. A malicious server can register a look-alike tool to "
    "intercept calls meant for a trusted one.",
)
def check_shadowing(tools: List[Tool]) -> Iterator[Finding]:
    by_name = defaultdict(set)
    for t in tools:
        by_name[t.name.lower()].add(t.server)
    for name, servers in sorted(by_name.items()):
        if len(servers) > 1:
            src = next(t.source for t in tools if t.name.lower() == name)
            yield Finding(
                rule_id="MCG004",
                title=check_shadowing.title,
                severity=Severity.MEDIUM,
                message=f"Tool '{name}' is exposed by {len(servers)} servers: {', '.join(sorted(servers))}.",
                source=src,
                tool=name,
                remediation="Disable one of the servers, or use a client that namespaces tools by server.",
            )


# --------------------------------------------------------------------------- #
# Server-configuration rules
# --------------------------------------------------------------------------- #

SECRET_PATTERNS = [
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"sk-(proj-)?[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{40,}", "GitHub fine-grained token"),
    (r"glpat-[A-Za-z0-9_\-]{20,}", "GitLab token"),
    (r"xox[abposr]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API key"),
    (r"(sk|rk)_live_[0-9a-zA-Z]{20,}", "Stripe live key"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^:\s/]+:[^@\s]+@", "database URL with password"),
]
_SECRET_RES = [(re.compile(p), what) for p, what in SECRET_PATTERNS]
_SECRETY_KEY = re.compile(r"(api[_-]?key|token|secret|password|passwd|pwd|auth|credential|private[_-]?key)", re.I)
_PLACEHOLDER = re.compile(r"^(\$\{?[A-Z0-9_:\-]+\}?|<[^>]+>|your[_\- ].*|x{4,}|\*{3,}|changeme|example|placeholder|todo|\s*)$", re.I)


def _mask(value: str) -> str:
    return value[:4] + "…" + value[-2:] if len(value) > 8 else "****"


@_rule(
    "MCG010",
    "Hard-coded secret in MCP configuration",
    "API keys and passwords written directly into an MCP config end up in backups, dotfile repos and screen "
    "shares, and are readable by every other local process and server.",
)
def check_secrets(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        places = [("env", k, v) for k, v in s.env.items()]
        places += [("headers", k, v) for k, v in s.headers.items()]
        places += [("args", str(i), a) for i, a in enumerate(s.args)]
        if s.url:
            places.append(("url", "", s.url))
        for where, key, value in places:
            if not value or _PLACEHOLDER.match(value):
                continue
            what = None
            for rx, label in _SECRET_RES:
                if rx.search(value):
                    what = label
                    break
            if what is None and where in ("env", "headers") and _SECRETY_KEY.search(key) and len(value) >= 12:
                what = f"value of {key}"
            if what is None and where == "headers" and key.lower() == "authorization" and len(value) > 12:
                what = "Authorization header"
            if what:
                loc = f"{where}.{key}" if key else where
                yield Finding(
                    rule_id="MCG010",
                    title=check_secrets.title,
                    severity=Severity.HIGH,
                    message=f"Server '{s.name}' has a hard-coded {what} in {loc}.",
                    source=s.source,
                    server=s.name,
                    evidence=_mask(value),
                    remediation="Reference an environment variable or secret manager instead (e.g. \"${env:API_TOKEN}\"), "
                    "and rotate the exposed credential.",
                )


_RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "dlx"}


def _base(cmd: str) -> str:
    return re.split(r"[\\/]", cmd)[-1].lower().replace(".cmd", "").replace(".exe", "")


def _package_arg(s: Server) -> str:
    """First positional argument after the runner and its flags (the package spec)."""
    args = list(s.args)
    if _base(s.command or "") == "pnpm" and args[:1] == ["dlx"]:
        args = args[1:]
    if _base(s.command or "") == "pipx" and args[:1] == ["run"]:
        args = args[1:]
    skip_next = {"--from", "-p", "--package", "--python", "--with", "--index-url", "--spec"}
    i = 0
    while i < len(args):
        a = args[i]
        if a in skip_next:
            # uvx --from pkg==1.0 tool  -> the --from value is the real package spec
            if a in ("--from", "--package", "-p", "--spec") and i + 1 < len(args):
                return args[i + 1]
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return ""


def _is_pinned(spec: str, runner: str) -> bool:
    if not spec:
        return True
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.endswith((".js", ".py", ".ts", ".mjs")):
        return True  # local path or explicit URL: not a registry package
    if runner in ("uvx", "pipx"):
        return bool(re.search(r"(==|@)\s*\d", spec))
    # npm: name@version or @scope/name@version, with a concrete version (not latest/next/^/~)
    m = re.match(r"^(@[^/]+/)?[^@]+@(.+)$", spec)
    if not m:
        return False
    version = m.group(2)
    return bool(re.match(r"^\d+\.\d+\.\d+([-.+][0-9A-Za-z.\-]+)?$", version))


def _pin_example(spec: str, runner: str) -> str:
    if runner in ("uvx", "pipx"):
        return re.split(r"[=@<>~!]", spec, maxsplit=1)[0] + "==1.2.3"
    scope = ""
    if spec.startswith("@") and "/" in spec:
        scope, spec = spec.split("/", 1)
        scope += "/"
    return scope + spec.split("@", 1)[0] + "@1.2.3"


@_rule(
    "MCG011",
    "Server package is not pinned to a version",
    "Launching a server with npx/uvx without an exact version means every start can download new code. "
    "A compromised maintainer account or a 'rug pull' update silently changes what your agent runs.",
)
def check_unpinned(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        runner = _base(s.command or "")
        if runner == "pnpm" and s.args[:1] == ["dlx"]:
            runner = "dlx"
        if runner not in _RUNNERS:
            continue
        spec = _package_arg(s)
        if spec and not _is_pinned(spec, runner):
            yield Finding(
                rule_id="MCG011",
                title=check_unpinned.title,
                severity=Severity.MEDIUM,
                message=f"Server '{s.name}' runs '{spec}' via {runner} without an exact version.",
                source=s.source,
                server=s.name,
                evidence=" ".join([s.command or ""] + s.args),
                remediation=f"Pin an exact, reviewed version, e.g. {_pin_example(spec, runner)}, and update deliberately.",
            )


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


@_rule(
    "MCG012",
    "Remote MCP server over unencrypted HTTP",
    "Tool calls, results and any auth headers to a remote server are sent in clear text and can be read or "
    "modified in transit.",
)
def check_plain_http(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        if not s.url:
            continue
        u = urlparse(s.url)
        if u.scheme == "http" and (u.hostname or "") not in _LOCAL_HOSTS:
            yield Finding(
                rule_id="MCG012",
                title=check_plain_http.title,
                severity=Severity.HIGH,
                message=f"Server '{s.name}' connects to {u.hostname} over plain HTTP.",
                source=s.source,
                server=s.name,
                evidence=s.url,
                remediation="Use an https:// endpoint.",
            )


_SHELLS = {"bash", "sh", "zsh", "dash", "ash", "fish", "cmd", "powershell", "pwsh"}


@_rule(
    "MCG013",
    "Server launched through a shell or download-and-execute",
    "Wrapping the server in 'sh -c' / 'cmd /c' or piping curl/wget into a shell runs unreviewed code with your "
    "user's privileges every time the client starts.",
)
def check_shell(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        joined = " ".join([s.command or ""] + s.args)
        runner = _base(s.command or "")
        pipe = re.search(r"(curl|wget|iwr|invoke-webrequest)[^|]*\|\s*(ba|z)?sh|iex\s*\(|\|\s*iex", joined, re.I)
        if pipe:
            yield Finding(
                rule_id="MCG013",
                title=check_shell.title,
                severity=Severity.CRITICAL,
                message=f"Server '{s.name}' downloads and executes code at start-up.",
                source=s.source,
                server=s.name,
                evidence=joined[:200],
                remediation="Install the server from a pinned, reviewed package instead of piping a download into a shell.",
            )
        elif runner in _SHELLS and any(a.lower() in ("-c", "/c", "-command", "/k") for a in s.args):
            yield Finding(
                rule_id="MCG013",
                title=check_shell.title,
                severity=Severity.MEDIUM,
                message=f"Server '{s.name}' is launched through {runner} with an inline command.",
                source=s.source,
                server=s.name,
                evidence=joined[:200],
                remediation="Call the server binary directly so the exact command is visible and reviewable.",
            )


_BROAD_PATHS = re.compile(r"^(/|~/?|\$HOME/?|\$\{HOME\}/?|%USERPROFILE%\\?|[A-Za-z]:\\?|/Users/?|/home/?|/root/?|\.\.?/?)$")


@_rule(
    "MCG014",
    "Overly broad filesystem access",
    "Giving a filesystem server your whole disk or home directory exposes SSH keys, cloud credentials and "
    "browser data to anything that can steer the agent (including prompt injection).",
)
def check_broad_fs(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        text = " ".join([s.command or ""] + s.args).lower()
        if "filesystem" not in text and "fs" not in s.name.lower() and "file" not in s.name.lower():
            continue
        for a in s.args:
            if _BROAD_PATHS.match(a.strip()):
                yield Finding(
                    rule_id="MCG014",
                    title=check_broad_fs.title,
                    severity=Severity.HIGH if a.strip() in ("/", "C:\\", "c:\\") else Severity.MEDIUM,
                    message=f"Server '{s.name}' is allowed to access '{a}'.",
                    source=s.source,
                    server=s.name,
                    evidence=a,
                    remediation="Limit the server to the specific project directories it needs.",
                )


@_rule(
    "MCG015",
    "Container launched with host-level privileges",
    "Docker flags such as --privileged, --network host, or mounting the Docker socket or host root give the "
    "server (and anyone who can steer it) control of the host.",
)
def check_docker(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        if _base(s.command or "") not in ("docker", "podman"):
            continue
        args = s.args
        joined = " ".join(args)
        problems = []
        if "--privileged" in args:
            problems.append("--privileged")
        for i, a in enumerate(args):
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if a in ("--network", "--net") and nxt == "host" or a in ("--network=host", "--net=host"):
                problems.append("host networking")
            if a in ("--pid", "--ipc") and nxt == "host" or a in ("--pid=host", "--ipc=host"):
                problems.append(f"{a.split('=')[0]} host")
            if a in ("-v", "--volume", "--mount") or a.startswith(("--volume=", "--mount=")):
                spec = nxt if "=" not in a else a.split("=", 1)[1]
                if "docker.sock" in spec:
                    problems.append("Docker socket mounted")
                elif re.match(r"^(/|source=/,|src=/,|/:)", spec) and spec.split(":")[0] in ("/", "source=/", "src=/"):
                    problems.append("host root mounted")
            if a == "--cap-add" and nxt.upper() in ("ALL", "SYS_ADMIN"):
                problems.append(f"--cap-add {nxt}")
        for p in dict.fromkeys(problems):
            yield Finding(
                rule_id="MCG015",
                title=check_docker.title,
                severity=Severity.HIGH,
                message=f"Server '{s.name}' container runs with {p}.",
                source=s.source,
                server=s.name,
                evidence=joined[:200],
                remediation="Drop the flag; mount only the directories the server needs, read-only where possible.",
            )


@_rule(
    "MCG016",
    "Tools auto-approved without human confirmation",
    "Auto-approve / alwaysAllow lists let the agent call tools without asking. Combined with prompt injection, "
    "that turns a malicious web page or email into actions on your machine.",
)
def check_auto_approve(servers: List[Server]) -> Iterator[Finding]:
    for s in servers:
        for key in ("alwaysAllow", "autoApprove", "auto_approve", "trust"):
            value = s.raw.get(key)
            if value in (None, False, [], ""):
                continue
            everything = value is True or value == "*" or (isinstance(value, list) and "*" in value)
            yield Finding(
                rule_id="MCG016",
                title=check_auto_approve.title,
                severity=Severity.HIGH if everything else Severity.LOW,
                message=f"Server '{s.name}' auto-approves "
                + ("every tool" if everything else f"{len(value) if isinstance(value, list) else 'some'} tool(s)")
                + f" via '{key}'.",
                source=s.source,
                server=s.name,
                evidence=str(value)[:120],
                remediation="Only auto-approve read-only tools; keep confirmation on anything that writes, sends or executes.",
            )


TOOL_RULES = [check_tool_poisoning, check_hidden_chars, check_exfil_urls, check_shadowing]
SERVER_RULES = [check_secrets, check_unpinned, check_plain_http, check_shell, check_broad_fs, check_docker, check_auto_approve]


def run_rules(servers: List[Server], tools: List[Tool]) -> Iterable[Finding]:
    for rule in SERVER_RULES:
        yield from rule(servers)
    for rule in TOOL_RULES:
        yield from rule(tools)
