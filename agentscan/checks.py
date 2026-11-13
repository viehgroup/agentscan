"""The actual checks. Each one takes a file and yields findings."""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

from .discover import AgentFile
from .secrets import find_in_text, looks_like_secret_value, mask

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    fix: str = ""


RULES = {
    "AS001": ("Hardcoded secret", "A credential is stored in plain text in an agent config file."),
    "AS002": ("Secret in MCP server env/headers", "An MCP server gets a literal credential instead of an environment reference."),
    "AS003": ("Permission checks disabled", "The agent is set to run tools without asking."),
    "AS004": ("Unrestricted shell access", "The agent may run any shell command without approval."),
    "AS005": ("Broad command allowed", "An allow rule covers a command that can run arbitrary code or fetch from the network."),
    "AS006": ("All project MCP servers auto-trusted", "Any MCP server added to the repo starts without a prompt."),
    "AS007": ("Unpinned MCP package", "The MCP server installs whatever version is newest at launch."),
    "AS008": ("MCP server over plain HTTP", "Traffic to a remote MCP server is unencrypted."),
    "AS009": ("Risky MCP launch command", "The MCP server is launched in a way that runs downloaded code or escapes isolation."),
    "AS010": ("Hidden Unicode in instructions", "Invisible characters can carry instructions a reviewer won't see."),
    "AS011": ("Suspicious instruction", "Instruction text asks the agent to hide actions or run remote scripts."),
    "AS012": ("Hidden HTML comment in instructions", "Text in an HTML comment is invisible when rendered but read by the agent."),
    "AS013": ("Personal settings committed", "A file meant to stay local is tracked in git."),
    "AS014": ("Network call in hook", "A hook runs automatically and talks to the network."),
    "AS015": ("Unparseable config", "The file could not be parsed, so structural checks were skipped."),
}


def line_of(text: str, needle: str, start: int = 0) -> int:
    if not needle:
        return 1
    i = text.find(needle, start)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


# --------------------------------------------------------------------------- secrets

def check_secrets(f: AgentFile, text: str) -> Iterator[Finding]:
    seen = set()
    for hit in find_in_text(text):
        if hit.value in seen:
            continue
        seen.add(hit.value)
        msg = f"{hit.kind} in plain text: {mask(hit.value)}"
        fix = "Move it to an environment variable and reference it instead."
        if f.tracked:
            msg += ". This file is committed to git"
            fix = "Rotate this secret now (it's in git history), then load it from an environment variable."
        yield Finding("AS001", HIGH, f.display, line_of(text, hit.value), msg, fix)


# --------------------------------------------------------------------------- MCP

def _servers(data: Any) -> Dict[str, dict]:
    """MCP server blocks, wherever this tool keeps them."""
    out: Dict[str, dict] = {}
    if not isinstance(data, dict):
        return out
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            out.update({k: v for k, v in block.items() if isinstance(v, dict)})
    # ~/.claude.json nests per-project servers
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj, cfg in projects.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                for k, v in cfg["mcpServers"].items():
                    if isinstance(v, dict):
                        out[f"{k} ({proj})"] = v
    return out


_VERSIONED_NPM = re.compile(r"^(@[^/@\s]+/)?[^@\s/]+@\d")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _npm_pkg_arg(args: List[str]) -> Optional[str]:
    skip_next = {"-p", "--package", "--registry", "--cache"}
    it = iter(args)
    for a in it:
        if a in skip_next:
            return next(it, None) if a in ("-p", "--package") else None
        if a.startswith("-"):
            continue
        return a
    return None


def check_mcp(f: AgentFile, text: str, data: Any, already: set) -> Iterator[Finding]:
    for name, srv in _servers(data).items():
        cmd = str(srv.get("command") or "")
        args = [str(a) for a in (srv.get("args") or []) if isinstance(a, (str, int, float))]
        base = cmd.rsplit("/", 1)[-1].lower()
        anchor = line_of(text, f'"{name.split(" (")[0]}"')

        # literal secrets passed in env / headers
        for block in ("env", "headers"):
            vals = srv.get(block)
            if not isinstance(vals, dict):
                continue
            for k, v in vals.items():
                if not isinstance(v, str):
                    continue
                raw = re.sub(r"(?i)^(bearer|token|basic)\s+", "", v.strip())
                what = looks_like_secret_value(k, raw)
                if what and raw not in already:
                    already.add(raw)
                    yield Finding("AS002", HIGH, f.display, line_of(text, raw),
                                  f"MCP server '{name}' has {what} in {block}.{k}: {mask(raw)}",
                                  _env_fix(block, k))

        # unpinned packages
        if base in ("npx", "bunx", "pnpx") or (base in ("pnpm", "yarn") and args[:1] == ["dlx"]):
            pkg = _npm_pkg_arg(args[1:] if args[:1] == ["dlx"] else args)
            if pkg and not pkg.startswith((".", "/")):
                if pkg.endswith("@latest") or not _VERSIONED_NPM.match(pkg):
                    yield Finding("AS007", MEDIUM, f.display, anchor,
                                  f"MCP server '{name}' runs {base} {pkg} without a fixed version",
                                  f"Pin it, e.g. {pkg.split('@latest')[0]}@1.2.3, so a hijacked release can't run on your machine.")
        if base in ("uvx", "pipx") or (base == "uv" and args[:2] == ["tool", "run"]):
            rest = args[2:] if base == "uv" else (args[1:] if base == "pipx" and args[:1] == ["run"] else args)
            pkg = next((a for a in rest if not a.startswith("-")), None)
            if pkg and "==" not in pkg and "@" not in pkg:
                yield Finding("AS007", MEDIUM, f.display, anchor,
                              f"MCP server '{name}' runs {base} {pkg} without a fixed version",
                              f"Pin it, e.g. {pkg}==1.2.3.")

        # remote servers
        url = srv.get("url") or srv.get("serverUrl") or srv.get("httpUrl")
        if isinstance(url, str) and url.startswith("http://"):
            host = urlparse(url).hostname or ""
            if host not in _LOCAL_HOSTS:
                yield Finding("AS008", MEDIUM, f.display, line_of(text, url),
                              f"MCP server '{name}' connects to {url} without TLS",
                              "Use https so tokens and tool output aren't sent in clear text.")

        # risky launches
        joined = " ".join([cmd] + args)
        if re.search(r"(curl|wget)\b[^|]*\|\s*(ba|z)?sh\b", joined):
            yield Finding("AS009", HIGH, f.display, anchor,
                          f"MCP server '{name}' pipes a download straight into a shell",
                          "Install the server explicitly and pin its version.")
        if base in ("docker", "podman"):
            if "--privileged" in args:
                yield Finding("AS009", MEDIUM, f.display, anchor,
                              f"MCP server '{name}' runs a privileged container",
                              "Drop --privileged; grant only the capabilities it needs.")
            for i, a in enumerate(args):
                mount = args[i + 1] if a in ("-v", "--volume") and i + 1 < len(args) else (
                    a.split("=", 1)[1] if a.startswith("--volume=") else None)
                if mount and (mount.startswith("/:") or mount.startswith("/var/run/docker.sock")):
                    yield Finding("AS009", HIGH, f.display, anchor,
                                  f"MCP server '{name}' mounts {mount.split(':')[0]} into the container",
                                  "Mount only the directories the server actually needs.")


def _env_fix(block: str, key: str) -> str:
    if block == "headers" and key.lower() == "authorization":
        ref = '"Bearer ${API_TOKEN}"'
    else:
        ref = '"${' + re.sub(r"[^A-Z0-9]+", "_", key.upper()).strip("_") + '}"'
    return f"Use an env reference such as {ref} and keep the value out of the file."


# --------------------------------------------------------------------------- settings

_BROAD_CMDS = ("curl", "wget", "sh", "bash", "zsh", "sudo", "python", "python3", "node", "rm",
               "eval", "ssh", "scp", "nc", "powershell", "pwsh", "npx", "docker", "chmod")
_ANY_SHELL = re.compile(r"^Bash(\((\*|\*:\*|:\*)?\))?$")
_BROAD_SHELL = re.compile(r"^Bash\(\s*(" + "|".join(map(re.escape, _BROAD_CMDS)) + r")(\s*:?\s*\*|\s+\*)\s*\)$")


def check_claude_settings(f: AgentFile, text: str, data: Any) -> Iterator[Finding]:
    if not isinstance(data, dict):
        return
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        yield Finding("AS003", HIGH, f.display, line_of(text, "bypassPermissions"),
                      "defaultMode is bypassPermissions: every tool call runs without asking",
                      "Remove it, or keep it to throwaway containers. Use specific allow rules instead.")
    for rule in perms.get("allow") or []:
        if not isinstance(rule, str):
            continue
        r = rule.strip()
        if _ANY_SHELL.match(r):
            yield Finding("AS004", HIGH, f.display, line_of(text, f'"{rule}"'),
                          f"allow rule '{rule}' lets the agent run any shell command",
                          "Replace it with specific commands, e.g. Bash(npm test:*).")
        elif _BROAD_SHELL.match(r):
            yield Finding("AS005", MEDIUM, f.display, line_of(text, f'"{rule}"'),
                          f"allow rule '{rule}' can run arbitrary code or reach the network",
                          "Narrow it to the exact command and arguments you need.")
    if data.get("enableAllProjectMcpServers") is True:
        yield Finding("AS006", MEDIUM, f.display, line_of(text, "enableAllProjectMcpServers"),
                      "enableAllProjectMcpServers is on: a pull request that adds a server to .mcp.json gets it started automatically",
                      "Turn it off and approve servers individually.")
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            for cmd in _hook_commands(entries):
                if re.search(r"\b(curl|wget|nc|Invoke-WebRequest|iwr)\b", cmd):
                    yield Finding("AS014", MEDIUM, f.display, line_of(text, cmd[:40]),
                                  f"{event} hook makes a network call: {cmd[:80]}",
                                  "Hooks run on every matching event. Make sure you trust where this sends data.")


def _hook_commands(entries) -> Iterator[str]:
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict):
                if isinstance(e.get("command"), str):
                    yield e["command"]
                yield from _hook_commands(e.get("hooks"))


def check_vscode_settings(f: AgentFile, text: str, data: Any) -> Iterator[Finding]:
    if not isinstance(data, dict):
        return
    for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
        if data.get(key) is True:
            yield Finding("AS003", HIGH, f.display, line_of(text, key),
                          f"{key} is on: Copilot agent mode runs tools and terminal commands without asking",
                          "Turn it off and approve tools individually.")


# --------------------------------------------------------------------------- instructions

_INVISIBLE = {
    **{c: "zero-width" for c in (0x200B, 0x200C, 0x200D, 0x2060, 0x2062, 0x2063, 0x2064, 0x180E)},
    **{c: "bidi control" for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)},
}
_SUSPICIOUS = [
    (re.compile(r"(?i)\b(do not|don'?t|never)\s+(tell|inform|mention|show|reveal)\b.{0,30}\b(user|human|developer|anyone)"),
     "asks the agent to keep something from the user"),
    (re.compile(r"(?i)\b(ignore|disregard)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines)"),
     "tries to override earlier instructions"),
    (re.compile(r"(?i)\bwithout\s+(asking|telling|notifying|informing)\s+(the\s+)?(user|developer|anyone)"),
     "asks the agent to act without telling the user"),
    (re.compile(r"(?i)(curl|wget)\s+[^\n|]*https?://[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
     "pipes a remote script into a shell"),
    (re.compile(r"(?i)\b(send|post|upload|exfiltrate)\b[^\n]{0,40}\b(env|\.env|credentials|secrets|api keys?|ssh keys?|tokens?)\b[^\n]{0,40}\bto\s+https?://"),
     "asks the agent to send credentials somewhere"),
]


def check_instructions(f: AgentFile, text: str) -> Iterator[Finding]:
    # invisible characters, grouped per line
    per_line: Dict[int, set] = {}
    for i, ch in enumerate(text):
        cp = ord(ch)
        kind = _INVISIBLE.get(cp)
        if kind is None and 0xE0000 <= cp <= 0xE007F:
            kind = "Unicode tag"
        if kind is None and cp == 0xFEFF and i != 0:
            kind = "zero-width"
        if kind:
            per_line.setdefault(text.count("\n", 0, i) + 1, set()).add(kind)
    for ln, kinds in sorted(per_line.items()):
        hidden = _decode_tags(text.splitlines()[ln - 1]) if "Unicode tag" in kinds else ""
        msg = f"invisible characters ({', '.join(sorted(kinds))}) on this line"
        if hidden:
            msg += f'. Hidden text decodes to: "{hidden[:80]}"'
        # stray zero-width spaces are usually copy-paste debris; tags and
        # bidi controls are how hidden instructions actually get smuggled in
        sev = MEDIUM if kinds == {"zero-width"} else HIGH
        yield Finding("AS010", sev, f.display, ln, msg,
                      "Delete the characters and review what the line says without them. "
                      "Treat it as a possible backdoor if you didn't add them.")

    for rx, what in _SUSPICIOUS:
        for m in rx.finditer(text):
            yield Finding("AS011", MEDIUM, f.display, text.count("\n", 0, m.start()) + 1,
                          f"instruction {what}: \"{m.group(0)[:80]}\"",
                          "Check who added this and whether it belongs here.")

    for m in re.finditer(r"<!--(.*?)-->", text, re.S):
        body = " ".join(m.group(1).split())
        if len(body) >= 40:
            yield Finding("AS012", LOW, f.display, text.count("\n", 0, m.start()) + 1,
                          f"HTML comment hidden from rendered view: \"{body[:80]}\"",
                          "Agents read comments; make sure nothing in it is an instruction you wouldn't approve.")


def _decode_tags(line: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0020 <= ord(c) <= 0xE007E)


# --------------------------------------------------------------------------- driver

def _load_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    # VS Code style JSONC: strip comments and trailing commas
    stripped = re.sub(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', lambda m: m.group(1) or "", text, flags=re.S)
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def check_file(f: AgentFile) -> List[Finding]:
    try:
        with open(f.path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []

    findings = list(check_secrets(f, text))
    # values AS001 already reported shouldn't be reported again by AS002
    seen_values = {hit.value for hit in find_in_text(text)}

    name = f.display.rsplit("/", 1)[-1]
    if f.path.endswith(".json"):
        data = _load_json(text)
        if data is None and text.strip():
            findings.append(Finding("AS015", LOW, f.display, 1, "not valid JSON; structural checks skipped"))
        else:
            findings.extend(check_mcp(f, text, data, seen_values))
            if "/.claude/" in "/" + f.display and name.startswith("settings"):
                findings.extend(check_claude_settings(f, text, data))
            if ".vscode/settings.json" in f.display or "Code/User/settings.json" in f.display:
                findings.extend(check_vscode_settings(f, text, data))

    if f.kind == "instructions":
        findings.extend(check_instructions(f, text))

    if f.tracked and (name in ("settings.local.json", "CLAUDE.local.md")):
        findings.append(Finding("AS013", LOW, f.display, 1,
                                f"{name} is meant to stay on your machine but is tracked in git",
                                f"git rm --cached {f.display} and add it to .gitignore."))
    return findings
