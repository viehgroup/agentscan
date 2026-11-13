"""Find AI agent config and instruction files."""

import fnmatch
import os
import subprocess
from dataclasses import dataclass
from typing import Iterator, List, Optional, Set

# kind: "instructions" (read by the model), "mcp" (server definitions),
# "settings" (agent permissions and behaviour)
PROJECT_FILES = [
    # Claude Code
    ("CLAUDE.md", "instructions", "Claude Code"),
    ("CLAUDE.local.md", "instructions", "Claude Code"),
    (".claude/commands/*.md", "instructions", "Claude Code"),
    (".claude/agents/*.md", "instructions", "Claude Code"),
    (".claude/settings.json", "settings", "Claude Code"),
    (".claude/settings.local.json", "settings", "Claude Code"),
    (".mcp.json", "mcp", "Claude Code"),
    # Cursor
    (".cursorrules", "instructions", "Cursor"),
    (".cursor/rules/*.mdc", "instructions", "Cursor"),
    (".cursor/rules/*.md", "instructions", "Cursor"),
    (".cursor/mcp.json", "mcp", "Cursor"),
    # GitHub Copilot / VS Code
    (".github/copilot-instructions.md", "instructions", "Copilot"),
    (".github/instructions/*.md", "instructions", "Copilot"),
    (".github/prompts/*.md", "instructions", "Copilot"),
    (".vscode/mcp.json", "mcp", "VS Code"),
    (".vscode/settings.json", "settings", "VS Code"),
    # Windsurf, Cline, Roo
    (".windsurfrules", "instructions", "Windsurf"),
    (".windsurf/rules/*.md", "instructions", "Windsurf"),
    (".clinerules", "instructions", "Cline"),
    (".clinerules/*.md", "instructions", "Cline"),
    (".roo/mcp.json", "mcp", "Roo Code"),
    (".roo/rules/*.md", "instructions", "Roo Code"),
    # Gemini CLI, Continue, generic
    ("GEMINI.md", "instructions", "Gemini CLI"),
    (".gemini/settings.json", "settings", "Gemini CLI"),
    (".continue/config.json", "settings", "Continue"),
    (".continue/config.yaml", "settings", "Continue"),
    ("AGENTS.md", "instructions", "AGENTS.md"),
    ("mcp.json", "mcp", "MCP"),
]

HOME_FILES = [
    ("~/.claude.json", "mcp", "Claude Code"),
    ("~/.claude/settings.json", "settings", "Claude Code"),
    ("~/.claude/CLAUDE.md", "instructions", "Claude Code"),
    ("~/.cursor/mcp.json", "mcp", "Cursor"),
    ("~/.codeium/windsurf/mcp_config.json", "mcp", "Windsurf"),
    ("~/.gemini/settings.json", "settings", "Gemini CLI"),
    ("~/.continue/config.json", "settings", "Continue"),
    ("~/.continue/config.yaml", "settings", "Continue"),
    ("~/Library/Application Support/Claude/claude_desktop_config.json", "mcp", "Claude Desktop"),
    ("~/.config/Claude/claude_desktop_config.json", "mcp", "Claude Desktop"),
    ("~/AppData/Roaming/Claude/claude_desktop_config.json", "mcp", "Claude Desktop"),
    ("~/Library/Application Support/Code/User/settings.json", "settings", "VS Code"),
    ("~/.config/Code/User/settings.json", "settings", "VS Code"),
    ("~/Library/Application Support/Code/User/mcp.json", "mcp", "VS Code"),
    ("~/.config/Code/User/mcp.json", "mcp", "VS Code"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build",
             ".next", ".cache", "site-packages", "vendor", "target", ".terraform"}
MAX_BYTES = 2 * 1024 * 1024


@dataclass
class AgentFile:
    path: str      # absolute
    display: str   # relative to the scan root, or ~/...
    kind: str
    tool: str
    tracked: Optional[bool] = None  # in git? None if unknown


def _rel_pattern_match(rel: str, pattern: str) -> bool:
    rel = rel.replace(os.sep, "/")
    # a pattern can match at any depth so monorepos are covered
    return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, "*/" + pattern)


def _classify(rel: str):
    for pattern, kind, tool in PROJECT_FILES:
        if _rel_pattern_match(rel, pattern):
            if pattern == "mcp.json" and "/" in rel.replace(os.sep, "/"):
                # a bare mcp.json deep in a tree is too generic to trust
                parent = os.path.basename(os.path.dirname(rel))
                if parent not in (".vscode", ".cursor", ".roo", ""):
                    continue
            return kind, tool
    return None


def _git_tracked(root: str) -> Optional[Set[str]]:
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True,
                             timeout=20, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {p for p in out.stdout.decode("utf-8", "replace").split("\0") if p}


def scan_project(root: str) -> List[AgentFile]:
    root = os.path.abspath(root)
    tracked = _git_tracked(root)
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            hit = _classify(rel)
            if not hit:
                continue
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
            except OSError:
                continue
            is_tracked = None if tracked is None else rel.replace(os.sep, "/") in tracked
            found.append(AgentFile(full, rel.replace(os.sep, "/"), hit[0], hit[1], is_tracked))
    found.sort(key=lambda f: f.display)
    return found


def scan_home() -> List[AgentFile]:
    out = []
    for pattern, kind, tool in HOME_FILES:
        path = os.path.expanduser(pattern)
        if os.path.isfile(path):
            out.append(AgentFile(path, pattern, kind, tool, None))
    return out


def iter_all(root: Optional[str], home: bool) -> Iterator[AgentFile]:
    if root:
        yield from scan_project(root)
    if home:
        yield from scan_home()
