import json
import shutil
import textwrap
from collections import defaultdict
from typing import List

from . import __version__
from .checks import HIGH, LOW, MEDIUM, RULES, SEVERITY_ORDER, Finding
from .discover import AgentFile

_COLORS = {HIGH: "31", MEDIUM: "33", LOW: "36", "dim": "2", "bold": "1"}


def _paint(on: bool):
    return lambda s, k: f"\033[{_COLORS[k]}m{s}\033[0m" if on else s


def text(files: List[AgentFile], findings: List[Finding], color: bool) -> str:
    p = _paint(color)
    width = min(100, shutil.get_terminal_size((80, 24)).columns)
    out = []
    by_file = defaultdict(list)
    for fd in findings:
        by_file[fd.file].append(fd)

    for f in files:
        items = sorted(by_file.get(f.display, []), key=lambda x: (-SEVERITY_ORDER[x.severity], x.line))
        if not items:
            continue
        out.append(p(f.display, "bold") + p(f"  ({f.tool})", "dim"))
        for fd in items:
            tag = p(f"{fd.severity:<6}", fd.severity)
            head = f"  {tag} {fd.rule}  line {fd.line}"
            out.append(head)
            for line in textwrap.wrap(fd.message, width - 4, break_on_hyphens=False):
                out.append("    " + line)
            if fd.fix:
                for i, line in enumerate(textwrap.wrap(fd.fix, width - 9, break_on_hyphens=False)):
                    out.append(("    fix: " if i == 0 else "         ") + p(line, "dim"))
        out.append("")

    counts = {s: sum(1 for x in findings if x.severity == s) for s in (HIGH, MEDIUM, LOW)}
    if findings:
        summary = ", ".join(p(f"{n} {s}", s) for s, n in counts.items() if n)
        out.append(f"{len(files)} agent file{'s' if len(files) != 1 else ''} scanned: {summary}")
    elif files:
        out.append(f"{len(files)} agent file{'s' if len(files) != 1 else ''} scanned, nothing found.")
    else:
        out.append("No AI agent config files found.")
    return "\n".join(out)


def as_json(files: List[AgentFile], findings: List[Finding]) -> str:
    return json.dumps({
        "version": __version__,
        "files": [{"path": f.display, "tool": f.tool, "kind": f.kind, "tracked": f.tracked} for f in files],
        "findings": [fd.__dict__ for fd in findings],
    }, indent=2)


def sarif(findings: List[Finding]) -> str:
    level = {HIGH: "error", MEDIUM: "warning", LOW: "note"}
    used = sorted({fd.rule for fd in findings})
    rules = [{
        "id": rid,
        "name": RULES[rid][0].replace(" ", ""),
        "shortDescription": {"text": RULES[rid][0]},
        "fullDescription": {"text": RULES[rid][1]},
        "helpUri": "https://github.com/viehgroup/agentscan#rules",
    } for rid in used]
    results = [{
        "ruleId": fd.rule,
        "level": level[fd.severity],
        "message": {"text": fd.message + (f" Fix: {fd.fix}" if fd.fix else "")},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": fd.file},
            "region": {"startLine": max(1, fd.line)},
        }}],
    } for fd in findings if not fd.file.startswith("~")]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "agentscan", "version": __version__,
                                "informationUri": "https://github.com/viehgroup/agentscan",
                                "rules": rules}},
            "results": results,
        }],
    }, indent=2)


def github(findings: List[Finding]) -> str:
    """GitHub Actions workflow commands: shows up inline on pull requests."""
    kind = {HIGH: "error", MEDIUM: "warning", LOW: "notice"}

    def esc(s: str) -> str:
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def esc_prop(s: str) -> str:
        return esc(s).replace(":", "%3A").replace(",", "%2C")

    lines = []
    for fd in findings:
        title = f"{fd.rule} {RULES[fd.rule][0]}"
        msg = fd.message + (f". Fix: {fd.fix}" if fd.fix else "")
        lines.append(f"::{kind[fd.severity]} file={esc_prop(fd.file)},line={fd.line},"
                     f"title={esc_prop(title)}::{esc(msg)}")
    return "\n".join(lines)
