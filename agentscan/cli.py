import argparse
import os
import sys

from . import __version__, report
from .checks import RULES, SEVERITY_ORDER, check_file
from .discover import iter_all


def build_parser():
    p = argparse.ArgumentParser(
        prog="agentscan",
        description="Find leaked keys, risky permissions and hidden instructions in AI agent configs "
                    "(Claude Code, Cursor, Copilot, Windsurf, Gemini CLI, MCP and more).",
    )
    p.add_argument("path", nargs="?", default=".", help="project to scan (default: current directory)")
    p.add_argument("--home", action="store_true",
                   help="also scan your user-level configs (~/.claude.json, Cursor, Claude Desktop, ...)")
    p.add_argument("--no-project", action="store_true", help="with --home, skip the project directory")
    p.add_argument("--format", choices=["text", "json", "sarif", "github"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                   help="exit 1 if anything at or above this severity is found (default: high)")
    p.add_argument("--ignore", action="append", default=[], metavar="RULE",
                   help="skip a rule, e.g. --ignore AS012 (repeatable)")
    p.add_argument("--list-rules", action="store_true", help="show all rules and exit")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"agentscan {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for rid, (title, desc) in RULES.items():
            print(f"{rid}  {title}\n       {desc}")
        return 0

    root = None if args.no_project else args.path
    if root and not os.path.isdir(root):
        print(f"agentscan: {root}: not a directory", file=sys.stderr)
        return 2

    ignore = {r.upper() for r in args.ignore}
    files = list(iter_all(root, args.home))
    findings = [fd for f in files for fd in check_file(f) if fd.rule not in ignore]

    if args.format in ("sarif", "github") and root:
        # annotations and SARIF need paths relative to the repo root (cwd in CI),
        # not to the directory that was scanned
        prefix = os.path.relpath(os.path.abspath(root), os.getcwd()).replace(os.sep, "/")
        if prefix != "." and not prefix.startswith(".."):
            for fd in findings:
                if not fd.file.startswith("~"):
                    fd.file = f"{prefix}/{fd.file}"

    if args.format == "json":
        out = report.as_json(files, findings)
    elif args.format == "sarif":
        out = report.sarif(findings)
    elif args.format == "github":
        out = report.github(findings)
    else:
        color = (not args.output and sys.stdout.isatty() and not args.no_color
                 and "NO_COLOR" not in os.environ)
        out = report.text(files, findings, color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    elif out:
        print(out)

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
