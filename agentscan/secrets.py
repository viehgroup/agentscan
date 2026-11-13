"""Secret detection tuned for the things that end up in agent configs.

Mostly provider-specific prefixes, which are precise. The generic check
only fires on values sitting under a key that's named like a secret,
which keeps the noise down.
"""

import math
import re
from typing import Iterator, NamedTuple, Optional

PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}")),
    ("OpenAI API key (legacy)", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Notion token", re.compile(r"\b(?:secret|ntn)_[A-Za-z0-9]{43,}\b")),
    ("Linear API key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("Database URL with password", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@\"']+:[^@\s\"'$]{3,}@")),
]

SECRET_KEY_NAME = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|private[_-]?key|access[_-]?key|auth|credential)")

# Things that look like secrets but are references or placeholders
PLACEHOLDER = re.compile(
    r"(?i)^(\$\{?[A-Z0-9_:\-]+\}?|\$\{env:[^}]+\}|\{\{.*\}\}|<[^>]+>|\[[^\]]+\]|"
    r"x{4,}|\*{3,}|your[_-].*|changeme|example.*|dummy.*|test.*|placeholder|todo|none|null|true|false|"
    r"env:.*|op://.*|vault:.*|secretref:.*)$"
)


class SecretHit(NamedTuple):
    kind: str
    value: str


def mask(value: str) -> str:
    url = re.match(r"^([a-z+]+://[^:/@\s]+:)[^@]+(@.*)?$", value)
    if url:
        return url.group(1) + "****@…"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:6]}…{value[-2:]} ({len(value)} chars)"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def find_in_text(text: str) -> Iterator[SecretHit]:
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            yield SecretHit(kind, m.group(0))


def looks_like_secret_value(key: str, value: str) -> Optional[str]:
    """For `KEY=value` style pairs. Returns a description or None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    for kind, rx in PATTERNS:
        if rx.search(v):
            return kind
    if not SECRET_KEY_NAME.search(key or ""):
        return None
    if len(v) < 12 or PLACEHOLDER.match(v) or " " in v or "$" in v:
        return None
    if entropy(v) < 3.0:
        return None
    return f"hardcoded value for {key}"
