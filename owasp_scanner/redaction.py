"""Masking for anything that lands in a report.

Scan reports get committed, emailed and pasted into tickets. A tool that finds
a hard-coded key and then reprints it in full has moved the secret somewhere
with a wider audience, so every snippet and excerpt passes through here first.
"""

from __future__ import annotations

import re

SECRET_PATTERNS = re.compile(
    r"""(?x)
      \bsk-(?:proj-|ant-|or-|admin-)?[A-Za-z0-9_\-]{16,}
    | \bAKIA[0-9A-Z]{16}
    | \bAIza[0-9A-Za-z_\-]{35}
    | \bghp_[A-Za-z0-9]{36}
    | \bhf_[A-Za-z0-9]{34,}
    | \bxox[baprs]-[A-Za-z0-9\-]{10,}
    | \b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s"'`]{6,}
    | -----BEGIN[^-]{0,40}PRIVATE\s+KEY-----
    | \beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}
    """
)

# Value side of `password = "..."` style assignments.
ASSIGNED_SECRET = re.compile(
    r"""(?ix)
    (?P<key>\b[\w.]*(?:api[_-]?key|apikey|secret|token|password|passwd|
        access[_-]?key|private[_-]?key|auth[_-]?token|bearer)[\w.]*
        \s*[:=]\s*)
    (?P<quote>["'])(?P<value>[^"']{8,})(?P=quote)
    """
)


def _mask(value: str) -> str:
    """Keep just enough to identify which secret this was."""
    value = value.strip()
    if len(value) <= 10:
        return "***REDACTED***"
    return f"{value[:6]}…{value[-3:]} [REDACTED {len(value)} chars]"


def redact(text: str) -> str:
    """Mask credential-shaped substrings, leaving surrounding context readable."""
    if not text:
        return text

    def _sub_assigned(m: re.Match[str]) -> str:
        return f'{m.group("key")}{m.group("quote")}{_mask(m.group("value"))}{m.group("quote")}'

    text = ASSIGNED_SECRET.sub(_sub_assigned, text)
    text = SECRET_PATTERNS.sub(lambda m: _mask(m.group(0)), text)
    return text
