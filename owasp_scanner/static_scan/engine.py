"""Static analysis engine.

Three kinds of check run over a codebase:

1. Line rules (`rules.py`) — a single regex against a single line.
2. Taint heuristic — tracks variables assigned from an LLM call and reports
   when one reaches a dangerous sink. This is what makes LLM05 findings
   meaningful rather than "this file contains eval()".
3. Absence checks — a control that *should* be present isn't (no max_tokens,
   no timeout, no rate limiting). These can only be decided per file or per
   project, not per line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import (
    CategoryResult,
    Confidence,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    Status,
)
from .. import knowledge
from ..redaction import redact
from . import patterns as P
from .rules import RULES


MAX_SNIPPET = 180
MAX_FINDINGS_PER_RULE = 25


def _snippet(line: str) -> str:
    s = redact(line.strip())
    return s[:MAX_SNIPPET] + ("…" if len(s) > MAX_SNIPPET else "")


class FileUnit:
    """One scannable file, normalized to a list of (line_no, text)."""

    def __init__(self, path: Path, root: Path):
        self.path = path
        self.rel = str(path.relative_to(root)).replace("\\", "/")
        self.suffix = path.suffix.lower()
        self.lines: list[tuple[int, str]] = []
        self.text = ""

    def load(self) -> bool:
        try:
            if self.path.stat().st_size > P.MAX_FILE_BYTES:
                return False
            raw = self.path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            return False

        if self.suffix == ".ipynb":
            raw = self._notebook_source(raw)

        self.text = raw
        self.lines = [(i + 1, ln) for i, ln in enumerate(raw.splitlines())]
        return True

    @staticmethod
    def _notebook_source(raw: str) -> str:
        """Flatten a notebook to just its code cells, preserving line count roughly."""
        try:
            nb = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        out: list[str] = []
        for cell in nb.get("cells", []):
            if cell.get("cell_type") != "code":
                continue
            src = cell.get("source", [])
            out.extend(s.rstrip("\n") for s in (src if isinstance(src, list) else [src]))
        return "\n".join(out)


def iter_files(root: Path) -> list[Path]:
    """Walk the target tree, skipping vendored and build directories."""
    found: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if entry.name not in P.SKIP_DIRS and not entry.name.startswith("."):
                        stack.append(entry)
                elif entry.is_file():
                    suffix = entry.suffix.lower()
                    if suffix in P.CODE_EXTENSIONS or suffix in P.CONFIG_EXTENSIONS:
                        found.append(entry)
            except OSError:
                continue
    return found


# --------------------------------------------------------------------------
# Taint heuristic: model output -> dangerous sink
# --------------------------------------------------------------------------

ASSIGN = re.compile(
    r"""^\s*
    (?:const\s+|let\s+|var\s+|final\s+)?
    (?P<var>[A-Za-z_$][\w$]*)
    \s*(?::\s*[^=]+?)?\s*=\s*(?!=)
    (?P<rhs>.*)$
    """,
    re.VERBOSE,
)


def _tainted_variables(unit: FileUnit) -> dict[str, int]:
    """Variables that plausibly hold model output, mapped to the line that set them.

    Two passes so that `text = response.choices[0].message.content` inherits
    taint from `response = client.chat.completions.create(...)`.
    """
    tainted: dict[str, int] = {}

    for lineno, line in unit.lines:
        m = ASSIGN.match(line)
        if not m:
            continue
        var, rhs = m.group("var"), m.group("rhs")
        if P.LLM_CALL.search(rhs):
            tainted[var] = lineno
        elif P.LLM_OUTPUT_NAMES.fullmatch(var) or P.LLM_OUTPUT_NAMES.match(var):
            # Naming convention alone is weak evidence, but only counts when the
            # file actually talks to a model somewhere.
            if P.LLM_CALL.search(unit.text):
                tainted.setdefault(var, lineno)

    # Propagate through response-shape accessors and simple transforms.
    for _ in range(3):
        grew = False
        for lineno, line in unit.lines:
            m = ASSIGN.match(line)
            if not m:
                continue
            var, rhs = m.group("var"), m.group("rhs")
            if var in tainted:
                continue
            for src in list(tainted):
                if re.search(rf"\b{re.escape(src)}\b", rhs):
                    if P.LLM_RESPONSE_ACCESS.search(rhs) or len(rhs) < 120:
                        tainted[var] = lineno
                        grew = True
                        break
        if not grew:
            break

    return tainted


def _is_interpolated(line: str, var: str) -> bool:
    """True if `var` is spliced into a string rather than passed as an argument.

    A parameterized query (`execute("… VALUES (?)", (answer,))`) is the correct,
    safe pattern; only interpolation into the statement text is an injection.
    """
    v = re.escape(var)
    return bool(
        re.search(rf"""f["'][^"']*\{{[^}}]*\b{v}\b""", line)
        or re.search(rf"""\+\s*{v}\b|\b{v}\s*\+""", line)
        or re.search(rf"""%\s*\(?\s*{v}\b""", line)
        or re.search(rf"""\.\s*format\s*\([^)]*\b{v}\b""", line)
        or re.search(rf"""`[^`]*\$\{{[^}}]*\b{v}\b""", line)
    )


# Sinks where merely passing the value as an argument is already unsafe.
# For the rest, the value must be interpolated into a statement/markup string.
ALWAYS_UNSAFE_SINKS = {
    "code_execution", "shell_execution", "deserialization", "ssrf_http", "file_write",
}


def _taint_findings(unit: FileUnit) -> list[Finding]:
    """Report model-output variables that reach a dangerous sink (LLM05)."""
    tainted = _tainted_variables(unit)
    if not tainted:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for lineno, line in unit.lines:
        for sink_name, sink_re in P.SINKS.items():
            if not sink_re.search(line):
                continue
            for var, origin_line in tainted.items():
                if origin_line == lineno:
                    continue
                if not re.search(rf"\b{re.escape(var)}\b", line):
                    continue
                if sink_name not in ALWAYS_UNSAFE_SINKS and not _is_interpolated(line, var):
                    continue
                key = (sink_name, lineno)
                if key in seen:
                    continue
                seen.add(key)

                label = P.SINK_LABELS[sink_name]
                findings.append(
                    Finding(
                        category_id="LLM05",
                        rule_id=f"LLM05-TAINT-{sink_name.upper()}",
                        title=f"Model output reaches {label}",
                        severity=Severity(P.SINK_SEVERITY[sink_name]),
                        confidence=Confidence.HIGH,
                        source="static",
                        evidence=Evidence(
                            location=f"{unit.rel}:{lineno}",
                            snippet=_snippet(line),
                            detail=(
                                f"`{var}` holds model output (assigned at line {origin_line}) "
                                f"and is used here in {label}. LLM05 treats model output as "
                                f"untrusted user input, so this is an injection path the "
                                f"attacker reaches through the prompt."
                            ),
                        ),
                        remediation=(
                            "Validate model output against a strict allow-list before use. "
                            "For SQL use parameterized queries; for HTML apply context-aware "
                            "encoding; never pass model output to eval, exec or a shell."
                        ),
                    )
                )
                break

    return findings


# --------------------------------------------------------------------------
# Multi-line system prompt blocks (LLM07)
# --------------------------------------------------------------------------

SYSTEM_PROMPT_ASSIGN = re.compile(
    r"""(?ix)
    ^\s*(?:const\s+|let\s+|var\s+)?
    (?:\w*(?:system|sys)_?(?:prompt|message|msg|instruction|persona|role)\w*
      |\w*(?:prompt|instruction)s?_?(?:template|text|header)?\w*)
    \s*(?::\s*\w+)?\s*=\s*(?P<q>\"\"\"|'''|`)
    """
)

SECRET_IN_TEXT = re.compile(
    r"""(?ix)
      \bsk-[A-Za-z0-9_\-]{16,}
    | \bAKIA[0-9A-Z]{16}
    | \bAIza[0-9A-Za-z_\-]{35}
    | \b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s"']{8,}
    | \b(?:api[\s_-]?key|password|passwd|secret|bearer\stoken|access[\s_-]?token)\b
      [^\n]{0,30}?(?:is|=|:)\s*\S{8,}
    """
)

AUTHZ_IN_TEXT = re.compile(
    r"""(?ix)
      \bonly\s+(?:if|when)\s+the\s+user\s+is\b
    | \bif\s+the\s+user\s+is\s+(?:an?\s+)?(?:admin|administrator|manager|premium|staff)\b
    | \bnever\s+(?:reveal|disclose|show|share|output)\b
    | \bdo\s+not\s+(?:reveal|disclose|show|share)\b
    | \b(?:admins?|administrators?)\s+(?:only|may|can)\b
    """
)


def _system_prompt_blocks(unit: FileUnit) -> list[tuple[int, str]]:
    """Find multi-line string literals assigned to system-prompt-shaped names.

    A line-oriented rule cannot see a secret sitting three lines inside a
    triple-quoted prompt, which is exactly where these secrets tend to live.
    """
    blocks: list[tuple[int, str]] = []
    lines = unit.lines
    i = 0
    while i < len(lines):
        lineno, line = lines[i]
        m = SYSTEM_PROMPT_ASSIGN.match(line)
        if not m:
            i += 1
            continue
        quote = m.group("q")
        rest = line[m.end():]
        if quote in rest:  # opens and closes on the same line
            blocks.append((lineno, rest[: rest.index(quote)]))
            i += 1
            continue
        collected = [rest]
        j = i + 1
        while j < len(lines) and len(collected) < 200:
            _, nxt = lines[j]
            if quote in nxt:
                collected.append(nxt[: nxt.index(quote)])
                break
            collected.append(nxt)
            j += 1
        blocks.append((lineno, "\n".join(collected)))
        i = j + 1
    return blocks


def _system_prompt_findings(unit: FileUnit) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, block in _system_prompt_blocks(unit):
        secret = SECRET_IN_TEXT.search(block)
        if secret:
            hit = secret.group(0).strip()
            masked = hit[:8] + "…" if len(hit) > 12 else hit
            findings.append(
                Finding(
                    category_id="LLM07",
                    rule_id="LLM07-SECRET-IN-PROMPT-BLOCK",
                    title="Credential embedded in a multi-line system prompt",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    source="static",
                    evidence=Evidence(
                        location=f"{unit.rel}:{lineno}",
                        snippet=_snippet(masked),
                        detail=(
                            "The system prompt block starting on this line contains a "
                            "credential. LLM07 exists because prompts do leak, so treat "
                            "this secret as already disclosed."
                        ),
                    ),
                    remediation=(
                        "Rotate the credential and remove it from the prompt. The "
                        "application should hold secrets and make privileged calls in "
                        "code, never the model."
                    ),
                )
            )

        authz = AUTHZ_IN_TEXT.search(block)
        if authz:
            findings.append(
                Finding(
                    category_id="LLM07",
                    rule_id="LLM07-AUTHZ-IN-PROMPT-BLOCK",
                    title="Access-control rule written into a system prompt",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source="static",
                    evidence=Evidence(
                        location=f"{unit.rel}:{lineno}",
                        snippet=_snippet(authz.group(0)),
                        detail=(
                            "Authorization is being enforced by prompt text. That is not a "
                            "security boundary: once the prompt leaks the rules are known, "
                            "and the model can be argued out of them regardless."
                        ),
                    ),
                    remediation=(
                        "Move the check into deterministic application code outside the "
                        "LLM; keep the prompt for tone and task framing only."
                    ),
                )
            )
    return findings


# --------------------------------------------------------------------------
# Absence checks
# --------------------------------------------------------------------------

HAS_MAX_TOKENS = re.compile(r"(?i)\bmax_?(?:tokens|output_tokens|new_tokens|completion_tokens)\b")
HAS_TIMEOUT = re.compile(r"(?i)\btimeout\s*[:=]|\brequest_timeout\b|\bmax_retries\b")
HAS_RATE_LIMIT = re.compile(
    r"(?i)\bratelimit|\brate_limit|\blimiter\b|\bslowapi\b|\bthrottl|"
    r"\bexpress-rate-limit\b|\bbucket4j\b|\bquota\b"
)


def _absence_findings(unit: FileUnit) -> list[Finding]:
    findings: list[Finding] = []

    call_lines = [(n, ln) for n, ln in unit.lines if P.LLM_CALL.search(ln)]
    if not call_lines:
        return findings

    if not HAS_MAX_TOKENS.search(unit.text):
        lineno, line = call_lines[0]
        findings.append(
            Finding(
                category_id="LLM10",
                rule_id="LLM10-NO-MAX-TOKENS",
                title="Model invoked without an output token cap",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                source="static",
                evidence=Evidence(
                    location=f"{unit.rel}:{lineno}",
                    snippet=_snippet(line),
                    detail=(
                        f"{unit.rel} calls a model but never sets a max token limit. "
                        "Output length is then bounded only by the provider default, which "
                        "is the denial-of-wallet case in LLM10."
                    ),
                ),
                remediation="Set max_tokens (or the provider equivalent) on every model call.",
            )
        )

    if not HAS_TIMEOUT.search(unit.text):
        lineno, line = call_lines[0]
        findings.append(
            Finding(
                category_id="LLM10",
                rule_id="LLM10-NO-TIMEOUT",
                title="Model call with no timeout configured",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                source="static",
                evidence=Evidence(
                    location=f"{unit.rel}:{lineno}",
                    snippet=_snippet(line),
                    detail="No timeout is set, so a slow or hung provider call ties up the worker.",
                ),
                remediation="Set an explicit timeout and a bounded retry policy on model calls.",
            )
        )

    return findings


def _project_findings(units: list[FileUnit], root: Path) -> list[Finding]:
    """Checks that need a whole-project view."""
    findings: list[Finding] = []
    uses_llm = any(P.LLM_CALL.search(u.text) for u in units)
    if not uses_llm:
        return findings

    if not any(HAS_RATE_LIMIT.search(u.text) for u in units):
        findings.append(
            Finding(
                category_id="LLM10",
                rule_id="LLM10-NO-RATE-LIMITING",
                title="No rate limiting found anywhere in the project",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                source="static",
                evidence=Evidence(
                    location=str(root),
                    snippet="",
                    detail=(
                        "The project calls a model but no rate limiting, throttling or quota "
                        "mechanism was found in any scanned file. LLM10 lists per-user rate "
                        "limiting as the primary control against both denial of service and "
                        "denial of wallet."
                    ),
                ),
                remediation=(
                    "Add per-identity rate limiting and a spend quota in front of every "
                    "model-backed endpoint, and alert on consumption anomalies."
                ),
            )
        )

    return findings


# --------------------------------------------------------------------------
# Rule execution
# --------------------------------------------------------------------------

def _rule_findings(unit: FileUnit) -> list[Finding]:
    findings: list[Finding] = []
    counts: dict[str, int] = {}

    for rule in RULES:
        if rule.extensions and unit.suffix not in rule.extensions:
            continue
        # requirements-style rule should only look at requirements files
        if rule.id == "LLM03-UNPINNED-DEPENDENCY" and "requirements" not in unit.rel.lower():
            continue

        for lineno, line in unit.lines:
            if not line.strip() or line.lstrip().startswith(("#", "//", "*")):
                continue
            if not rule.pattern.search(line):
                continue
            if rule.suppress_if and rule.suppress_if.search(line):
                continue
            if counts.get(rule.id, 0) >= MAX_FINDINGS_PER_RULE:
                break
            counts[rule.id] = counts.get(rule.id, 0) + 1

            findings.append(
                Finding(
                    category_id=rule.category_id,
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    source="static",
                    evidence=Evidence(
                        location=f"{unit.rel}:{lineno}",
                        snippet=_snippet(line),
                        detail=rule.detail,
                    ),
                    remediation=rule.remediation,
                )
            )

    return findings


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def scan_path(root: Path, result: ScanResult) -> dict[str, list[Finding]]:
    """Scan a directory (or single file) and return findings grouped by category."""
    root = root.resolve()
    paths = [root] if root.is_file() else iter_files(root)
    base = root.parent if root.is_file() else root

    units: list[FileUnit] = []
    for path in paths:
        unit = FileUnit(path, base)
        if unit.load():
            units.append(unit)

    all_findings: list[Finding] = []
    for unit in units:
        all_findings.extend(_rule_findings(unit))
        all_findings.extend(_taint_findings(unit))
        all_findings.extend(_system_prompt_findings(unit))
        all_findings.extend(_absence_findings(unit))
    all_findings.extend(_project_findings(units, root))

    result.stats["files_scanned"] = len(units)
    result.stats["lines_scanned"] = sum(len(u.lines) for u in units)
    result.stats["llm_files_detected"] = sum(1 for u in units if P.LLM_CALL.search(u.text))

    grouped: dict[str, list[Finding]] = {c.id: [] for c in knowledge.CATEGORIES}
    for finding in all_findings:
        grouped.setdefault(finding.category_id, []).append(finding)
    return grouped


# Which categories the static engine is genuinely able to assess.
STATIC_CHECKED_CATEGORIES = {
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
    "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
}


def build_category_results(grouped: dict[str, list[Finding]]) -> list[CategoryResult]:
    results: list[CategoryResult] = []
    for cat in knowledge.CATEGORIES:
        findings = grouped.get(cat.id, [])
        checked = cat.id in STATIC_CHECKED_CATEGORIES
        if findings:
            status = Status.FOUND
        elif checked:
            status = Status.NOT_FOUND
        else:
            status = Status.NOT_CHECKED
        rule_ids = sorted({r.id for r in RULES if r.category_id == cat.id})
        results.append(
            CategoryResult(
                category_id=cat.id,
                title=cat.title,
                status=status,
                findings=findings,
                checks_run=[f"static:{rid}" for rid in rule_ids],
            )
        )
    return results
