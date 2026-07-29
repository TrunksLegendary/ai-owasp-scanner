"""Terminal summary of a scan result."""

from __future__ import annotations

import os
import sys

from ..models import ScanResult, Status

_USE_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)

_C = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "grey": "\033[90m", "bold": "\033[1m", "off": "\033[0m",
}


def _c(text: str, *names: str) -> str:
    if not _USE_COLOR:
        return text
    return "".join(_C[n] for n in names) + text + _C["off"]


_STATUS_STYLE = {
    Status.FOUND:       ("  FOUND    ", "red"),
    Status.NOT_FOUND:   ("  NOT FOUND", "green"),
    Status.NOT_CHECKED: ("NOT CHECKED", "grey"),
    Status.ERROR:       ("  ERROR    ", "yellow"),
}

_SEV_COLOR = {
    "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "grey",
}


def render(result: ScanResult, show_findings: bool = True, max_per_category: int = 5) -> str:
    out: list[str] = []
    w = 74

    out.append("")
    out.append(_c("  OWASP Top 10 for LLM Applications — Scan Report", "bold"))
    out.append(_c("  " + "─" * w, "grey"))
    out.append(f"  Target : {result.target}")
    out.append(f"  Mode   : {', '.join(result.scan_modes)}")
    out.append(f"  Time   : {result.finished_at or result.started_at}")
    if result.stats:
        bits = []
        if "files_scanned" in result.stats:
            bits.append(f'{result.stats["files_scanned"]} files')
        if "lines_scanned" in result.stats:
            bits.append(f'{result.stats["lines_scanned"]:,} lines')
        if "probes_run" in result.stats:
            bits.append(f'{result.stats["probes_run"]} probes')
        if bits:
            out.append(f"  Scope  : {', '.join(bits)}")
    out.append("")

    for cat in result.categories:
        label, color = _STATUS_STYLE[cat.status]
        badge = _c(f"[{label}]", color, "bold")
        line = f"  {badge}  {_c(cat.category_id, 'bold')}  {cat.title}"
        if cat.status is Status.FOUND:
            sev = cat.highest_severity
            n = len(cat.findings)
            line += _c(f"  ({n} finding{'s' if n != 1 else ''}, "
                       f"highest {sev.value.lower() if sev else 'n/a'})", "grey")
        out.append(line)

        if show_findings and cat.status is Status.FOUND:
            for finding in cat.findings[:max_per_category]:
                sev = _c(f"{finding.severity.value:<8}", _SEV_COLOR[finding.severity.value])
                out.append(f"                 {sev} {finding.title}")
                out.append(_c(f"                          {finding.evidence.location}", "grey"))
            extra = len(cat.findings) - max_per_category
            if extra > 0:
                out.append(_c(f"                          … and {extra} more", "grey"))
            out.append("")

    out.append(_c("  " + "─" * w, "grey"))
    found = result.found_count
    verdict_color = "red" if found else "green"
    out.append(
        f"  {_c(str(found), verdict_color, 'bold')} of {len(result.categories)} categories "
        f"flagged · {result.total_findings} findings total"
    )
    unchecked = sum(1 for c in result.categories if c.status is Status.NOT_CHECKED)
    if unchecked:
        out.append(_c(
            f"  {unchecked} categories NOT CHECKED — no applicable check ran; "
            f"this is not an all-clear.", "grey"
        ))
    if result.errors:
        out.append(_c(f"  {len(result.errors)} scan warnings (see JSON report)", "yellow"))
    out.append("")
    return "\n".join(out)
