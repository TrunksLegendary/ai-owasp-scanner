"""Core data types shared by the static and dynamic scan engines."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Outcome of checking one OWASP category against one target.

    NOT_CHECKED is distinct from NOT_FOUND on purpose: a static-only scan
    cannot prove anything about runtime behaviour, and reporting that as a
    clean result would be a false assurance.
    """

    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    NOT_CHECKED = "NOT_CHECKED"
    ERROR = "ERROR"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Evidence:
    """Where and why a detector fired."""

    location: str          # file path with :line, or the probed URL
    snippet: str = ""      # the matching source line or response excerpt
    detail: str = ""       # human-readable explanation


@dataclass
class Finding:
    """One concrete piece of evidence for one OWASP category."""

    category_id: str       # e.g. "LLM01"
    rule_id: str           # e.g. "LLM01-STATIC-CONCAT-PROMPT"
    title: str
    severity: Severity
    confidence: Confidence
    source: str            # "static" | "dynamic"
    evidence: Evidence
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class CategoryResult:
    """Rolled-up status for a single OWASP Top 10 category."""

    category_id: str
    title: str
    status: Status
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])

    def to_dict(self) -> dict[str, Any]:
        sev = self.highest_severity
        return {
            "category_id": self.category_id,
            "title": self.title,
            "status": self.status.value,
            "highest_severity": sev.value if sev else None,
            "finding_count": len(self.findings),
            "checks_run": self.checks_run,
            "note": self.note,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    """Everything one scan run produced."""

    target: str
    scan_modes: list[str]
    started_at: str
    finished_at: str = ""
    categories: list[CategoryResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @property
    def found_count(self) -> int:
        return sum(1 for c in self.categories if c.status is Status.FOUND)

    @property
    def total_findings(self) -> int:
        return sum(len(c.findings) for c in self.categories)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_modes": self.scan_modes,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "categories_total": len(self.categories),
                "categories_found": self.found_count,
                "categories_not_found": sum(
                    1 for c in self.categories if c.status is Status.NOT_FOUND
                ),
                "categories_not_checked": sum(
                    1 for c in self.categories if c.status is Status.NOT_CHECKED
                ),
                "total_findings": self.total_findings,
            },
            "stats": self.stats,
            "errors": self.errors,
            "categories": [c.to_dict() for c in self.categories],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
