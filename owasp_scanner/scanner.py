"""Orchestration: run the requested engines and merge their results."""

from __future__ import annotations

from pathlib import Path

from . import knowledge
from .models import CategoryResult, Finding, ScanResult, Status
from .static_scan import engine as static_engine
from .dynamic_scan import engine as dynamic_engine
from .dynamic_scan.engine import Target


def _merge(
    static_results: list[CategoryResult] | None,
    dynamic_results: list[CategoryResult] | None,
) -> list[CategoryResult]:
    """Combine per-engine verdicts into one status per category.

    FOUND wins over everything. NOT_FOUND only stands if at least one engine
    actually ran a check — otherwise the category stays NOT_CHECKED, because
    "we didn't look" must never render as "we looked and it's fine".
    """
    merged: list[CategoryResult] = []
    by_id_static = {c.category_id: c for c in (static_results or [])}
    by_id_dynamic = {c.category_id: c for c in (dynamic_results or [])}

    for cat in knowledge.CATEGORIES:
        s = by_id_static.get(cat.id)
        d = by_id_dynamic.get(cat.id)

        findings: list[Finding] = []
        checks: list[str] = []
        notes: list[str] = []
        for part in (s, d):
            if part is None:
                continue
            findings.extend(part.findings)
            checks.extend(part.checks_run)
            if part.note:
                notes.append(part.note)

        if findings:
            status = Status.FOUND
        elif checks:
            status = Status.NOT_FOUND
        else:
            status = Status.NOT_CHECKED

        findings.sort(key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value],
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f.confidence.value],
        ))

        merged.append(
            CategoryResult(
                category_id=cat.id,
                title=cat.title,
                status=status,
                findings=findings,
                checks_run=checks,
                note=" ".join(notes) if status is Status.NOT_CHECKED else "",
            )
        )
    return merged


def run_scan(
    code_path: Path | None = None,
    target: Target | None = None,
    verbose: bool = False,
) -> ScanResult:
    if code_path is None and target is None:
        raise ValueError("Provide a code path, a live target, or both.")

    modes = []
    if code_path is not None:
        modes.append("static")
    if target is not None:
        modes.append("dynamic")

    target_label = " + ".join(
        p for p in (str(code_path) if code_path else "", target.url if target else "") if p
    )

    result = ScanResult(
        target=target_label,
        scan_modes=modes,
        started_at=ScanResult.now(),
    )

    static_results = None
    if code_path is not None:
        if verbose:
            print(f"[static] scanning {code_path} …")
        grouped = static_engine.scan_path(Path(code_path), result)
        static_results = static_engine.build_category_results(grouped)

    dynamic_results = None
    if target is not None:
        if verbose:
            print(f"[dynamic] probing {target.url} …")
        grouped = dynamic_engine.scan_target(target, result, verbose=verbose)
        dynamic_results = dynamic_engine.build_category_results(
            grouped, result.stats.get("probe_ids", [])
        )

    result.categories = _merge(static_results, dynamic_results)
    result.finished_at = ScanResult.now()
    return result
