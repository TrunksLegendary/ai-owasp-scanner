"""Regression tests for the static engine.

The two sample apps are the contract: the vulnerable fixture must trip every
category, and the secure fixture must trip none. A change that blurs that
separation is a regression regardless of how it looks on real code.

Run with:  python -m pytest tests -q     (or: python tests/test_static_scan.py)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from owasp_scanner import knowledge                      # noqa: E402
from owasp_scanner.models import ScanResult, Status      # noqa: E402
from owasp_scanner.scanner import run_scan               # noqa: E402
from owasp_scanner.static_scan import engine             # noqa: E402

VULNERABLE = ROOT / "samples" / "vulnerable_app"
SECURE = ROOT / "samples" / "secure_app"


def _statuses(path: Path) -> dict[str, Status]:
    result = run_scan(code_path=path)
    return {c.category_id: c.status for c in result.categories}


def test_vulnerable_app_trips_every_category():
    statuses = _statuses(VULNERABLE)
    missed = [cid for cid, st in statuses.items() if st is not Status.FOUND]
    assert not missed, f"vulnerable fixture should trip all 10, missed: {missed}"


def test_secure_app_is_clean():
    result = run_scan(code_path=SECURE)
    flagged = [
        f"{c.category_id}: {f.rule_id} at {f.evidence.location}"
        for c in result.categories
        for f in c.findings
    ]
    assert not flagged, "secure fixture produced false positives:\n  " + "\n  ".join(flagged)


def test_secure_app_reports_not_found_not_unchecked():
    """A clean scan must say NOT FOUND, never NOT CHECKED — they mean different things."""
    statuses = _statuses(SECURE)
    for cid, status in statuses.items():
        assert status is Status.NOT_FOUND, f"{cid} came back {status.value}, expected NOT_FOUND"


def test_parameterized_sql_is_not_flagged():
    """Binding a model response as a query parameter is the correct pattern."""
    result = run_scan(code_path=SECURE)
    llm05 = next(c for c in result.categories if c.category_id == "LLM05")
    assert not llm05.findings


def test_taint_links_output_to_sink():
    """LLM05 findings must name the variable and its origin, not just the sink."""
    result = run_scan(code_path=VULNERABLE)
    llm05 = next(c for c in result.categories if c.category_id == "LLM05")
    taint = [f for f in llm05.findings if f.rule_id.startswith("LLM05-TAINT-")]
    assert taint, "expected taint-based findings on the vulnerable fixture"
    for finding in taint:
        assert "assigned at line" in finding.evidence.detail


def test_multiline_system_prompt_secret_detected():
    result = run_scan(code_path=VULNERABLE)
    llm07 = next(c for c in result.categories if c.category_id == "LLM07")
    rules = {f.rule_id for f in llm07.findings}
    assert "LLM07-SECRET-IN-PROMPT-BLOCK" in rules
    assert "LLM07-AUTHZ-IN-PROMPT-BLOCK" in rules


def test_secret_value_is_masked_in_output():
    """The report must not reprint a full credential it just found."""
    result = run_scan(code_path=VULNERABLE)
    llm07 = next(c for c in result.categories if c.category_id == "LLM07")
    block = next(f for f in llm07.findings if f.rule_id == "LLM07-SECRET-IN-PROMPT-BLOCK")
    assert "sk-admin-000000000000000000000000000000" not in block.evidence.snippet


def test_all_ten_categories_always_present():
    """Every report covers all 10, so a category can never silently vanish."""
    for path in (VULNERABLE, SECURE):
        result = run_scan(code_path=path)
        ids = [c.category_id for c in result.categories]
        assert ids == [c.id for c in knowledge.CATEGORIES]


def test_empty_target_is_not_checked_not_clean(tmp_path=None):
    """Scanning a directory with no LLM code must not read as an all-clear."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "notes.md").write_text("no code here", encoding="utf-8")
        result = run_scan(code_path=Path(tmp))
        assert result.found_count == 0
        assert result.total_findings == 0


def test_json_round_trip():
    import json

    result = run_scan(code_path=VULNERABLE)
    data = json.loads(result.to_json())
    assert data["summary"]["categories_found"] == 10
    assert len(data["categories"]) == 10


def test_ipynb_code_cells_are_scanned():
    import json
    import tempfile

    notebook = {
        "cells": [
            {"cell_type": "markdown", "source": ["# notes"]},
            {"cell_type": "code", "source": ["model = X.from_pretrained('a/b', trust_remote_code=True)\n"]},
        ],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5,
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "demo.ipynb"
        path.write_text(json.dumps(notebook), encoding="utf-8")
        result = run_scan(code_path=Path(tmp))
        llm03 = next(c for c in result.categories if c.category_id == "LLM03")
        assert any(f.rule_id == "LLM03-TRUST-REMOTE-CODE" for f in llm03.findings)


def test_html_report_renders():
    from owasp_scanner.reporting import html_report

    result = run_scan(code_path=VULNERABLE)
    page = html_report.render(result)
    assert page.startswith("<!doctype html>")
    assert "OWASP Top 10 for LLM Applications" in page
    for cat in knowledge.CATEGORIES:
        assert cat.id in page
    # The dashboard must never leak a discovered credential into the HTML.
    assert "sk-proj-000000000000000000000000000000000000" not in page


if __name__ == "__main__":
    failures = 0
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}\n        {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  ERROR {name}\n        {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    raise SystemExit(1 if failures else 0)
