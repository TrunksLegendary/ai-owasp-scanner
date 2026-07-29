"""Command-line interface for the OWASP LLM Top 10 scanner."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

from . import knowledge
from .dynamic_scan.engine import Target
from .models import Status
from .reporting import console, html_report
from .scanner import run_scan

DEFAULT_OUTPUT_DIR = Path("scans")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="owasp-scan",
        description=(
            "Scan an application for the OWASP Top 10 for LLM Applications (2025) and "
            "report FOUND / NOT FOUND per category."
        ),
        epilog=(
            "Live probing sends adversarial payloads. Only run --target against systems "
            "you own or have written authorization to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", type=Path,
                   help="path to the codebase or file to scan statically")
    p.add_argument("-t", "--target", type=Path, metavar="TARGET.json",
                   help="JSON target file describing a live endpoint to probe")
    p.add_argument("-o", "--output", type=Path, metavar="DIR", default=DEFAULT_OUTPUT_DIR,
                   help=f"directory for reports (default: {DEFAULT_OUTPUT_DIR})")
    p.add_argument("--open", action="store_true",
                   help="open the HTML dashboard in a browser when the scan finishes")
    p.add_argument("--no-html", action="store_true", help="skip the HTML dashboard")
    p.add_argument("--json-only", action="store_true",
                   help="print JSON to stdout and write nothing else")
    p.add_argument("-v", "--verbose", action="store_true", help="show progress per check")
    p.add_argument("--fail-on", choices=["any", "critical", "high", "medium", "never"],
                   default="never",
                   help="exit non-zero when a finding at or above this severity exists "
                        "(default: never; use in CI)")
    p.add_argument("--list-checks", action="store_true",
                   help="list every check the scanner can run, then exit")
    return p


def _list_checks() -> None:
    from .static_scan.rules import RULES
    from .dynamic_scan.probes import ALL_PROBES

    print("\nOWASP Top 10 for LLM Applications — available checks\n")
    for cat in knowledge.CATEGORIES:
        static = [r for r in RULES if r.category_id == cat.id]
        dynamic = [p for p in ALL_PROBES if p.category_id == cat.id]
        print(f"{cat.id}  {cat.title}")
        for r in static:
            print(f"    static   {r.id:<38} {r.severity.value}")
        for p in dynamic:
            print(f"    dynamic  {p.id:<38} {p.severity.value}")
        if not static and not dynamic:
            print("    (no automated check)")
        print()
    print("Additional cross-line static checks: LLM05 taint tracking of model output into")
    print("code execution, shell, SQL, HTML, HTTP, filesystem and deserialization sinks.\n")


def _exit_code(result, threshold: str) -> int:
    if threshold == "never":
        return 0
    order = {"critical": 0, "high": 1, "medium": 2}
    if threshold == "any":
        return 1 if result.found_count else 0
    limit = order[threshold]
    ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for cat in result.categories:
        for finding in cat.findings:
            if ranks[finding.severity.value] <= limit:
                return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        _list_checks()
        return 0

    if not args.path and not args.target:
        print("error: give a path to scan, a --target to probe, or both.\n", file=sys.stderr)
        build_parser().print_help(sys.stderr)
        return 2

    if args.path and not args.path.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    target = None
    if args.target:
        if not args.target.exists():
            print(f"error: target file not found: {args.target}", file=sys.stderr)
            return 2
        try:
            target = Target.from_file(args.target)
        except (ValueError, OSError) as exc:
            print(f"error: could not read target file — {exc}", file=sys.stderr)
            return 2
        print(f"\n  Live probing {target.url}")
        print("  Only proceed if you own this system or have written authorization.\n")

    try:
        result = run_scan(code_path=args.path, target=target, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    if args.json_only:
        print(result.to_json())
        return _exit_code(result, args.fail_on)

    print(console.render(result))

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.output)
    json_path = html_report.write_json(result, out_dir / f"scan-{stamp}.json")
    print(f"  JSON report : {json_path}")

    if not args.no_html:
        html_path = html_report.write(result, out_dir / f"scan-{stamp}.html")
        print(f"  Dashboard   : {html_path}")
        if args.open:
            webbrowser.open(html_path.resolve().as_uri())
    print()

    return _exit_code(result, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
