"""Regenerate `reference/owasp_llm_top10_v2_text.txt` from the OWASP PDF.

The OWASP document is not redistributed in this repository. Download it from
https://genai.owasp.org and run:

    python tools/extract_reference.py path/to/LLMAll_en-US_FINAL.pdf

The extracted text is a convenience for cross-checking the claims in
`owasp_scanner/knowledge.py`, which cites page numbers from that PDF. Nothing
in the scanner needs this file at runtime — scans work without it.

Requires: pip install pypdf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "reference" / "owasp_llm_top10_v2_text.txt"


def extract(pdf_path: Path, out_path: Path) -> int:
    try:
        import pypdf
    except ImportError:
        print("error: pypdf is required — pip install pypdf", file=sys.stderr)
        return 1

    if not pdf_path.exists():
        print(f"error: no such file: {pdf_path}", file=sys.stderr)
        return 2

    reader = pypdf.PdfReader(str(pdf_path))
    chunks: list[str] = []
    for i, page in enumerate(reader.pages):
        chunks.append(f"\n\n===== PAGE {i + 1} =====\n")
        chunks.append(page.extract_text() or "")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("".join(chunks), encoding="utf-8")
    print(f"wrote {out_path} ({len(reader.pages)} pages, {out_path.stat().st_size:,} bytes)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pdf", type=Path, help="path to the OWASP Top 10 for LLM Apps PDF")
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT,
                    help=f"output path (default: {DEFAULT_OUT.relative_to(ROOT)})")
    args = ap.parse_args()
    return extract(args.pdf, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
