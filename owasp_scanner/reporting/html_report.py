"""Renders a scan result as a self-contained HTML dashboard.

No external assets: the file can be opened directly from disk or served, and
carries its own CSS and JS so results stay readable when emailed or archived.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .. import knowledge
from ..models import ScanResult, Status

STATUS_LABEL = {
    Status.FOUND: "FOUND",
    Status.NOT_FOUND: "NOT FOUND",
    Status.NOT_CHECKED: "NOT CHECKED",
    Status.ERROR: "ERROR",
}

STATUS_CLASS = {
    Status.FOUND: "found",
    Status.NOT_FOUND: "clean",
    Status.NOT_CHECKED: "unchecked",
    Status.ERROR: "error",
}

CSS = """
*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #f6f7f9; --panel: #ffffff; --ink: #16181d; --muted: #5f6672;
  --line: #e2e5ea; --accent: #2f5fd0;
  --found: #c0342b; --found-bg: #fdeceb; --found-line: #f0b8b4;
  --clean: #1c7a4a; --clean-bg: #e9f6ef; --clean-line: #b2ddc5;
  --unchecked: #6b6255; --unchecked-bg: #f4f0e8; --unchecked-line: #ded3c0;
  --crit: #8b1a1a; --high: #c0342b; --med: #b26a00; --low: #4a6785; --info: #6b7280;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --panel: #1c1f25; --ink: #e8eaed; --muted: #9aa2ae;
    --line: #2c3038; --accent: #7aa2f7;
    --found: #ff7b72; --found-bg: #2d1b1a; --found-line: #5c2b28;
    --clean: #56d39a; --clean-bg: #14291f; --clean-line: #2a5040;
    --unchecked: #c3b393; --unchecked-bg: #26221a; --unchecked-line: #4a4133;
    --crit: #ff5f56; --high: #ff7b72; --med: #e3a008; --low: #7aa2f7; --info: #9aa2ae;
  }
}
:root[data-theme="dark"] {
  --bg: #14161a; --panel: #1c1f25; --ink: #e8eaed; --muted: #9aa2ae;
  --line: #2c3038; --accent: #7aa2f7;
  --found: #ff7b72; --found-bg: #2d1b1a; --found-line: #5c2b28;
  --clean: #56d39a; --clean-bg: #14291f; --clean-line: #2a5040;
  --unchecked: #c3b393; --unchecked-bg: #26221a; --unchecked-line: #4a4133;
  --crit: #ff5f56; --high: #ff7b72; --med: #e3a008; --low: #7aa2f7; --info: #9aa2ae;
}
:root[data-theme="light"] {
  --bg: #f6f7f9; --panel: #ffffff; --ink: #16181d; --muted: #5f6672;
  --line: #e2e5ea; --accent: #2f5fd0;
  --found: #c0342b; --found-bg: #fdeceb; --found-line: #f0b8b4;
  --clean: #1c7a4a; --clean-bg: #e9f6ef; --clean-line: #b2ddc5;
  --unchecked: #6b6255; --unchecked-bg: #f4f0e8; --unchecked-line: #ded3c0;
  --crit: #8b1a1a; --high: #c0342b; --med: #b26a00; --low: #4a6785; --info: #6b7280;
}

body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 32px 20px 72px; }

header.top { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 26px; }
h1 { margin: 0 0 6px; font-size: 25px; letter-spacing: -0.3px; }
.sub { color: var(--muted); font-size: 13.5px; }
.sub code { font-family: var(--mono); font-size: 12.5px; background: var(--panel);
  border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; }

.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin-bottom: 28px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px 18px; }
.tile .n { font-size: 30px; font-weight: 650; line-height: 1.1; letter-spacing: -1px; }
.tile .k { font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.7px;
  color: var(--muted); margin-top: 4px; }
.tile.found .n { color: var(--found); }
.tile.clean .n { color: var(--clean); }
.tile.unchecked .n { color: var(--unchecked); }

.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
.filters button { font: inherit; font-size: 13px; cursor: pointer; padding: 6px 13px;
  border-radius: 999px; border: 1px solid var(--line); background: var(--panel);
  color: var(--muted); }
.filters button[aria-pressed="true"] { border-color: var(--accent); color: var(--accent);
  font-weight: 600; }

.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  margin-bottom: 10px; overflow: hidden; }
.card.found { border-left: 4px solid var(--found); }
.card.clean { border-left: 4px solid var(--clean); }
.card.unchecked { border-left: 4px solid var(--unchecked); }

.card > summary { cursor: pointer; list-style: none; padding: 15px 18px;
  display: flex; align-items: center; gap: 14px; }
.card > summary::-webkit-details-marker { display: none; }
.card > summary:hover { background: color-mix(in srgb, var(--ink) 3%, transparent); }
.cid { font-family: var(--mono); font-size: 12.5px; color: var(--muted);
  min-width: 52px; font-weight: 600; }
.ctitle { flex: 1; font-weight: 570; min-width: 0; }
.count { font-size: 12.5px; color: var(--muted); white-space: nowrap; }

.badge { font-size: 11px; font-weight: 700; letter-spacing: 0.6px; padding: 4px 10px;
  border-radius: 5px; white-space: nowrap; border: 1px solid transparent; }
.badge.found { color: var(--found); background: var(--found-bg); border-color: var(--found-line); }
.badge.clean { color: var(--clean); background: var(--clean-bg); border-color: var(--clean-line); }
.badge.unchecked { color: var(--unchecked); background: var(--unchecked-bg);
  border-color: var(--unchecked-line); }

.body { padding: 4px 18px 18px; border-top: 1px solid var(--line); }
.desc { color: var(--muted); font-size: 13.5px; margin: 14px 0 4px; }
.note { font-size: 13px; color: var(--muted); background: var(--unchecked-bg);
  border: 1px solid var(--unchecked-line); border-radius: 7px; padding: 10px 13px;
  margin-top: 12px; }

.finding { border: 1px solid var(--line); border-radius: 8px; padding: 13px 15px;
  margin-top: 12px; }
.fhead { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.fhead .ft { font-weight: 600; font-size: 14px; }
.sev { font-family: var(--mono); font-size: 10.5px; font-weight: 700; letter-spacing: 0.5px;
  padding: 2px 7px; border-radius: 4px; border: 1px solid currentColor; }
.sev.CRITICAL { color: var(--crit); } .sev.HIGH { color: var(--high); }
.sev.MEDIUM { color: var(--med); } .sev.LOW { color: var(--low); }
.sev.INFO { color: var(--info); }
.meta { font-family: var(--mono); font-size: 12px; color: var(--muted); margin-top: 7px;
  word-break: break-all; }
.snippet { font-family: var(--mono); font-size: 12.5px; background: var(--bg);
  border: 1px solid var(--line); border-radius: 6px; padding: 9px 11px; margin-top: 9px;
  overflow-x: auto; white-space: pre; }
.detail { font-size: 13.5px; margin-top: 10px; color: var(--ink); }
.fix { font-size: 13.5px; margin-top: 9px; padding-left: 11px;
  border-left: 2px solid var(--accent); color: var(--muted); }
.fix b { color: var(--ink); font-weight: 600; }

.mit { margin: 14px 0 0; padding-left: 20px; font-size: 13.5px; color: var(--muted); }
.mit li { margin-bottom: 5px; }

footer { margin-top: 40px; padding-top: 18px; border-top: 1px solid var(--line);
  color: var(--muted); font-size: 12.5px; }
footer a { color: var(--accent); }
.hidden { display: none !important; }
@media (max-width: 620px) {
  .card > summary { flex-wrap: wrap; gap: 8px; }
  .ctitle { flex-basis: 100%; order: 3; }
}
"""

JS = """
const buttons = document.querySelectorAll('.filters button');
buttons.forEach(btn => btn.addEventListener('click', () => {
  const want = btn.dataset.filter;
  buttons.forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
  document.querySelectorAll('.card').forEach(card => {
    card.classList.toggle('hidden', want !== 'all' && card.dataset.status !== want);
  });
}));
"""


def _esc(text: str) -> str:
    return html.escape(text or "", quote=True)


def _tile(value: int, label: str, cls: str = "") -> str:
    return f'<div class="tile {cls}"><div class="n">{value}</div><div class="k">{_esc(label)}</div></div>'


def _finding_html(f: dict) -> str:
    ev = f["evidence"]
    parts = [
        '<div class="finding">',
        '<div class="fhead">',
        f'<span class="sev {_esc(f["severity"])}">{_esc(f["severity"])}</span>',
        f'<span class="ft">{_esc(f["title"])}</span>',
        '</div>',
        f'<div class="meta">{_esc(ev["location"])} · {_esc(f["rule_id"])} '
        f'· {_esc(f["source"])} · confidence {_esc(f["confidence"].lower())}</div>',
    ]
    if ev.get("snippet"):
        parts.append(f'<div class="snippet">{_esc(ev["snippet"])}</div>')
    if ev.get("detail"):
        parts.append(f'<div class="detail">{_esc(ev["detail"])}</div>')
    if f.get("remediation"):
        parts.append(f'<div class="fix"><b>Fix:</b> {_esc(f["remediation"])}</div>')
    parts.append("</div>")
    return "".join(parts)


def _card_html(cat_result: dict) -> str:
    status = Status(cat_result["status"])
    cls = STATUS_CLASS[status]
    meta = knowledge.BY_ID.get(cat_result["category_id"])
    n = cat_result["finding_count"]

    if status is Status.FOUND:
        sev = cat_result.get("highest_severity") or ""
        count_text = f"{n} finding{'s' if n != 1 else ''} · highest {sev.lower()}"
    elif status is Status.NOT_FOUND:
        count_text = f"{len(cat_result['checks_run'])} checks passed"
    else:
        count_text = "no applicable check ran"

    body = [f'<div class="body">']
    if meta:
        body.append(f'<p class="desc">{_esc(meta.summary)}</p>')
    if cat_result.get("note"):
        body.append(f'<div class="note">{_esc(cat_result["note"])}</div>')

    for finding in cat_result["findings"]:
        body.append(_finding_html(finding))

    if meta and status is not Status.FOUND:
        body.append("<ul class='mit'>")
        for m in meta.key_mitigations[:4]:
            body.append(f"<li>{_esc(m)}</li>")
        body.append("</ul>")
    body.append("</div>")

    return (
        f'<details class="card {cls}" data-status="{cls}"{" open" if status is Status.FOUND else ""}>'
        f'<summary>'
        f'<span class="cid">{_esc(cat_result["category_id"])}</span>'
        f'<span class="ctitle">{_esc(cat_result["title"])}</span>'
        f'<span class="count">{_esc(count_text)}</span>'
        f'<span class="badge {cls}">{STATUS_LABEL[status]}</span>'
        f'</summary>'
        + "".join(body)
        + "</details>"
    )


def render(result: ScanResult) -> str:
    data = result.to_dict()
    s = data["summary"]
    stats = data.get("stats", {})

    stat_bits = []
    if "files_scanned" in stats:
        stat_bits.append(f'{stats["files_scanned"]} files scanned')
    if "probes_run" in stats:
        stat_bits.append(f'{stats["probes_run"]} live probes sent')
    stat_line = " · ".join(stat_bits)

    cards = "".join(_card_html(c) for c in data["categories"])

    errors_html = ""
    if data["errors"]:
        items = "".join(f"<li>{_esc(e)}</li>" for e in data["errors"][:20])
        errors_html = f'<div class="note"><b>Scan warnings</b><ul class="mit">{items}</ul></div>'

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP LLM Scan — {_esc(data["target"])}</title>
<style>{CSS}</style>
</head><body>
<div class="wrap">
<header class="top">
  <h1>OWASP LLM Top 10 — Scan Report</h1>
  <div class="sub">
    Target <code>{_esc(data["target"])}</code> ·
    mode {_esc(", ".join(data["scan_modes"]))} ·
    {_esc(data["finished_at"] or data["started_at"])}
    {(" · " + _esc(stat_line)) if stat_line else ""}
  </div>
</header>

<div class="tiles">
  {_tile(s["categories_found"], "issues found", "found")}
  {_tile(s["categories_not_found"], "not found", "clean")}
  {_tile(s["categories_not_checked"], "not checked", "unchecked")}
  {_tile(s["total_findings"], "total findings")}
</div>

<div class="filters">
  <button data-filter="all" aria-pressed="true">All 10</button>
  <button data-filter="found" aria-pressed="false">Found</button>
  <button data-filter="clean" aria-pressed="false">Not found</button>
  <button data-filter="unchecked" aria-pressed="false">Not checked</button>
</div>

{errors_html}
{cards}

<footer>
  Categories and mitigations from {_esc(knowledge.SOURCE_DOCUMENT)} —
  <a href="https://genai.owasp.org">genai.owasp.org</a>.<br>
  <b>NOT CHECKED</b> means no applicable check ran for that category; it is not a
  statement that the category is safe. Findings are heuristic and need human
  confirmation before being treated as confirmed vulnerabilities.
</footer>
</div>
<script>{JS}</script>
</body></html>"""


def write(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result), encoding="utf-8")
    return path


def write_json(result: ScanResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.to_json(), encoding="utf-8")
    return path
