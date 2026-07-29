# AI OWASP Scanner

Scans an application against the **OWASP Top 10 for LLM Applications v2.0 (2025)**
and reports, for each of the ten categories, whether a security issue was
**FOUND** or **NOT FOUND**.

Two engines feed one report:

- **Static** — walks a codebase and looks for the weaknesses in the source.
- **Dynamic** — sends adversarial probes to a live endpoint and judges the responses.

No third-party runtime dependencies; Python 3.10+ standard library only.

---

## Quick start

Scan a codebase:

```bash
python -m owasp_scanner /path/to/your/app
```

Scan and open the dashboard:

```bash
python -m owasp_scanner /path/to/your/app --open
```

Probe a live endpoint (see [targets/README.md](targets/README.md)):

```bash
python -m owasp_scanner --target targets/my_app.json
```

Both at once, which is the only way to get a verdict on all ten categories:

```bash
python -m owasp_scanner /path/to/your/app --target targets/my_app.json
```

See every check the scanner can run:

```bash
python -m owasp_scanner --list-checks
```

Each run writes a JSON report and a self-contained HTML dashboard into `scans/`.

---

## The three statuses

The distinction between the last two is the point of the tool, so it is worth
being precise:

| Status | Meaning |
|---|---|
| **FOUND** | At least one check produced evidence of this weakness. |
| **NOT FOUND** | Checks for this category ran and found nothing. |
| **NOT CHECKED** | No applicable check ran. **This is not an all-clear.** |

A static-only scan cannot observe runtime behaviour, and a dynamic-only scan
cannot see your build pipeline. When an engine has nothing to say about a
category, the report says NOT CHECKED rather than quietly rendering it green.

---

## Coverage

| | Static | Dynamic |
|---|:---:|:---:|
| LLM01 Prompt Injection | ✅ | ✅ direct, indirect, payload-splitting |
| LLM02 Sensitive Information Disclosure | ✅ | ✅ |
| LLM03 Supply Chain | ✅ | — |
| LLM04 Data and Model Poisoning | ✅ | — |
| LLM05 Improper Output Handling | ✅ taint tracking | ✅ |
| LLM06 Excessive Agency | ✅ | ✅ |
| LLM07 System Prompt Leakage | ✅ | ✅ |
| LLM08 Vector and Embedding Weaknesses | ✅ | — |
| LLM09 Misinformation | ✅ | ✅ |
| LLM10 Unbounded Consumption | ✅ | ✅ |

LLM03, LLM04 and LLM08 have no dynamic probe because they are properties of the
build and data pipeline, not of runtime responses.

### How LLM05 detection works

Rather than reporting every `eval()` in the codebase, the static engine tracks
which variables hold model output — following them through response accessors
like `response.choices[0].message.content` — and reports only when one of those
variables reaches a dangerous sink. It also recognises safe patterns: a model
response bound as a parameter in `execute("… VALUES (?)", (answer,))` is not
flagged, because that is the correct way to do it.

---

## Validating the detectors

Two fixtures under `samples/` define the contract:

- `samples/vulnerable_app/` — deliberately insecure; must trip all 10 categories.
- `samples/secure_app/` — same features, mitigations applied; must trip none.

```bash
python tests/test_static_scan.py
```

Current state: **10/10 found** on the vulnerable fixture, **0 findings** on the
secure one.

---

## Use in CI

`--fail-on` sets the exit code so a build can gate on results:

```bash
python -m owasp_scanner ./src --fail-on high --no-html
```

Exits non-zero if any finding is HIGH or CRITICAL. Options: `any`, `critical`,
`high`, `medium`, `never` (default).

---

## Reports never reprint secrets

Every snippet and probe excerpt passes through `redaction.py` before it reaches
a report. A tool that finds a hard-coded key and then prints it in full has just
copied that secret into a file people commit and email around, so discovered
credentials are masked to `sk-pro…Qj5 [REDACTED 51 chars]`.

---

## Authorized use only

The dynamic engine sends real adversarial payloads: instruction-override
attempts, credential-extraction requests, oversized inputs, and a burst of
requests to test for rate limiting. Only run it against systems you own or have
written permission to test. Prefer staging — the burst probe spends real
inference budget.

The static engine only reads files and sends nothing anywhere.

---

## Findings are leads, not verdicts

Detection is heuristic. A FOUND result means something matched a pattern worth a
human look, not that a vulnerability is confirmed. Each finding carries a
confidence level; treat LOW confidence as a prompt to check, not a bug report.
Equally, NOT FOUND means these particular checks found nothing — it is not proof
the category is absent.

---

## Layout

```
owasp_scanner/
  knowledge.py          the 10 categories, with mitigations and PDF page refs
  models.py             Status / Severity / Finding / ScanResult
  redaction.py          secret masking applied to everything in a report
  scanner.py            orchestration and merge of engine verdicts
  cli.py                command-line interface
  static_scan/
    patterns.py         LLM-call, sink and untrusted-source vocabularies
    rules.py            declarative line rules
    engine.py           file walk, taint tracking, absence checks
  dynamic_scan/
    probes.py           probe payloads and their detectors
    engine.py           target config, transport, probe execution
  reporting/
    console.py          terminal summary
    html_report.py      self-contained HTML dashboard
samples/                vulnerable and secure test fixtures + mock endpoint
targets/                live-endpoint target configs
tests/                  regression suite
tools/                  extract_reference.py (regenerates OWASP text from the PDF)
reference/              extracted OWASP text (gitignored, regenerate locally)
scans/                  generated reports (gitignored)
```

### A note on the test fixtures

`samples/vulnerable_app/` and `samples/mock_endpoint.py` contain deliberately
insecure code and credential-shaped strings. Those strings are inert
placeholders — correct in shape so the detectors fire, with all-zero bodies so
they cannot be mistaken for live credentials. Nothing in this repository is or
ever was a real secret. Do not copy these fixtures into production code.

---

## Attribution and licensing

Category definitions and mitigations are adapted from the *OWASP Top 10 for
Large Language Model Applications v2.0 (2025)*, published by the OWASP
Foundation under CC BY-SA 4.0 — <https://genai.owasp.org>.

The OWASP PDF is **not redistributed here**. To cross-check the page references
in `owasp_scanner/knowledge.py` against the source, download the document from
<https://genai.owasp.org> and run:

```bash
pip install pypdf
python tools/extract_reference.py path/to/LLMAll_en-US_FINAL.pdf
```

Scans work fine without it; the extracted text is only for verification.

| Part | License |
|---|---|
| Detection rules, engines, reporting, CLI, tests | Apache 2.0 (see [LICENSE](LICENSE)) |
| OWASP-adapted content in `owasp_scanner/knowledge.py` | CC BY-SA 4.0 (see [NOTICE](NOTICE)) |

This scanner is an independent tool. It is not affiliated with, endorsed by, or
sponsored by the OWASP Foundation.

## Status

v0.1. Validated against the bundled fixtures in both directions, but not yet
run against a real third-party codebase — treat the false-positive rate on
unfamiliar code as unmeasured.
