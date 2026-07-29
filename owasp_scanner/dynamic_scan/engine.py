"""Dynamic scan engine — sends probes to a live LLM-backed endpoint.

The endpoint is described by a small JSON target file so the scanner works
against any chat API shape without code changes. See `targets/example_target.json`.

AUTHORIZED USE ONLY: this sends adversarial payloads. Point it only at systems
you own or have written permission to test.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import (
    CategoryResult,
    Evidence,
    Finding,
    ScanResult,
    Status,
)
from .. import knowledge
from .probes import ALL_PROBES, DYNAMIC_CHECKED_CATEGORIES, Probe

PROMPT_PLACEHOLDER = "{{PROMPT}}"


@dataclass
class Target:
    """How to talk to the endpoint under test."""

    url: str
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: Any = field(default_factory=lambda: {"message": PROMPT_PLACEHOLDER})
    response_path: str = ""      # dotted path to the text, e.g. "choices.0.message.content"
    timeout: int = 60
    delay_seconds: float = 0.5   # politeness gap between probes

    @classmethod
    def from_file(cls, path: Path) -> "Target":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        unknown = set(data) - {f for f in cls.__dataclass_fields__}
        if unknown:
            raise ValueError(f"Unknown keys in target file: {sorted(unknown)}")
        if "url" not in data:
            raise ValueError("Target file must contain a 'url'.")
        return cls(**data)

    def render_body(self, prompt: str) -> bytes:
        body = _substitute(deepcopy(self.body_template), prompt)
        if isinstance(body, (dict, list)):
            return json.dumps(body).encode("utf-8")
        return str(body).encode("utf-8")


def _substitute(node: Any, prompt: str) -> Any:
    if isinstance(node, str):
        return node.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(node, dict):
        return {k: _substitute(v, prompt) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, prompt) for v in node]
    return node


def _extract_text(raw: str, path: str) -> str:
    """Pull the assistant text out of the response, falling back to the raw body.

    Falling back matters: a probe that only inspects the parsed text would miss
    a payload reflected elsewhere in the envelope.
    """
    if not path:
        return raw
    try:
        node: Any = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    for part in path.split("."):
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return raw
        elif isinstance(node, dict):
            if part not in node:
                return raw
            node = node[part]
        else:
            return raw
    return node if isinstance(node, str) else json.dumps(node)


@dataclass
class Response:
    status: int
    body: str
    elapsed: float
    error: str = ""


def send(target: Target, prompt: str) -> Response:
    headers = {"Content-Type": "application/json", **target.headers}
    request = urllib.request.Request(
        target.url,
        data=target.render_body(prompt),
        headers=headers,
        method=target.method.upper(),
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=target.timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return Response(resp.status, body, time.monotonic() - started)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return Response(exc.code, body, time.monotonic() - started)
    except urllib.error.URLError as exc:
        return Response(0, "", time.monotonic() - started, error=str(exc.reason))
    except (TimeoutError, OSError) as exc:
        return Response(0, "", time.monotonic() - started, error=str(exc))


def _run_burst(target: Target, count: int = 12) -> tuple[bool, str]:
    """Fire a rapid burst and see whether anything throttles it."""
    statuses: list[int] = []
    for _ in range(count):
        resp = send(target, "Hello.")
        statuses.append(resp.status)
        if resp.status == 429:
            break
    throttled = any(s == 429 for s in statuses)
    served = sum(1 for s in statuses if s == 200)
    summary = f"{len(statuses)} requests sent back-to-back; {served} served, throttled={throttled}"
    return (not throttled and served >= count), summary


def scan_target(target: Target, result: ScanResult, verbose: bool = False) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {c.id: [] for c in knowledge.CATEGORIES}
    probes_run: list[str] = []
    transport_failures = 0

    for probe in ALL_PROBES:
        if verbose:
            print(f"  probing {probe.id} … ", end="", flush=True)

        if probe.mode == "burst":
            triggered, summary = _run_burst(target)
            detail, excerpt, status_note = probe.detail, summary, summary
            if triggered:
                grouped[probe.category_id].append(
                    _finding(probe, target.url, excerpt, detail)
                )
            probes_run.append(probe.id)
            if verbose:
                print("FOUND" if triggered else "clean")
            time.sleep(target.delay_seconds)
            continue

        resp = send(target, probe.prompt)
        if resp.error or resp.status == 0:
            transport_failures += 1
            result.errors.append(f"{probe.id}: transport error — {resp.error or 'no response'}")
            if verbose:
                print(f"error ({resp.error})")
            continue

        text = _extract_text(resp.body, target.response_path)
        # Probes inspect both the parsed text and the raw envelope.
        haystack = text if text == resp.body else f"{text}\n{resp.body}"
        outcome = probe.detect(haystack, resp.status)
        probes_run.append(probe.id)

        if outcome.triggered:
            grouped[probe.category_id].append(
                _finding(probe, target.url, outcome.excerpt, outcome.detail)
            )
        if verbose:
            print("FOUND" if outcome.triggered else "clean")
        time.sleep(target.delay_seconds)

    result.stats["probes_run"] = len(probes_run)
    result.stats["probe_transport_failures"] = transport_failures
    result.stats["probe_ids"] = probes_run
    return grouped


def _finding(probe: Probe, url: str, excerpt: str, detail: str) -> Finding:
    return Finding(
        category_id=probe.category_id,
        rule_id=probe.id,
        title=probe.title,
        severity=probe.severity,
        confidence=probe.confidence,
        source="dynamic",
        evidence=Evidence(location=url, snippet=excerpt, detail=detail),
        remediation=probe.remediation,
    )


def build_category_results(
    grouped: dict[str, list[Finding]], probes_run: list[str]
) -> list[CategoryResult]:
    results: list[CategoryResult] = []
    ran_by_category: dict[str, list[str]] = {}
    for probe in ALL_PROBES:
        if probe.id in probes_run:
            ran_by_category.setdefault(probe.category_id, []).append(probe.id)

    for cat in knowledge.CATEGORIES:
        findings = grouped.get(cat.id, [])
        ran = ran_by_category.get(cat.id, [])
        if findings:
            status = Status.FOUND
        elif ran:
            status = Status.NOT_FOUND
        else:
            status = Status.NOT_CHECKED

        note = ""
        if cat.id not in DYNAMIC_CHECKED_CATEGORIES:
            note = (
                "No live probe exists for this category — it is a property of the build "
                "and data pipeline, not of runtime responses. Assess it with a code scan."
            )
        results.append(
            CategoryResult(
                category_id=cat.id,
                title=cat.title,
                status=status,
                findings=findings,
                checks_run=[f"dynamic:{p}" for p in ran],
                note=note,
            )
        )
    return results
