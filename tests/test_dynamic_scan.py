"""Regression tests for the dynamic engine.

Spins up `samples/mock_endpoint.py` on a free port in both its vulnerable and
hardened modes. The contract mirrors the static suite: the naive endpoint must
trip every probe, the hardened one must trip none.

Run with:  python tests/test_dynamic_scan.py
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from owasp_scanner.dynamic_scan.engine import Target                       # noqa: E402
from owasp_scanner.dynamic_scan.probes import ALL_PROBES                   # noqa: E402
from owasp_scanner.models import Status                                    # noqa: E402
from owasp_scanner.scanner import run_scan                                 # noqa: E402

MOCK = ROOT / "samples" / "mock_endpoint.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockServer:
    """Context manager that starts the mock endpoint and waits for it to answer."""

    def __init__(self, secure: bool = False):
        self.secure = secure
        self.port = _free_port()
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/chat"

    def __enter__(self) -> "MockServer":
        cmd = [sys.executable, str(MOCK), "--port", str(self.port)]
        if self.secure:
            cmd.append("--secure")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(
                    self.url, data=b'{"message":"ping"}',
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(req, timeout=2):
                    return self
            except (urllib.error.URLError, OSError, TimeoutError):
                time.sleep(0.2)
        self.__exit__(None, None, None)
        raise RuntimeError(f"mock endpoint failed to start on port {self.port}")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def target(self) -> Target:
        return Target(
            url=self.url,
            body_template={"message": "{{PROMPT}}"},
            response_path="reply",
            timeout=15,
            delay_seconds=0.0,
        )


def test_vulnerable_endpoint_trips_every_probe():
    with MockServer() as server:
        result = run_scan(target=server.target())
    fired = {f.rule_id for c in result.categories for f in c.findings}
    expected = {p.id for p in ALL_PROBES}
    assert fired == expected, f"probes that did not fire: {sorted(expected - fired)}"


def test_hardened_endpoint_is_clean():
    with MockServer(secure=True) as server:
        result = run_scan(target=server.target())
    flagged = [f"{f.rule_id}: {f.evidence.detail}"
               for c in result.categories for f in c.findings]
    assert not flagged, "hardened endpoint produced false positives:\n  " + "\n  ".join(flagged)


def test_all_probes_ran_without_transport_errors():
    with MockServer() as server:
        result = run_scan(target=server.target())
    assert not result.errors, f"transport errors: {result.errors}"
    assert result.stats["probes_run"] == len(ALL_PROBES)


def test_pipeline_only_categories_are_not_checked():
    """Dynamic-only scans must not claim a verdict on build-pipeline categories."""
    with MockServer(secure=True) as server:
        result = run_scan(target=server.target())
    by_id = {c.category_id: c for c in result.categories}
    for cid in ("LLM03", "LLM04", "LLM08"):
        assert by_id[cid].status is Status.NOT_CHECKED, (
            f"{cid} has no dynamic probe, so it must report NOT_CHECKED, "
            f"got {by_id[cid].status.value}"
        )
        assert by_id[cid].note, f"{cid} should explain why it was not checked"


def test_combined_scan_covers_all_ten():
    """Static plus dynamic is the only mode that reaches a verdict everywhere."""
    with MockServer() as server:
        result = run_scan(
            code_path=ROOT / "samples" / "vulnerable_app", target=server.target()
        )
    unchecked = [c.category_id for c in result.categories if c.status is Status.NOT_CHECKED]
    assert not unchecked, f"combined scan left categories unchecked: {unchecked}"
    assert result.found_count == 10
    sources = {f.source for c in result.categories for f in c.findings}
    assert sources == {"static", "dynamic"}, f"expected both sources, got {sources}"


def test_response_path_extraction():
    from owasp_scanner.dynamic_scan.engine import _extract_text

    body = '{"choices":[{"message":{"content":"hello there"}}]}'
    assert _extract_text(body, "choices.0.message.content") == "hello there"
    # A bad path falls back to the raw body rather than silently returning nothing,
    # so a misconfigured target cannot read as a clean scan.
    assert _extract_text(body, "nope.0.bad") == body
    assert _extract_text("not json", "a.b") == "not json"


def test_body_template_substitution_at_depth():
    target = Target(
        url="http://example.invalid",
        body_template={"model": "x", "messages": [{"role": "user", "content": "{{PROMPT}}"}]},
    )
    rendered = target.render_body("HELLO").decode()
    assert "HELLO" in rendered and "{{PROMPT}}" not in rendered


def test_secrets_are_redacted_in_probe_output():
    with MockServer() as server:
        result = run_scan(target=server.target())
    blob = result.to_json()
    for secret in (
        "sk-proj-000000000000000000000000000000000000",
        "sk-admin-000000000000000000000000000000",
        "0000000000@db.invalid",
    ):
        assert secret not in blob, f"report leaked a secret: {secret[:12]}…"


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
