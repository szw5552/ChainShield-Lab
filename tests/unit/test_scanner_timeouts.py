import subprocess

import pytest

from chainshield import scanners


@pytest.mark.parametrize(
    "gate, command",
    [
        ("snyk", ["snyk", "test", "--json"]),
        ("socket", ["socket", "ci", "--json"]),
    ],
)
def test_live_scanner_timeout_yields_sanitized_failure_evidence(gate, command):
    def timeout_runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    evidence = scanners.run_live_scanner(
        gate,
        command,
        run_id="run-timeout",
        runner=timeout_runner,
        timeout_seconds=120,
    )

    assert evidence["status"] == "manual_review"
    assert evidence["exit_code"] is None
    assert evidence["command"] == " ".join(command)
    joined = " ".join(evidence["reasons"])
    assert "timeout" in joined.lower()
    assert "120" in joined
    assert "started_at=" in joined and "ended_at=" in joined


def test_live_unavailable_falls_back_to_fixture_and_marks_evidence(monkeypatch):
    unavailable = scanners.manual_review_evidence(
        gate="snyk",
        run_id="run-fallback",
        source_kind="live",
        source_path=None,
        command="snyk test --json",
        exit_code=2,
        reasons=["live_unavailable: auth_or_network_unavailable"],
    )
    monkeypatch.setattr(scanners, "run_live_scanner", lambda *args, **kwargs: unavailable)

    results = scanners.run_scanners(
        scanner_mode={"snyk": "live", "socket": "skip"},
        fixtures={"snyk_report": "fixtures/reports/snyk-pass.json", "socket_report": None},
        run_id="run-fallback",
    )

    assert results[0]["gate"] == "snyk"
    assert results[0]["status"] == "pass"
    assert any("live_unavailable" in reason for reason in results[0]["reasons"])
