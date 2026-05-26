import json
from pathlib import Path

import pytest

from chainshield import cli, scanners


REPORTS = Path("reports")


def cleanup(*paths):
    for path in paths:
        if path:
            Path(path).unlink(missing_ok=True)


def test_fixture_first_deny_writes_decision_without_sandbox_install(monkeypatch):
    decision_path = REPORTS / "demo-fixture-deny-decision.json"
    summary_path = REPORTS / "demo-fixture-deny-summary.md"
    cleanup(decision_path, summary_path)
    monkeypatch.setattr(cli, "run_sandbox", lambda *args, **kwargs: pytest.fail("sandbox/npm install must not run after static deny"))

    exit_code = cli.main(["evaluate", "--config", "fixtures/configs/demo-fixture-deny.json"])

    assert exit_code == 1
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["decision"] == "deny"
    assert {item["gate"] for item in decision["gate_results"]} == {"snyk", "socket"}
    assert any(item["status"] == "deny" for item in decision["gate_results"])
    cleanup(decision_path, summary_path)


def write_config(path, *, scanner_mode, snyk_report, socket_report, decision_name, summary_name=None):
    config = {
        "version": 1,
        "request_id": f"REQ-{decision_name}",
        "package_manager": "npm",
        "scanner_mode": scanner_mode,
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": snyk_report,
            "socket_report": socket_report,
            "openshell_log": None,
            "canary_secret": "fixtures/canary/synthetic-canary.txt",
        },
        "outputs": {
            "decision_json": f"reports/{decision_name}.json",
            "markdown_summary": f"reports/{summary_name}.md" if summary_name else None,
        },
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    cleanup(config["outputs"]["decision_json"], config["outputs"]["markdown_summary"] or "")
    return config


def test_snyk_low_medium_residual_risk_is_allow_with_json_and_markdown_summary(tmp_path):
    config_path = tmp_path / "low-medium.json"
    write_config(
        config_path,
        scanner_mode={"snyk": "fixture", "socket": "fixture"},
        snyk_report="fixtures/reports/snyk-low-medium.json",
        socket_report="fixtures/reports/socket-pass.json",
        decision_name="test-low-medium-decision",
        summary_name="test-low-medium-summary",
    )

    exit_code = cli.main(["evaluate", "--config", str(config_path)])

    assert exit_code == 0
    decision = json.loads((REPORTS / "test-low-medium-decision.json").read_text(encoding="utf-8"))
    assert decision["decision"] == "allow"
    assert "residual risk" in json.dumps(decision, ensure_ascii=False).lower()
    assert "residual risk" in (REPORTS / "test-low-medium-summary.md").read_text(encoding="utf-8").lower()
    cleanup(REPORTS / "test-low-medium-decision.json", REPORTS / "test-low-medium-summary.md")


def test_live_scanner_unavailable_uses_fixture_fallback(monkeypatch, tmp_path):
    unavailable = scanners.manual_review_evidence(
        gate="socket",
        run_id="run-live-fallback",
        source_kind="live",
        source_path=None,
        command="socket ci --json",
        exit_code=2,
        reasons=["live_unavailable: auth_or_network_unavailable"],
    )
    monkeypatch.setattr(scanners, "run_live_scanner", lambda *args, **kwargs: unavailable)
    config_path = tmp_path / "live-fallback.json"
    write_config(
        config_path,
        scanner_mode={"snyk": "fixture", "socket": "live"},
        snyk_report="fixtures/reports/snyk-pass.json",
        socket_report="fixtures/reports/socket-pass.json",
        decision_name="test-live-fallback-decision",
    )

    exit_code = cli.main(["evaluate", "--config", str(config_path)])

    assert exit_code == 0
    decision = json.loads((REPORTS / "test-live-fallback-decision.json").read_text(encoding="utf-8"))
    assert decision["decision"] == "allow"
    socket_result = next(item for item in decision["gate_results"] if item["gate"] == "socket")
    assert any("live_unavailable" in reason for reason in socket_result["reasons"])
    cleanup(REPORTS / "test-live-fallback-decision.json")


def test_missing_fixture_or_skipped_gate_requires_manual_review(monkeypatch, tmp_path):
    unavailable = scanners.manual_review_evidence(
        gate="socket",
        run_id="run-missing-live",
        source_kind="live",
        source_path=None,
        command="socket ci --json",
        exit_code=2,
        reasons=["live_unavailable: auth_or_network_unavailable"],
    )
    monkeypatch.setattr(scanners, "run_live_scanner", lambda *args, **kwargs: unavailable)
    missing_config = tmp_path / "missing-live.json"
    write_config(
        missing_config,
        scanner_mode={"snyk": "fixture", "socket": "live"},
        snyk_report="fixtures/reports/snyk-pass.json",
        socket_report=None,
        decision_name="test-missing-live-decision",
    )

    missing_exit = cli.main(["evaluate", "--config", str(missing_config)])
    missing_decision = json.loads((REPORTS / "test-missing-live-decision.json").read_text(encoding="utf-8"))
    assert missing_exit == 2
    assert missing_decision["decision"] == "manual_review"
    assert "socket" in missing_decision["missing_gates"]

    skip_config = tmp_path / "skip.json"
    write_config(
        skip_config,
        scanner_mode={"snyk": "skip", "socket": "skip"},
        snyk_report=None,
        socket_report=None,
        decision_name="test-skip-decision",
    )
    skip_exit = cli.main(["evaluate", "--config", str(skip_config)])
    skip_decision = json.loads((REPORTS / "test-skip-decision.json").read_text(encoding="utf-8"))
    assert skip_exit == 2
    assert skip_decision["decision"] == "manual_review"
    assert skip_decision["missing_gates"] == ["snyk", "socket"]
    cleanup(REPORTS / "test-missing-live-decision.json", REPORTS / "test-skip-decision.json")
