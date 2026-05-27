from __future__ import annotations

import json
from pathlib import Path

from chainshield import sandbox
from chainshield.cli import main


def test_live_sandbox_readiness_failure_yields_manual_review(monkeypatch, tmp_path):
    decision_path = Path("reports/test-sandbox-readiness-decision.json")
    decision_path.unlink(missing_ok=True)
    config = {
        "version": 1,
        "request_id": "REQ-live-sandbox-readiness",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "live",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-pass.json",
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": "fixtures/reports/openshell-deny.log",
            "canary_secret": "fixtures/canary/canary-secret.txt",
        },
        "outputs": {"decision_json": str(decision_path), "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "live-sandbox.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    monkeypatch.setattr(
        sandbox,
        "check_sandbox_readiness",
        lambda *args, **kwargs: sandbox.SandboxReadiness(
            status="manual_review",
            reasons=["OrbStack unavailable; host fallback prohibited"],
            fixture_evidence_path="fixtures/reports/openshell-deny.log",
        ),
    )

    exit_code = main(["evaluate", "--config", str(config_path)])

    assert exit_code == 2
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["decision"] == "manual_review"
    assert "openshell" in decision["missing_gates"]
    assert any(item["gate"] == "openshell" and item["status"] == "manual_review" for item in decision["gate_results"])
    decision_path.unlink(missing_ok=True)
