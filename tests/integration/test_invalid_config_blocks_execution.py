import json
from pathlib import Path

import pytest

from chainshield import cli


def write_invalid_config(tmp_path, decision_path):
    config = {
        "version": 1,
        "request_id": "REQ-invalid",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "../outside/snyk.json",
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": None,
            "canary_secret": "fixtures/canary/synthetic-canary.txt",
        },
        "outputs": {
            "decision_json": str(decision_path),
            "markdown_summary": str(tmp_path / "summary.md"),
        },
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "invalid.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


def test_invalid_config_writes_manual_review_and_blocks_scanner_sandbox(tmp_path, monkeypatch):
    calls = {"scanner": 0, "sandbox": 0}
    monkeypatch.setattr(cli, "run_scanners", lambda *a, **k: calls.__setitem__("scanner", calls["scanner"] + 1))
    monkeypatch.setattr(cli, "run_sandbox", lambda *a, **k: calls.__setitem__("sandbox", calls["sandbox"] + 1))
    decision_path = tmp_path / "decision.json"
    config_path = write_invalid_config(tmp_path, decision_path)

    exit_code = cli.main(["evaluate", "--config", str(config_path)])

    assert exit_code == 2
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["decision"] == "manual_review"
    assert any("config validation" in reason.lower() for reason in decision["primary_reasons"])
    assert calls == {"scanner": 0, "sandbox": 0}


def test_existing_output_path_is_not_overwritten(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_scanners", lambda *a, **k: pytest.fail("scanner must not run"))
    monkeypatch.setattr(cli, "run_sandbox", lambda *a, **k: pytest.fail("sandbox must not run"))
    decision_path = tmp_path / "decision.json"
    decision_path.write_text('{"existing": true}', encoding="utf-8")
    config_path = write_invalid_config(tmp_path, decision_path)

    exit_code = cli.main(["evaluate", "--config", str(config_path)])

    assert exit_code == 2
    assert json.loads(decision_path.read_text(encoding="utf-8")) == {"existing": True}
