from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_sandbox_only_wrapper_blocks_static_deny_without_allowing_host_lifecycle():
    decision_path = Path("reports/demo-fixture-deny-decision.json")
    summary_path = Path("reports/demo-fixture-deny-summary.md")
    decision_path.unlink(missing_ok=True)
    summary_path.unlink(missing_ok=True)

    completed = subprocess.run(
        [sys.executable, "scripts/run-demo.py", "--config", "fixtures/configs/demo-fixture-deny.json", "--sandbox-only"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["decision"] == "deny"
    assert "allow" not in decision["decision"]
    assert "npm install" not in completed.stderr.lower()
    decision_path.unlink(missing_ok=True)
    summary_path.unlink(missing_ok=True)


def test_sandbox_only_wrapper_requires_valid_override_reason(tmp_path):
    config = {
        "version": 1,
        "request_id": "REQ-wrapper-bad-override",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "fixture",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-high-critical.json",
            "socket_report": "fixtures/reports/socket-unhealthy.json",
            "openshell_log": "fixtures/reports/openshell-deny.log",
            "canary_secret": "fixtures/canary/canary-secret.txt",
        },
        "outputs": {"decision_json": str(tmp_path / "bad-override-decision.json"), "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": True, "reason": "short"},
        },
    }
    config_path = tmp_path / "bad-override.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/run-demo.py", "--config", str(config_path), "--sandbox-only"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    decision = json.loads((tmp_path / "bad-override-decision.json").read_text(encoding="utf-8"))
    assert decision["decision"] == "manual_review"
