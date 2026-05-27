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

    try:
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
    finally:
        decision_path.unlink(missing_ok=True)
        summary_path.unlink(missing_ok=True)


def test_sandbox_only_wrapper_requires_valid_override_reason(tmp_path):
    decision_path = Path("reports/test-bad-override-decision.json")
    decision_path.unlink(missing_ok=True)
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
        "outputs": {"decision_json": str(decision_path), "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": True, "reason": "short"},
        },
    }
    config_path = tmp_path / "bad-override.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    try:
        completed = subprocess.run(
            [sys.executable, "scripts/run-demo.py", "--config", str(config_path), "--sandbox-only"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert completed.returncode == 2
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        assert decision["decision"] == "manual_review"
    finally:
        decision_path.unlink(missing_ok=True)


def test_sandbox_only_requires_configured_sandbox_evidence(tmp_path):
    decision_path = Path("reports/test-sandbox-only-disabled-decision.json")
    decision_path.unlink(missing_ok=True)
    config = {
        "version": 1,
        "request_id": "REQ-wrapper-sandbox-required",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-pass.json",
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": None,
            "canary_secret": "fixtures/canary/canary-secret.txt",
        },
        "outputs": {"decision_json": str(decision_path), "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "sandbox-disabled.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    try:
        completed = subprocess.run(
            [sys.executable, "scripts/run-demo.py", "--config", str(config_path), "--sandbox-only"],
            capture_output=True,
            text=True,
            check=False,
        )

        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        assert completed.returncode == 2
        assert decision["decision"] == "manual_review"
        assert "openshell" in decision["missing_gates"]
        assert any("--sandbox-only requires sandbox_mode" in reason for reason in decision["primary_reasons"])
    finally:
        decision_path.unlink(missing_ok=True)


def test_wrapper_rotates_existing_output_paths_for_reruns(tmp_path):
    decision_path = Path("reports/test-wrapper-rerun-decision.json")
    summary_path = Path("reports/test-wrapper-rerun-summary.md")
    rotated_paths: list[Path] = []
    decision_path.parent.mkdir(exist_ok=True)
    decision_path.write_text('{"stale": true}', encoding="utf-8")
    summary_path.write_text("stale", encoding="utf-8")
    config = {
        "version": 1,
        "request_id": "REQ-wrapper-rerun",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "skip"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-pass.json",
            "socket_report": None,
            "openshell_log": None,
            "canary_secret": "fixtures/canary/canary-secret.txt",
        },
        "outputs": {"decision_json": str(decision_path), "markdown_summary": str(summary_path)},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "wrapper-rerun.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    try:
        completed = subprocess.run(
            [sys.executable, "scripts/run-demo.py", "--config", str(config_path)],
            capture_output=True,
            text=True,
            check=False,
        )

        assert completed.returncode == 2
        decision = json.loads(completed.stdout)
        rotated_decision = Path(decision["artifacts"]["decision_json"])
        rotated_summary = Path(decision["artifacts"]["markdown_summary"])
        rotated_paths.extend([rotated_decision, rotated_summary])
        assert rotated_decision != decision_path
        assert rotated_summary != summary_path
        assert rotated_decision.exists()
        assert rotated_summary.exists()
    finally:
        decision_path.unlink(missing_ok=True)
        summary_path.unlink(missing_ok=True)
        for path in rotated_paths:
            path.unlink(missing_ok=True)
        for generated in tmp_path.glob("wrapper-rerun-*.json"):
            generated.unlink(missing_ok=True)
