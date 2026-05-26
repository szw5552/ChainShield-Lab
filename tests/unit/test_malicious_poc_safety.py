from __future__ import annotations

import json
from pathlib import Path

from chainshield import cli


def test_postinstall_uses_only_synthetic_canary_and_egress_target():
    script = Path("fixtures/malicious-poc-pkg/postinstall.js").read_text(encoding="utf-8")

    assert "CHAINSHIELD_CANARY_PATH" in script
    assert "canary-secret.txt" in script
    assert "https://chainshield-egress-test.invalid/collect" in script
    assert "DO NOT RUN ON HOST" in script
    assert "/Users/" not in script
    assert "process.env.HOME" not in script


def test_invalid_config_and_static_deny_do_not_trigger_host_npm_lifecycle(monkeypatch, tmp_path):
    calls = {"sandbox": 0}
    monkeypatch.setattr(cli, "run_sandbox", lambda *args, **kwargs: calls.__setitem__("sandbox", calls["sandbox"] + 1))

    invalid = {
        "version": 1,
        "request_id": "REQ-invalid-host-block",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "live",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "../outside.json",
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": "fixtures/reports/openshell-deny.log",
            "canary_secret": "fixtures/canary/canary-secret.txt",
        },
        "outputs": {"decision_json": str(tmp_path / "invalid-decision.json"), "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")

    assert cli.main(["evaluate", "--config", str(invalid_path), "--sandbox-only"]) == 2
    decision_path = Path("reports/demo-fixture-deny-decision.json")
    summary_path = Path("reports/demo-fixture-deny-summary.md")
    decision_path.unlink(missing_ok=True)
    summary_path.unlink(missing_ok=True)
    assert cli.main(["evaluate", "--config", "fixtures/configs/demo-fixture-deny.json", "--sandbox-only"]) == 1
    assert calls["sandbox"] == 0
    decision_path.unlink(missing_ok=True)
    summary_path.unlink(missing_ok=True)


def test_poc_lockfile_and_manifest_remain_local_private_and_non_publishable():
    manifest = json.loads(Path("fixtures/malicious-poc-pkg/package.json").read_text(encoding="utf-8"))
    lockfile = json.loads(Path("fixtures/poc-app/package-lock.json").read_text(encoding="utf-8"))

    assert manifest["private"] is True
    assert "publishConfig" not in manifest
    scripts = manifest.get("scripts", {})
    assert "publish" not in scripts
    assert "prepublishOnly" not in scripts
    assert "registry" not in json.dumps(manifest).lower()
    assert "https://registry.npmjs.org" not in json.dumps(lockfile)
    assert lockfile["packages"]["node_modules/malicious-poc-pkg"]["resolved"] == "../malicious-poc-pkg"
