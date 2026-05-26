import json
from pathlib import Path

import pytest

from chainshield import cli
from chainshield.artifacts import ArtifactWriteError, write_json_artifact


REPORTS = Path("reports")


def cleanup(*paths):
    for path in paths:
        if path:
            Path(path).unlink(missing_ok=True)


def test_unsafe_fixture_report_is_rejected_before_decision_artifact_is_saved(tmp_path):
    unsafe_report = REPORTS / "test-redaction-unsafe-snyk.json"
    decision_path = REPORTS / "test-redaction-decision.json"
    summary_path = REPORTS / "test-redaction-summary.md"
    cleanup(unsafe_report, decision_path, summary_path)
    unsafe_report.parent.mkdir(parents=True, exist_ok=True)
    unsafe_report.write_text(
        json.dumps(
            {
                "vulnerabilities": [],
                "debug": [
                    "Authorization: Bearer secret-token",
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                    "aws_access_key_id = AKIAEXAMPLE",
                    "/Users/alice/.env contains local secrets",
                ],
            }
        ),
        encoding="utf-8",
    )
    config = {
        "version": 1,
        "request_id": "REQ-redaction",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": str(unsafe_report),
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": None,
            "canary_secret": "fixtures/canary/synthetic-canary.txt",
        },
        "outputs": {"decision_json": str(decision_path), "markdown_summary": str(summary_path)},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config_path = tmp_path / "redaction-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    exit_code = cli.main(["evaluate", "--config", str(config_path)])

    assert exit_code == 2
    decision_text = decision_path.read_text(encoding="utf-8")
    markdown_text = summary_path.read_text(encoding="utf-8")
    combined = decision_text + markdown_text
    assert "secret-token" not in combined
    assert "OPENSSH PRIVATE KEY" not in combined
    assert "aws_access_key_id" not in combined
    assert "/Users/alice/.env" not in combined
    decision = json.loads(decision_text)
    snyk_result = next(item for item in decision["gate_results"] if item["gate"] == "snyk")
    assert snyk_result["status"] == "manual_review"
    reason_text = " ".join(snyk_result["reasons"])
    assert "sanitizer rejected report" in reason_text
    assert "token/API key" in reason_text
    assert "SSH private key" in reason_text
    assert "cloud profile" in reason_text
    assert "personal .env" in reason_text
    cleanup(unsafe_report, decision_path, summary_path)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "TOKEN=secret-token",
        "-----BEGIN RSA PRIVATE KEY-----",
        "[profile demo]\naws_secret_access_key = secret",
        "/home/alice/.env contains local secrets",
    ],
)
def test_output_artifact_writer_refuses_unsanitized_content(tmp_path, unsafe_value):
    output_path = tmp_path / "unsafe-output.json"

    with pytest.raises(ArtifactWriteError):
        write_json_artifact(output_path, {"decision": "manual_review", "debug": unsafe_value})

    assert not output_path.exists()
