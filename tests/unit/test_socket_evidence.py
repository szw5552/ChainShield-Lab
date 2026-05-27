import json

import pytest

from chainshield.evidence import normalize_socket_report, normalize_socket_report_data, socket_evidence_from_classification


def test_socket_unhealthy_report_denies():
    evidence = normalize_socket_report_data(
        {"healthy": False, "issues": [{"type": "unhealthy", "title": "Package health failed"}]},
        source_path="fixtures/reports/socket-unhealthy.json",
        run_id="run-us1",
    )

    assert evidence["gate"] == "socket"
    assert evidence["status"] == "deny"
    assert any("unhealthy" in reason.lower() for reason in evidence["reasons"])


def test_socket_policy_violation_denies():
    evidence = normalize_socket_report_data(
        {"healthy": True, "policy": {"violations": [{"name": "Block install scripts", "severity": "high"}]}},
        source_path="fixtures/reports/socket-policy-violation.json",
        run_id="run-us1",
    )

    assert evidence["status"] == "deny"
    assert any("policy" in reason.lower() for reason in evidence["reasons"])


@pytest.mark.parametrize(
    "report",
    [
        {"alerts": [{"type": "malware", "severity": "critical", "title": "malware indicator"}]},
        {"supply_chain_risk": True, "alerts": [{"type": "supply_chain", "title": "typosquat risk"}]},
    ],
)
def test_socket_malware_or_supply_chain_risk_denies(report):
    evidence = normalize_socket_report_data(
        report,
        source_path="fixtures/reports/socket-malware-risk.json",
        run_id="run-us1",
    )

    assert evidence["status"] == "deny"
    assert any("malware" in reason.lower() or "supply-chain" in reason.lower() for reason in evidence["reasons"])


def test_socket_policy_failure_exit_code_denies():
    evidence = socket_evidence_from_classification(
        "policy_failure",
        exit_code=1,
        command="socket ci --json",
        run_id="run-us1",
    )

    assert evidence["status"] == "deny"
    assert evidence["exit_code"] == 1


@pytest.mark.parametrize("classification", ["auth_or_network_unavailable", "timeout", "unknown_exit_code"])
def test_socket_unavailable_timeout_and_unknown_exit_codes_require_manual_review(classification):
    evidence = socket_evidence_from_classification(
        classification,
        exit_code=99,
        command="socket ci --json",
        run_id="run-us1",
    )

    assert evidence["status"] == "manual_review"
    assert evidence["risk_level"] == "unknown"
    assert any(classification in reason for reason in evidence["reasons"])


def test_socket_unparseable_report_requires_manual_review(tmp_path):
    report = tmp_path / "socket.txt"
    report.write_text("not json", encoding="utf-8")

    evidence = normalize_socket_report(report, run_id="run-us1")

    assert evidence["status"] == "manual_review"
    assert any("parse" in reason.lower() for reason in evidence["reasons"])
