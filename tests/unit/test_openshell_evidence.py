from __future__ import annotations

from pathlib import Path

from chainshield.evidence import normalize_openshell_log, normalize_openshell_log_data


def test_openshell_pass_requires_file_read_and_egress_blocks():
    evidence = normalize_openshell_log_data(
        "\n".join(
            [
                '{"event_type":"filesystem_read","blocked_path":"/sandbox/canary/canary-secret.txt","policy_rule_id":"fs.default_deny","result":"blocked","timestamp":"2026-05-27T00:00:00Z","artifact_path":"fixtures/reports/openshell-deny.log","source_kind":"fixture","sanitized":true}',
                '{"event_type":"network_egress","blocked_target":"https://chainshield-egress-test.invalid/collect","policy_rule_id":"net.default_deny","result":"blocked","timestamp":"2026-05-27T00:00:01Z","artifact_path":"fixtures/reports/openshell-deny.log","source_kind":"fixture","sanitized":true}',
            ]
        ),
        source_path="fixtures/reports/openshell-deny.log",
        run_id="run-openshell",
        source_kind="fixture",
    )

    assert evidence["gate"] == "openshell"
    assert evidence["status"] == "pass"
    assert {event["event_type"] for event in evidence["containment_events"]} == {"filesystem_read", "network_egress"}
    for event in evidence["containment_events"]:
        assert event["result"] == "blocked"
        assert event["policy_rule_id"]
        assert event["timestamp"]
        assert event["artifact_path"] == "fixtures/reports/openshell-deny.log"
        assert event["source_kind"] in {"live", "fixture"}
        assert event["sanitized"] is True
        assert event.get("blocked_path") or event.get("blocked_target")


def test_openshell_missing_egress_block_requires_manual_review():
    evidence = normalize_openshell_log_data(
        '{"event_type":"filesystem_read","blocked_path":"/sandbox/canary/canary-secret.txt","policy_rule_id":"fs.default_deny","result":"blocked","timestamp":"2026-05-27T00:00:00Z","artifact_path":"fixtures/reports/openshell-partial.log","source_kind":"fixture","sanitized":true}',
        source_path="fixtures/reports/openshell-partial.log",
        run_id="run-openshell",
        source_kind="fixture",
    )

    assert evidence["status"] == "manual_review"
    assert any("egress" in reason.lower() for reason in evidence["reasons"])


def test_openshell_fixture_log_normalizes_to_pass():
    evidence = normalize_openshell_log(Path("fixtures/reports/openshell-deny.log"), run_id="run-openshell")

    assert evidence["status"] == "pass"
    assert any("file read" in reason.lower() for reason in evidence["reasons"])
    assert any("egress" in reason.lower() for reason in evidence["reasons"])
