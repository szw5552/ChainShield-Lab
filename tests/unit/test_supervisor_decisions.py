from dataclasses import replace

from chainshield.config import WorkerProviderConfig
from chainshield.supervisor import GateEvidence, decide_static_gates


def evidence(gate, status, reasons=None):
    return GateEvidence(
        gate=gate,
        status=status,
        source_kind="fixture",
        source_path=f"fixtures/reports/{gate}.json",
        command=None,
        exit_code=0 if status == "pass" else 1,
        risk_level="critical" if status == "deny" else "none",
        reasons=reasons or [f"{gate} {status}"],
        observed_at="2026-05-27T00:00:00Z",
        run_id="run-foundation",
    )


def test_snyk_deny_wins_static_gate_matrix():
    decision = decide_static_gates([evidence("snyk", "deny"), evidence("socket", "pass")])

    assert decision.decision == "deny"
    assert "snyk" in decision.primary_reasons[0].lower()


def test_socket_deny_wins_static_gate_matrix():
    decision = decide_static_gates([evidence("snyk", "pass"), evidence("socket", "deny")])

    assert decision.decision == "deny"
    assert "socket" in decision.primary_reasons[0].lower()


def test_missing_evidence_yields_manual_review():
    decision = decide_static_gates([evidence("snyk", "pass")])

    assert decision.decision == "manual_review"
    assert decision.missing_gates == ["socket"]


def test_skipped_scanner_modes_yield_manual_review_with_missing_gates():
    decision = decide_static_gates(
        [], scanner_mode={"snyk": "skip", "socket": "skip"}
    )

    assert decision.decision == "manual_review"
    assert decision.missing_gates == ["snyk", "socket"]


def test_static_deny_cannot_be_overridden_by_sandbox_demo_override():
    decision = decide_static_gates(
        [evidence("snyk", "deny"), evidence("socket", "pass")],
        sandbox_demo_override=True,
    )

    assert decision.decision == "deny"
    assert any("override" in action.lower() for action in decision.next_actions)


def test_static_deny_still_reports_missing_peer_static_gate():
    missing_socket = decide_static_gates([evidence("snyk", "deny")])
    skipped_socket = decide_static_gates(
        [evidence("snyk", "deny")],
        scanner_mode={"snyk": "fixture", "socket": "skip"},
    )

    assert missing_socket.decision == "deny"
    assert missing_socket.missing_gates == ["socket"]
    assert skipped_socket.decision == "deny"
    assert skipped_socket.missing_gates == ["socket"]


def test_allow_requires_snyk_socket_pass_with_fixture_or_live_source_kind():
    decision = decide_static_gates([evidence("snyk", "pass"), evidence("socket", "pass")])
    assert decision.decision == "allow"

    manual = replace(evidence("snyk", "pass"), source_kind="manual_observation")
    decision = decide_static_gates([manual, evidence("socket", "pass")])
    assert decision.decision == "manual_review"
    assert "snyk" in decision.missing_gates


def test_conflicting_gate_results_yield_manual_review():
    decision = decide_static_gates([evidence("snyk", "pass"), evidence("snyk", "manual_review"), evidence("socket", "pass")])
    assert decision.decision == "manual_review"
    assert "snyk" in decision.missing_gates


def openshell(status="pass", events=True):
    item = replace(evidence("openshell", status), risk_level="none", source_path="fixtures/reports/openshell-deny.log")
    if events:
        item_dict = item.to_dict()
        item_dict["containment_events"] = [
            {
                "event_type": "filesystem_read",
                "blocked_path": "/sandbox/canary/canary-secret.txt",
                "blocked_target": None,
                "policy_rule_id": "fs.default_deny",
                "result": "blocked",
                "timestamp": "2026-05-27T00:00:00Z",
                "artifact_path": "fixtures/reports/openshell-deny.log",
                "source_kind": "fixture",
                "sanitized": True,
            },
            {
                "event_type": "network_egress",
                "blocked_path": None,
                "blocked_target": "https://chainshield-egress-test.invalid/collect",
                "policy_rule_id": "net.default_deny",
                "result": "blocked",
                "timestamp": "2026-05-27T00:00:01Z",
                "artifact_path": "fixtures/reports/openshell-deny.log",
                "source_kind": "fixture",
                "sanitized": True,
            },
        ]
        return item_dict
    return item.to_dict()


def test_sandbox_executed_allow_requires_complete_openshell_containment():
    base = [evidence("snyk", "pass"), evidence("socket", "pass")]

    missing_event = openshell("pass")
    missing_event["containment_events"] = missing_event["containment_events"][:1]
    decision = decide_static_gates([*base, missing_event])
    assert decision.decision == "manual_review"
    assert "openshell" in decision.missing_gates

    decision = decide_static_gates([*base, openshell("pass")])
    assert decision.decision == "allow"


def test_worker_finding_status_blocks_allow_without_direct_deny():
    clear_invocation = {
        "provider": "nemotron_api",
        "model": "nvidia/nemotron-3-nano-30b-a3b",
        "status": "pass",
        "request_id": "REQ-worker",
        "run_id": "run-foundation",
        "finding_status": "clear",
        "boundary_violation": False,
        "boundary_violation_reasons": [],
        "task_packet_path": "reports/worker-task-packet.json",
        "input_artifacts": [],
        "output_artifact_path": "reports/worker-summary.json",
        "observations": ["all evidence clear"],
        "missing_evidence": [],
        "errors": [],
        "observed_at": "2026-05-27T00:00:00Z",
        "sanitized": True,
    }
    concern = dict(clear_invocation, finding_status="concern", observations=["worker concern"])

    decision = decide_static_gates(
        [evidence("snyk", "pass"), evidence("socket", "pass")],
        worker_provider=WorkerProviderConfig.default_enabled("reports/worker-summary.json"),
        agent_invocations=[concern],
    )
    assert decision.decision == "manual_review"
    assert "worker_provider" in decision.missing_gates

    decision = decide_static_gates(
        [evidence("snyk", "pass"), evidence("socket", "pass")],
        worker_provider=WorkerProviderConfig.default_enabled("reports/worker-summary.json"),
        agent_invocations=[clear_invocation],
    )
    assert decision.decision == "allow"


def test_worker_clear_invocation_cannot_upgrade_static_deny():
    clear_invocation = {
        "provider": "nemotron_api",
        "model": "nvidia/nemotron-3-nano-30b-a3b",
        "status": "pass",
        "request_id": "REQ-worker",
        "run_id": "run-foundation",
        "finding_status": "clear",
        "boundary_violation": False,
        "boundary_violation_reasons": [],
        "task_packet_path": "reports/worker-task-packet.json",
        "input_artifacts": [],
        "output_artifact_path": "reports/worker-summary.json",
        "observations": ["worker evidence is clear"],
        "missing_evidence": [],
        "errors": [],
        "observed_at": "2026-05-27T00:00:00Z",
        "sanitized": True,
    }

    decision = decide_static_gates(
        [evidence("snyk", "deny"), evidence("socket", "pass")],
        worker_provider=WorkerProviderConfig.default_enabled("reports/worker-summary.json"),
        agent_invocations=[clear_invocation],
    )

    assert decision.decision == "deny"
    assert "snyk" in decision.primary_reasons[0].lower()


def test_worker_disabled_produces_no_agent_invocations():
    decision = decide_static_gates([evidence("snyk", "pass"), evidence("socket", "pass")])
    assert decision.agent_invocations == []
    assert decision.worker_provider["enabled"] is False
