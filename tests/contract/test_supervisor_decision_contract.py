from chainshield.config import build_run_id
from chainshield.supervisor import decide_static_gates
from chainshield.schemas import validate_contract


def gate(gate_name, status="pass", *, source_kind="fixture", run_id="run-contract"):
    return {
        "gate": gate_name,
        "run_id": run_id,
        "status": status,
        "source_kind": source_kind,
        "source_path": f"fixtures/reports/{gate_name}-pass.json",
        "command": None,
        "exit_code": 0,
        "risk_level": "none",
        "reasons": [f"{gate_name} fixture {status}"],
        "observed_at": "2026-05-27T00:00:00Z",
        "sanitized": True,
    }


def test_supervisor_decision_contract_and_run_id_traceability():
    timestamp = "2026-05-27T00:00:00Z"
    run_id = build_run_id(
        "fixtures/configs/demo-fixture-allow.json",
        {"snyk_report": "fixtures/reports/snyk-pass.json", "socket_report": "fixtures/reports/socket-pass.json"},
        timestamp,
        "abcdef1234567890",
    )

    decision = decide_static_gates(
        [gate("snyk", run_id=run_id), gate("socket", run_id=run_id)],
        request_id="REQ-contract",
        run_id=run_id,
        artifacts={
            "decision_json": "reports/contract-decision.json",
            "markdown_summary": "reports/contract-summary.md",
            "reports": ["fixtures/reports/snyk-pass.json", "fixtures/reports/socket-pass.json"],
            "logs": [],
            "worker": [],
        },
    ).to_dict()

    assert "fixtures" not in run_id
    assert run_id.startswith("run-20260527T000000Z-")
    assert decision["run_id"] == run_id
    validate_contract("supervisor-decision.schema.json", decision)
