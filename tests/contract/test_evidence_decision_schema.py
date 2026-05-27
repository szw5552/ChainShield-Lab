from chainshield.schemas import validate_contract


GATE_EVIDENCE = {
    "gate": "snyk",
    "run_id": "run-foundation",
    "status": "deny",
    "source_kind": "fixture",
    "source_path": "fixtures/reports/snyk-high-critical.json",
    "command": None,
    "exit_code": 1,
    "risk_level": "critical",
    "reasons": ["critical vulnerability fixture"],
    "observed_at": "2026-05-27T00:00:00Z",
    "sanitized": True,
}

AGENT_INVOCATION = {
    "provider": "nemotron_api",
    "model": "nvidia/nemotron-3-nano-30b-a3b",
    "status": "failed",
    "request_id": "REQ-foundation",
    "run_id": "run-foundation",
    "finding_status": None,
    "boundary_violation": False,
    "boundary_violation_reasons": [],
    "task_packet_path": "reports/worker-task-packet.json",
    "input_artifacts": ["reports/decision.json"],
    "output_artifact_path": None,
    "observations": [],
    "missing_evidence": ["nvidia_api_key"],
    "errors": ["NVIDIA_API_KEY unavailable"],
    "observed_at": "2026-05-27T00:00:01Z",
    "sanitized": True,
}


def test_gate_evidence_schema_requires_sanitized_evidence():
    validate_contract("gate-evidence.schema.json", GATE_EVIDENCE)

    dirty = dict(GATE_EVIDENCE)
    dirty["sanitized"] = False

    errors = validate_contract("gate-evidence.schema.json", dirty, raise_on_error=False)
    assert any("True was expected" in error.message for error in errors)


def test_agent_invocation_schema_requires_finding_status_for_pass_only():
    passing = dict(AGENT_INVOCATION, status="pass", finding_status="clear")
    validate_contract("agent-invocation-evidence.schema.json", passing)

    invalid_pass = dict(AGENT_INVOCATION, status="pass", finding_status=None)
    errors = validate_contract("agent-invocation-evidence.schema.json", invalid_pass, raise_on_error=False)
    assert errors

    invalid_failed = dict(AGENT_INVOCATION, status="failed", finding_status="clear")
    errors = validate_contract("agent-invocation-evidence.schema.json", invalid_failed, raise_on_error=False)
    assert errors


def test_supervisor_decision_schema_requires_traceable_fields_and_worker_metadata():
    decision = {
        "request_id": "REQ-foundation",
        "run_id": "run-foundation",
        "decision": "deny",
        "summary": "Static gate denied the install.",
        "primary_reasons": ["Snyk critical vulnerability fixture"],
        "gate_results": [GATE_EVIDENCE],
        "agent_invocations": [AGENT_INVOCATION],
        "missing_gates": [],
        "next_actions": ["Do not run npm install on host."],
        "generated_at": "2026-05-27T00:00:02Z",
        "worker_provider": {
            "enabled": True,
            "provider_chain": ["nemotron_api", "codex_subagent", "claude_subagent", "manual_review"],
            "fallback_order_after_primary_failure": ["codex_subagent", "claude_subagent", "manual_review"],
            "timeout_seconds": 60,
            "output_path": "reports/worker-summary.json",
        },
        "artifacts": {
            "decision_json": "reports/decision.json",
            "markdown_summary": "reports/summary.md",
            "reports": ["fixtures/reports/snyk-high-critical.json"],
            "logs": [],
            "worker": ["reports/worker-summary.json"],
        },
    }

    validate_contract("supervisor-decision.schema.json", decision)

    missing = dict(decision)
    missing.pop("primary_reasons")
    errors = validate_contract("supervisor-decision.schema.json", missing, raise_on_error=False)
    assert any("'primary_reasons' is a required property" in error.message for error in errors)
