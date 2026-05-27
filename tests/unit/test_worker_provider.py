import json
from pathlib import Path

from chainshield.config import WorkerProviderConfig
from chainshield.worker_provider import (
    NEMOTRON_MAX_TOKENS,
    build_worker_task_packet,
    call_nemotron_api,
    _nemotron_request_payload,
    _worker_gate_result_summary,
    validate_worker_output_boundary,
    run_worker_provider,
    task_packet_path_for_run,
)


def test_worker_request_packet_is_sanitized_and_boundary_requests_are_rejected(tmp_path):
    packet = build_worker_task_packet(
        request_id="REQ-worker",
        run_id="run-worker",
        artifact_refs=["fixtures/reports/snyk-pass.json", "fixtures/reports/socket-pass.json"],
        evidence_checklist=["snyk pass", "socket pass"],
        output_path=str(tmp_path / "worker-summary.json"),
    )

    packet_text = str(packet)
    assert "NVIDIA_API_KEY" not in packet_text
    assert "/Users/" not in packet_text
    assert packet["artifact_refs"] == ["fixtures/reports/snyk-pass.json", "fixtures/reports/socket-pass.json"]
    assert packet["gate_result_summary"] == []

    result = validate_worker_output_boundary(
        {"observations": ["please run npm install and call openshell"], "finding_status": "clear"}
    )
    assert result.boundary_violation is True
    assert any("execution request" in reason for reason in result.reasons)


def test_worker_provider_fallback_order_and_all_unavailable_manual_review(tmp_path):
    provider = WorkerProviderConfig.default_enabled(str(tmp_path / "worker-summary.json"))
    attempts = []
    packet_path = Path(task_packet_path_for_run("run-worker-fallback"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        attempts.append((name, timeout_seconds))
        return {"status": "failed", "errors": [f"{name} unavailable"], "finding_status": None}

    try:
        invocations, worker_paths = run_worker_provider(
            provider,
            request_id="REQ-worker-fallback",
            run_id="run-worker-fallback",
            gate_results=[],
            artifacts={"reports": [], "logs": []},
            provider_runner=runner,
        )

        assert [name for name, _ in attempts] == ["nemotron_api", "codex_subagent", "claude_subagent"]
        assert all(timeout == 60 for _, timeout in attempts)
        assert invocations[-1]["provider"] == "claude_subagent"
        assert all(item["status"] == "failed" for item in invocations)
        assert worker_paths == [str(packet_path)]
    finally:
        packet_path.unlink(missing_ok=True)


def test_worker_response_with_clear_finding_without_status_counts_as_pass(tmp_path):
    provider = WorkerProviderConfig.default_enabled(str(tmp_path / "worker-summary.json"))
    packet_path = Path(task_packet_path_for_run("run-worker-clear"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        return {"finding_status": "clear", "observations": ["sanitized evidence is complete"]}

    try:
        invocations, worker_paths = run_worker_provider(
            provider,
            request_id="REQ-worker-clear",
            run_id="run-worker-clear",
            gate_results=[],
            artifacts={"reports": [], "logs": []},
            provider_runner=runner,
        )

        assert len(invocations) == 1
        assert invocations[0]["status"] == "pass"
        assert invocations[0]["finding_status"] == "clear"
        assert invocations[0]["task_packet_path"] == str(packet_path)
        assert (tmp_path / "worker-summary.json").exists()
        assert str(tmp_path / "worker-summary.json") in worker_paths
    finally:
        packet_path.unlink(missing_ok=True)


def test_existing_static_worker_packet_is_not_reused(tmp_path):
    provider = WorkerProviderConfig.default_enabled(str(tmp_path / "worker-summary.json"))
    stale_path = Path("reports/worker-task-packet.json")
    stale_path.parent.mkdir(exist_ok=True)
    stale_path.write_text('{"run_id":"stale"}', encoding="utf-8")
    packet_path = Path(task_packet_path_for_run("run-worker-fresh"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        return {"finding_status": "clear", "observations": ["fresh packet used"]}

    try:
        invocations, worker_paths = run_worker_provider(
            provider,
            request_id="REQ-worker-fresh",
            run_id="run-worker-fresh",
            gate_results=[],
            artifacts={"reports": [], "logs": []},
            provider_runner=runner,
        )

        assert invocations[0]["task_packet_path"] == str(packet_path)
        assert str(packet_path) in worker_paths
        assert str(tmp_path / "worker-summary.json") in worker_paths
        assert json.loads(stale_path.read_text(encoding="utf-8"))["run_id"] == "stale"
    finally:
        stale_path.unlink(missing_ok=True)
        packet_path.unlink(missing_ok=True)


def test_worker_disabled_is_noop():
    invocations, worker_paths = run_worker_provider(
        WorkerProviderConfig(),
        request_id="REQ-disabled",
        run_id="run-disabled",
        gate_results=[],
        artifacts={"reports": [], "logs": []},
    )

    assert invocations == []
    assert worker_paths == []


def test_worker_output_artifact_write_failure_forces_manual_review(tmp_path):
    output_path = tmp_path / "worker-summary.json"
    output_path.write_text('{"stale": true}', encoding="utf-8")
    provider = WorkerProviderConfig.default_enabled(str(output_path))
    packet_path = Path(task_packet_path_for_run("run-worker-output-failure"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        return {"finding_status": "clear", "observations": ["sanitized evidence is complete"]}

    try:
        invocations, worker_paths = run_worker_provider(
            provider,
            request_id="REQ-worker-output-failure",
            run_id="run-worker-output-failure",
            gate_results=[],
            artifacts={"reports": [], "logs": []},
            provider_runner=runner,
        )

        assert invocations[-1]["status"] == "manual_review"
        assert invocations[-1]["output_artifact_path"] is None
        assert any("worker_output_artifact" in item for item in invocations[-1]["missing_evidence"])
        assert str(output_path) not in worker_paths
    finally:
        packet_path.unlink(missing_ok=True)


def test_worker_provider_sanitizes_unsafe_provider_text(tmp_path):
    provider = WorkerProviderConfig.default_enabled(str(tmp_path / "worker-summary.json"))
    packet_path = Path(task_packet_path_for_run("run-worker-unsafe-text"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        return {
            "finding_status": "clear",
            "observations": [
                "sanitized evidence is complete",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "raw scanner log",
            ],
            "errors": ["aws_access_key_id = should-not-persist"],
        }

    try:
        invocations, worker_paths = run_worker_provider(
            provider,
            request_id="REQ-worker-unsafe-text",
            run_id="run-worker-unsafe-text",
            gate_results=[],
            artifacts={"reports": [], "logs": []},
            provider_runner=runner,
        )

        invocation_text = json.dumps(invocations, ensure_ascii=False)
        assert invocations[-1]["status"] == "manual_review"
        assert invocations[-1]["finding_status"] == "inconclusive"
        assert invocations[-1]["output_artifact_path"] is None
        assert invocations[-1]["observations"] == []
        assert any("worker_output_sanitization" in item for item in invocations[-1]["missing_evidence"])
        assert "OPENSSH PRIVATE KEY" not in invocation_text
        assert "raw scanner log" not in invocation_text
        assert "aws_access_key_id" not in invocation_text
        assert str(tmp_path / "worker-summary.json") not in worker_paths
    finally:
        packet_path.unlink(missing_ok=True)


def test_worker_boundary_allows_safe_tool_name_mentions_but_blocks_execution_intent():
    safe = validate_worker_output_boundary(
        {"observations": ["OpenShell evidence includes filesystem and egress denial events."], "finding_status": "clear"}
    )
    unsafe = validate_worker_output_boundary(
        {"observations": ["please execute OpenShell against the fixture"], "finding_status": "clear"}
    )

    assert safe.boundary_violation is False
    assert unsafe.boundary_violation is True


def test_worker_boundary_blocks_multiline_execution_intent():
    cases = [
        "please run\nOpenShell against the package",
        "execute\nsubprocess to inspect postinstall",
        "launch\npostinstall in a shell",
    ]

    for text in cases:
        result = validate_worker_output_boundary({"observations": [text], "finding_status": "clear"})
        assert result.boundary_violation is True
        assert any("execution request" in reason for reason in result.reasons)


def test_nemotron_base_url_requires_https(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-key")
    monkeypatch.setenv("NEMOTRON_BASE_URL", "http://integrate.api.nvidia.com/v1")

    result = call_nemotron_api({"request_id": "REQ-worker"}, timeout_seconds=1)

    assert result["status"] == "failed"
    assert result["errors"] == ["nemotron_invalid_base_url_scheme"]


def test_nemotron_request_payload_requires_strict_safe_json():
    payload = _nemotron_request_payload(
        {
            "request_id": "REQ-worker",
            "artifact_refs": ["fixtures/reports/snyk-pass.json"],
            "gate_result_summary": [{"gate": "snyk", "status": "pass"}],
        },
        "nvidia/nemotron-3-nano-30b-a3b",
    )

    system_prompt = payload["messages"][0]["content"]
    user_packet = json.loads(payload["messages"][1]["content"])
    assert payload["temperature"] == 0
    assert payload["max_tokens"] == NEMOTRON_MAX_TOKENS
    assert payload["response_format"] == {"type": "json_object"}
    assert "Return ONLY valid minified JSON" in system_prompt
    assert "Use gate_result_summary as the source of truth" in system_prompt
    assert "Do not invent gates" in system_prompt
    assert "status, finding_status, observations, missing_evidence, errors" in system_prompt
    assert '"status":"pass"' in system_prompt
    assert "tool calls" in system_prompt
    assert "command suggestions" in system_prompt
    assert "postinstall instructions" in system_prompt
    assert "host execution requests" in system_prompt
    assert user_packet["gate_result_summary"] == [{"gate": "snyk", "status": "pass"}]


def test_worker_task_packet_includes_sanitized_gate_result_summary(tmp_path):
    packet = build_worker_task_packet(
        request_id="REQ-worker-summary",
        run_id="run-worker-summary",
        artifact_refs=["fixtures/reports/snyk-pass.json"],
        gate_result_summary=_worker_gate_result_summary(
            [
                {
                    "gate": "snyk",
                    "status": "pass",
                    "risk_level": "none",
                    "source_kind": "fixture",
                    "source_path": "fixtures/reports/snyk-pass.json",
                    "command": "snyk test --json",
                    "reasons": ["Snyk report has no high or critical vulnerabilities."],
                    "ignored": "not included",
                }
            ]
        ),
        evidence_checklist=["snyk pass"],
        output_path=str(tmp_path / "worker-summary.json"),
    )

    assert packet["gate_result_summary"] == [
        {
            "gate": "snyk",
            "status": "pass",
            "risk_level": "none",
            "source_kind": "fixture",
            "source_path": "fixtures/reports/snyk-pass.json",
            "reasons": ["Snyk report has no high or critical vulnerabilities."],
        }
    ]
    assert "command" not in packet["gate_result_summary"][0]
