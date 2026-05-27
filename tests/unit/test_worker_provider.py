import json
from pathlib import Path

from chainshield.config import WorkerProviderConfig
from chainshield.worker_provider import (
    build_worker_task_packet,
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
        assert worker_paths == [str(packet_path), str(tmp_path / "worker-summary.json")]
    finally:
        packet_path.unlink(missing_ok=True)


def test_worker_response_with_clear_finding_without_status_counts_as_pass(tmp_path):
    provider = WorkerProviderConfig.default_enabled(str(tmp_path / "worker-summary.json"))
    packet_path = Path(task_packet_path_for_run("run-worker-clear"))
    packet_path.unlink(missing_ok=True)

    def runner(name, packet, timeout_seconds):
        return {"finding_status": "clear", "observations": ["sanitized evidence is complete"]}

    try:
        invocations, _ = run_worker_provider(
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
