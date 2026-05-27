from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from .artifacts import ArtifactWriteError, redact_text, sanitize_text, write_json_artifact
from .config import DEFAULT_WORKER_TIMEOUT_SECONDS, WorkerProviderConfig

DEFAULT_NEMOTRON_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_NEMOTRON_MODEL = "nvidia/nemotron-3-nano-30b-a3b"
TASK_PACKET_PATH = "reports/worker-task-packet.json"
UNSAFE_WORKER_PATTERNS = [
    re.compile(r"\bnpm\s+(?:install|run|exec|pack)\b", re.I),
    re.compile(r"\b(?:run|execute|invoke|spawn|launch)\b[\s\S]{0,40}\bpostinstall\b", re.I),
    re.compile(r"\bsnyk\s+test\b", re.I),
    re.compile(r"\bsocket\s+(?:ci|scan)\b", re.I),
    re.compile(r"\b(?:run|execute|invoke|spawn|launch)\b[\s\S]{0,40}\b(?:openshell|nemoclaw)\b", re.I),
    re.compile(r"\b(?:run|execute|invoke|spawn|launch)\b[\s\S]{0,40}\b(?:shell|subprocess|exec)\b", re.I),
    re.compile(r"\b(?:tool_call|function_call)\s*\(|\bexecute\s+tool\b|\bunauthorized tool invocation\b", re.I),
]


@dataclass(frozen=True)
class BoundaryValidationResult:
    boundary_violation: bool
    reasons: list[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def task_packet_path_for_run(run_id: str) -> str:
    safe_run_id = re.sub(r"[^0-9A-Za-z_.-]+", "-", run_id).strip("-") or "run"
    return f"reports/worker-task-packet-{safe_run_id}.json"


def redact_provider_text(text: str) -> str:
    return redact_text(text)


def build_worker_task_packet(
    *,
    request_id: str,
    run_id: str,
    artifact_refs: list[str],
    evidence_checklist: list[str],
    output_path: str | None,
) -> dict[str, Any]:
    packet = {
        "request_id": request_id,
        "run_id": run_id,
        "provider_chain": ["nemotron_api", "codex_subagent", "claude_subagent", "manual_review"],
        "fallback_order_after_primary_failure": ["codex_subagent", "claude_subagent", "manual_review"],
        "artifact_refs": artifact_refs,
        "evidence_checklist": evidence_checklist,
        "output_path": output_path,
        "metadata": {
            "purpose": "sanitized ChainShield Worker evidence summary only",
            "safety": "do not execute scanner, sandbox, shell, npm lifecycle, or host commands",
        },
    }
    text = json.dumps(packet, ensure_ascii=False, sort_keys=True)
    result = sanitize_text(text)
    if not result.safe:
        raise ArtifactWriteError("refusing to build unsanitized worker task packet: " + ", ".join(result.reasons))
    return packet


def validate_worker_output_boundary(output: Any) -> BoundaryValidationResult:
    text = json.dumps(output, ensure_ascii=False, sort_keys=True) if not isinstance(output, str) else output
    text = text.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
    reasons: list[str] = []
    for pattern in UNSAFE_WORKER_PATTERNS:
        if pattern.search(text):
            reasons.append("unsafe execution request in Worker output")
            break
    if isinstance(output, dict) and output.get("tool_calls"):
        reasons.append("unauthorized tool invocation requested by Worker output")
    return BoundaryValidationResult(boundary_violation=bool(reasons), reasons=reasons)


def build_agent_invocation(
    *,
    provider: str,
    model: str,
    status: str,
    request_id: str,
    run_id: str,
    finding_status: str | None = None,
    boundary_violation: bool = False,
    boundary_violation_reasons: list[str] | None = None,
    task_packet_path: str = TASK_PACKET_PATH,
    input_artifacts: list[str] | None = None,
    output_artifact_path: str | None = None,
    missing_evidence: list[str] | None = None,
    errors: list[str] | None = None,
    observations: list[str] | None = None,
) -> dict[str, Any]:
    clean_errors = [redact_provider_text(error) for error in (errors or [])]
    clean_observations = [redact_provider_text(item) for item in (observations or [])]
    if finding_status is None and status not in {"failed", "skipped"}:
        finding_status = "inconclusive"
    return {
        "provider": provider,
        "model": model,
        "status": status,
        "request_id": request_id,
        "run_id": run_id,
        "finding_status": finding_status,
        "boundary_violation": boundary_violation,
        "boundary_violation_reasons": boundary_violation_reasons or [],
        "task_packet_path": task_packet_path,
        "input_artifacts": input_artifacts or [],
        "output_artifact_path": output_artifact_path,
        "observations": clean_observations,
        "missing_evidence": missing_evidence or [],
        "errors": clean_errors,
        "observed_at": _utc_now(),
        "sanitized": True,
    }


def _provider_model(provider: str) -> str:
    if provider == "nemotron_api":
        return os.environ.get("NEMOTRON_MODEL", DEFAULT_NEMOTRON_MODEL)
    if provider == "codex_subagent":
        return "local-codex-chainshield-worker"
    return "local-claude-chainshield-worker"


def call_nemotron_api(packet: dict[str, Any], *, timeout_seconds: int) -> dict[str, Any]:
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        return {
            "status": "failed",
            "finding_status": None,
            "missing_evidence": ["nvidia_api_key"],
            "errors": ["NVIDIA_API_KEY unavailable"],
        }

    base_url = os.environ.get("NEMOTRON_BASE_URL", DEFAULT_NEMOTRON_BASE_URL).rstrip("/")
    parsed_url = urlparse(base_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        return {"status": "failed", "finding_status": None, "errors": ["nemotron_invalid_base_url_scheme"]}
    model = os.environ.get("NEMOTRON_MODEL", DEFAULT_NEMOTRON_MODEL)
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return a sanitized ChainShield worker evidence summary only. Do not request tool execution.",
                },
                {"role": "user", "content": json.dumps(packet, ensure_ascii=False, sort_keys=True)},
            ],
            "temperature": 0,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return {"status": "failed", "finding_status": None, "errors": [f"nemotron_http_{exc.code}"]}
    except (urllib.error.URLError, TimeoutError) as exc:
        return {"status": "failed", "finding_status": None, "errors": [f"nemotron_unavailable: {type(exc).__name__}"]}

    try:
        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content) if isinstance(content, str) and content.strip().startswith("{") else {"observations": [content]}
    except Exception as exc:  # sanitized parse reason only
        return {"status": "failed", "finding_status": None, "errors": [f"malformed response: {type(exc).__name__}"]}
    return parsed if isinstance(parsed, dict) else {"status": "failed", "errors": ["malformed response: non-object"]}


def _default_provider_runner(provider: str, packet: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    if provider == "nemotron_api":
        return call_nemotron_api(packet, timeout_seconds=timeout_seconds)
    return {
        "status": "failed",
        "finding_status": None,
        "missing_evidence": [f"{provider}_manual_handoff_required"],
        "errors": [f"{provider} unavailable in automated CLI path; use .agents/skills/chainshield-worker/SKILL.md manually"],
    }


def _normalize_response(
    *,
    provider: str,
    response: dict[str, Any],
    request_id: str,
    run_id: str,
    packet_path: str,
    input_artifacts: list[str],
    output_path: str | None,
) -> dict[str, Any]:
    boundary = validate_worker_output_boundary(response)
    finding = response.get("finding_status")
    if finding not in {"clear", "concern", "inconclusive", None}:
        finding = "inconclusive"
    missing_evidence = [str(item) for item in response.get("missing_evidence", [])]
    errors = [str(item) for item in response.get("errors", [])]
    if response.get("status"):
        status = str(response["status"])
    elif finding == "clear" and not missing_evidence and not errors:
        status = "pass"
    elif finding in {"concern", "inconclusive"} or missing_evidence:
        status = "manual_review"
    else:
        status = "failed"
    if boundary.boundary_violation:
        status = "manual_review"
    return build_agent_invocation(
        provider=provider,
        model=str(response.get("model") or _provider_model(provider)),
        status=status,
        request_id=request_id,
        run_id=run_id,
        finding_status=finding,
        boundary_violation=boundary.boundary_violation,
        boundary_violation_reasons=boundary.reasons,
        task_packet_path=packet_path,
        input_artifacts=input_artifacts,
        output_artifact_path=output_path if status == "pass" else None,
        missing_evidence=missing_evidence,
        errors=errors,
        observations=[str(item) for item in response.get("observations", [])],
    )


def _persist_worker_output(invocation: dict[str, Any], output_path: str) -> dict[str, Any]:
    payload = {
        "provider": invocation["provider"],
        "model": invocation["model"],
        "status": invocation["status"],
        "request_id": invocation["request_id"],
        "run_id": invocation["run_id"],
        "finding_status": invocation["finding_status"],
        "boundary_violation": invocation["boundary_violation"],
        "task_packet_path": invocation["task_packet_path"],
        "input_artifacts": invocation["input_artifacts"],
        "observations": invocation["observations"],
        "missing_evidence": invocation["missing_evidence"],
        "errors": invocation["errors"],
        "observed_at": invocation["observed_at"],
        "sanitized": True,
    }
    try:
        write_json_artifact(output_path, payload)
    except ArtifactWriteError as exc:
        updated = dict(invocation)
        updated["status"] = "manual_review"
        updated["output_artifact_path"] = None
        updated["missing_evidence"] = list(dict.fromkeys([*updated.get("missing_evidence", []), "worker_output_artifact"]))
        updated["errors"] = list(updated.get("errors", [])) + [redact_provider_text(f"worker_output_artifact_write_failed: {exc}")]
        return updated
    return invocation


def run_worker_provider(
    provider: WorkerProviderConfig,
    *,
    request_id: str,
    run_id: str,
    gate_results: list[dict[str, Any]],
    artifacts: dict[str, Any],
    provider_runner: Callable[[str, dict[str, Any], int], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not provider.enabled:
        return [], []

    input_artifacts = list(dict.fromkeys([*artifacts.get("reports", []), *artifacts.get("logs", [])]))
    checklist = [
        "Snyk and Socket evidence must pass or provide deterministic deny/manual_review reasons.",
        "OpenShell evidence must include filesystem_read and network_egress blocks when sandbox ran.",
        "Worker finding_status must be clear to support allow; concern/inconclusive require manual_review.",
    ]
    packet = build_worker_task_packet(
        request_id=request_id,
        run_id=run_id,
        artifact_refs=input_artifacts,
        evidence_checklist=checklist,
        output_path=provider.output_path,
    )
    packet_path = task_packet_path_for_run(run_id)
    try:
        write_json_artifact(packet_path, packet)
    except ArtifactWriteError:
        # Existing task packets are runtime artifacts; avoid pointing at stale evidence.
        packet_path = "in-memory"

    runner = provider_runner or _default_provider_runner
    invocations: list[dict[str, Any]] = []
    chain = [provider.primary or "nemotron_api", *provider.fallbacks]
    chain = [name for name in chain if name in {"nemotron_api", "codex_subagent", "claude_subagent"}]
    if not chain:
        chain = ["nemotron_api", "codex_subagent", "claude_subagent"]

    for provider_name in chain:
        response = runner(provider_name, packet, provider.timeout_seconds or DEFAULT_WORKER_TIMEOUT_SECONDS)
        invocation = _normalize_response(
            provider=provider_name,
            response=response,
            request_id=request_id,
            run_id=run_id,
            packet_path=packet_path,
            input_artifacts=input_artifacts,
            output_path=provider.output_path,
        )
        if invocation["status"] == "pass" and invocation["finding_status"] == "clear" and not invocation["boundary_violation"]:
            if provider.output_path:
                invocation = _persist_worker_output(invocation, provider.output_path)
        invocations.append(invocation)
        if invocation["status"] == "pass" and invocation["finding_status"] == "clear" and not invocation["boundary_violation"]:
            break

    worker_paths = []
    if packet_path != "in-memory":
        worker_paths.append(packet_path)
    produced_outputs = [str(item["output_artifact_path"]) for item in invocations if item.get("output_artifact_path")]
    worker_paths.extend(list(dict.fromkeys(produced_outputs)))
    return invocations, worker_paths
