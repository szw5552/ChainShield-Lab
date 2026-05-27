from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import WorkerProviderConfig
from .evidence import REQUIRED_OPENSHELL_EVENTS

STATIC_GATES = ("snyk", "socket")
ALLOW_SOURCE_KINDS = {"fixture", "live"}


def default_artifacts() -> dict[str, Any]:
    return {
        "decision_json": "reports/decision.json",
        "markdown_summary": None,
        "reports": [],
        "logs": [],
        "worker": [],
    }


@dataclass(frozen=True)
class GateEvidence:
    gate: str
    status: str
    source_kind: str
    source_path: str | None
    command: str | None
    exit_code: int | None
    risk_level: str
    reasons: list[str]
    observed_at: str
    run_id: str
    sanitized: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "run_id": self.run_id,
            "status": self.status,
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "command": self.command,
            "exit_code": self.exit_code,
            "risk_level": self.risk_level,
            "reasons": self.reasons,
            "observed_at": self.observed_at,
            "sanitized": self.sanitized,
        }


@dataclass(frozen=True)
class SupervisorDecision:
    decision: str
    summary: str
    primary_reasons: list[str]
    gate_results: list[dict[str, Any]] = field(default_factory=list)
    missing_gates: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    request_id: str = "REQ-foundation"
    run_id: str = "run-foundation"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    agent_invocations: list[dict[str, Any]] = field(default_factory=list)
    worker_provider: dict[str, Any] = field(default_factory=lambda: WorkerProviderConfig().to_decision_metadata())
    artifacts: dict[str, Any] = field(default_factory=default_artifacts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "run_id": self.run_id,
            "decision": self.decision,
            "summary": self.summary,
            "primary_reasons": self.primary_reasons,
            "gate_results": self.gate_results,
            "agent_invocations": self.agent_invocations,
            "missing_gates": self.missing_gates,
            "next_actions": self.next_actions,
            "generated_at": self.generated_at,
            "worker_provider": self.worker_provider,
            "artifacts": self.artifacts,
        }


def _evidence_dict(item: GateEvidence | dict[str, Any]) -> dict[str, Any]:
    return item.to_dict() if isinstance(item, GateEvidence) else dict(item)


def _manual_review(
    *,
    summary: str,
    reasons: list[str],
    results: list[dict[str, Any]],
    missing: list[str],
    request_id: str,
    run_id: str,
    artifacts: dict[str, Any] | None,
    worker_provider: WorkerProviderConfig | None,
    agent_invocations: list[dict[str, Any]] | None = None,
) -> SupervisorDecision:
    return SupervisorDecision(
        decision="manual_review",
        summary=summary,
        primary_reasons=reasons or ["Evidence is insufficient for an allow decision."],
        gate_results=results,
        agent_invocations=agent_invocations or [],
        missing_gates=list(dict.fromkeys(missing)),
        next_actions=[
            "Provide updated sanitized evidence/config and rerun Supervisor.",
            "Use a new output path; do not manually rewrite an existing manual_review decision into allow.",
            "Do not run npm lifecycle scripts on the host.",
        ],
        request_id=request_id,
        run_id=run_id,
        artifacts=artifacts or default_artifacts(),
        worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
    )


def _conflicting_static_gates(results: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    missing: list[str] = []
    for gate in STATIC_GATES:
        statuses = {item.get("status") for item in results if item.get("gate") == gate}
        if len(statuses) > 1:
            missing.append(gate)
            reasons.append(f"{gate} evidence has conflicting statuses: {', '.join(sorted(str(item) for item in statuses))}")
    return reasons, missing


def _missing_static_gates_for_deny(by_gate: dict[str, dict[str, Any]], scanner_mode: dict[str, str]) -> list[str]:
    missing: list[str] = []
    for gate in STATIC_GATES:
        item = by_gate.get(gate)
        if scanner_mode.get(gate) == "skip" or item is None or item.get("status") in {"manual_review", "skipped"}:
            missing.append(gate)
    return list(dict.fromkeys(missing))


def _openshell_sufficient(item: dict[str, Any] | None) -> tuple[bool, list[str]]:
    if item is None:
        return True, []
    reasons: list[str] = []
    if item.get("status") != "pass":
        reasons.extend(item.get("reasons") or ["OpenShell containment evidence did not pass."])
    if item.get("source_kind") not in ALLOW_SOURCE_KINDS:
        reasons.append("OpenShell evidence must be live or fixture to support allow.")
    events = item.get("containment_events")
    if not isinstance(events, list):
        reasons.append("OpenShell containment events are missing.")
        return False, reasons
    present = {event.get("event_type") for event in events if isinstance(event, dict) and event.get("result") == "blocked"}
    missing = set(REQUIRED_OPENSHELL_EVENTS) - present
    for event_type in sorted(missing):
        reasons.append(f"OpenShell containment evidence missing {event_type}.")
    return not reasons, reasons


def _worker_sufficient(
    *,
    worker_provider: WorkerProviderConfig | None,
    agent_invocations: list[dict[str, Any]] | None,
) -> tuple[bool, list[str]]:
    provider = worker_provider or WorkerProviderConfig()
    if not provider.enabled:
        return True, []
    invocations = agent_invocations or []
    if not invocations:
        return False, ["Worker provider is enabled but no agent invocation evidence is present."]
    reasons: list[str] = []
    for item in invocations:
        if item.get("boundary_violation") is True:
            reasons.extend(item.get("boundary_violation_reasons") or ["Worker output requested unsafe execution."])
    clear = [
        item
        for item in invocations
        if item.get("status") == "pass" and item.get("finding_status") == "clear" and item.get("boundary_violation") is not True
    ]
    # Worker providers are fallback attempts: one clear, boundary-safe summary is sufficient.
    if clear and not reasons:
        return True, []
    for item in invocations:
        finding = item.get("finding_status")
        if finding in {"concern", "inconclusive"}:
            reasons.append(f"Worker provider returned {finding}; allow requires clear.")
        reasons.extend(item.get("missing_evidence") or [])
        reasons.extend(item.get("errors") or [])
    return False, reasons or ["Worker provider did not produce clear evidence."]


def decide_static_gates(
    gate_results: Iterable[GateEvidence | dict[str, Any]],
    *,
    scanner_mode: dict[str, str] | None = None,
    sandbox_demo_override: bool = False,
    request_id: str = "REQ-foundation",
    run_id: str = "run-foundation",
    artifacts: dict[str, Any] | None = None,
    worker_provider: WorkerProviderConfig | None = None,
    agent_invocations: list[dict[str, Any]] | None = None,
) -> SupervisorDecision:
    results = [_evidence_dict(item) for item in gate_results]
    by_gate = {item["gate"]: item for item in results if item.get("gate") in STATIC_GATES}
    scanner_mode = scanner_mode or {"snyk": "fixture", "socket": "fixture"}

    denies = [item for item in results if item.get("gate") in STATIC_GATES and item.get("status") == "deny"]
    if denies:
        reasons = [f"{item['gate']} deny: " + "; ".join(item.get("reasons", [])) for item in denies]
        next_actions = ["Do not run npm install on host."]
        if sandbox_demo_override:
            next_actions.append("Sandbox demo override may run containment demo only; it cannot change static deny to allow.")
        return SupervisorDecision(
            decision="deny",
            summary="Static dependency gate denied the request.",
            primary_reasons=reasons,
            gate_results=results,
            agent_invocations=agent_invocations or [],
            missing_gates=_missing_static_gates_for_deny(by_gate, scanner_mode),
            next_actions=next_actions,
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts or default_artifacts(),
            worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
        )

    conflict_reasons, conflict_missing = _conflicting_static_gates(results)
    if conflict_reasons:
        return _manual_review(
            summary="Static dependency gate evidence is conflicting.",
            reasons=conflict_reasons,
            results=results,
            missing=conflict_missing,
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts,
            worker_provider=worker_provider,
            agent_invocations=agent_invocations,
        )

    missing: list[str] = []
    reasons: list[str] = []
    for gate in STATIC_GATES:
        item = by_gate.get(gate)
        if scanner_mode.get(gate) == "skip":
            missing.append(gate)
            reasons.append(f"{gate} scanner mode is skip")
        elif item is None:
            missing.append(gate)
            reasons.append(f"missing {gate} evidence")
        elif item.get("status") in {"manual_review", "skipped"}:
            missing.append(gate)
            reasons.extend(item.get("reasons") or [f"{gate} requires manual review"])
        elif item.get("status") != "pass":
            missing.append(gate)
            reasons.append(f"{gate} status {item.get('status')} cannot support allow")
        elif item.get("source_kind") not in ALLOW_SOURCE_KINDS:
            missing.append(gate)
            reasons.append(f"{gate} evidence source_kind must be live or fixture to support allow")
        elif item.get("sanitized") is not True:
            missing.append(gate)
            reasons.append(f"{gate} evidence must be sanitized")

    if missing:
        return _manual_review(
            summary="Static dependency gate requires manual review.",
            reasons=reasons or ["missing static gate evidence"],
            results=results,
            missing=missing,
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts,
            worker_provider=worker_provider,
            agent_invocations=agent_invocations,
        )

    openshell = next((item for item in results if item.get("gate") == "openshell"), None)
    openshell_ok, openshell_reasons = _openshell_sufficient(openshell)
    if not openshell_ok:
        return _manual_review(
            summary="OpenShell containment evidence is insufficient for allow.",
            reasons=openshell_reasons,
            results=results,
            missing=["openshell"],
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts,
            worker_provider=worker_provider,
            agent_invocations=agent_invocations,
        )

    worker_ok, worker_reasons = _worker_sufficient(worker_provider=worker_provider, agent_invocations=agent_invocations)
    if not worker_ok:
        return _manual_review(
            summary="Worker provider evidence is insufficient for allow.",
            reasons=worker_reasons,
            results=results,
            missing=["worker_provider"],
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts,
            worker_provider=worker_provider,
            agent_invocations=agent_invocations,
        )

    residual_reasons = [
        reason
        for item in results
        for reason in item.get("reasons", [])
        if "residual risk" in str(reason).lower()
    ]
    primary_reasons = ["Snyk and Socket evidence passed.", *residual_reasons]
    summary = "Static dependency gates passed."
    if residual_reasons:
        summary = "Static dependency gates passed with residual risk noted."

    return SupervisorDecision(
        decision="allow",
        summary=summary,
        primary_reasons=primary_reasons,
        gate_results=results,
        agent_invocations=agent_invocations or [],
        next_actions=["Proceed only to the configured sandbox flow; never run malicious lifecycle scripts on host."],
        request_id=request_id,
        run_id=run_id,
        artifacts=artifacts or default_artifacts(),
        worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
    )
