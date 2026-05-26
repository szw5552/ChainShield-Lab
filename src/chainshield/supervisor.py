from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .config import WorkerProviderConfig

STATIC_GATES = ("snyk", "socket")


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


def decide_static_gates(
    gate_results: Iterable[GateEvidence | dict[str, Any]],
    *,
    scanner_mode: dict[str, str] | None = None,
    sandbox_demo_override: bool = False,
    request_id: str = "REQ-foundation",
    run_id: str = "run-foundation",
    artifacts: dict[str, Any] | None = None,
    worker_provider: WorkerProviderConfig | None = None,
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
            next_actions=next_actions,
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts or default_artifacts(),
            worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
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

    if missing:
        return SupervisorDecision(
            decision="manual_review",
            summary="Static dependency gate requires manual review.",
            primary_reasons=reasons or ["missing static gate evidence"],
            gate_results=results,
            missing_gates=missing,
            next_actions=["Provide sanitized Snyk and Socket evidence before allowing install."],
            request_id=request_id,
            run_id=run_id,
            artifacts=artifacts or default_artifacts(),
            worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
        )

    return SupervisorDecision(
        decision="allow",
        summary="Static dependency gates passed.",
        primary_reasons=["Snyk and Socket evidence passed."],
        gate_results=results,
        next_actions=["Proceed only to the configured sandbox flow; never run malicious lifecycle scripts on host."],
        request_id=request_id,
        run_id=run_id,
        artifacts=artifacts or default_artifacts(),
        worker_provider=(worker_provider or WorkerProviderConfig()).to_decision_metadata(),
    )
