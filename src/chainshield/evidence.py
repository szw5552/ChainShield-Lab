from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import sanitize_text

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 5}
DENY_SEVERITIES = {"high", "critical"}
LOW_MEDIUM_SEVERITIES = {"low", "medium"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _max_risk(severities: list[str]) -> str:
    if not severities:
        return "none"
    return max(severities, key=lambda item: SEVERITY_ORDER.get(item, 0))


def gate_evidence(
    *,
    gate: str,
    status: str,
    run_id: str,
    source_kind: str = "fixture",
    source_path: str | None = None,
    command: str | None = None,
    exit_code: int | None = None,
    risk_level: str = "unknown",
    reasons: list[str] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    return {
        "gate": gate,
        "run_id": run_id,
        "status": status,
        "source_kind": source_kind,
        "source_path": source_path,
        "command": command,
        "exit_code": exit_code,
        "risk_level": risk_level,
        "reasons": reasons or [],
        "observed_at": observed_at or utc_now(),
        "sanitized": True,
    }


def _safe_parse_error(gate: str, path: str | Path, exc: Exception, *, run_id: str) -> dict[str, Any]:
    return gate_evidence(
        gate=gate,
        status="manual_review",
        run_id=run_id,
        source_path=str(path),
        risk_level="unknown",
        reasons=[f"parse_or_schema_error: could not parse sanitized {gate} report ({type(exc).__name__})"],
    )


def _load_json_report(path: str | Path) -> Any:
    raw = Path(path).read_text(encoding="utf-8")
    result = sanitize_text(raw)
    if not result.safe:
        raise ValueError("sanitizer rejected report: " + ", ".join(result.reasons))
    return json.loads(raw)


def _vulnerabilities(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities")
    if isinstance(vulns, list):
        return [item for item in vulns if isinstance(item, dict)]
    issues = data.get("issues")
    if isinstance(issues, list):
        return [item for item in issues if isinstance(item, dict)]
    return []


def _vuln_reason(item: dict[str, Any]) -> str:
    severity = str(item.get("severity", "unknown")).lower()
    package = item.get("packageName") or item.get("package") or item.get("name") or "unknown-package"
    title = item.get("title") or item.get("id") or "unnamed issue"
    return f"{severity} vulnerability in {package}: {title}"


def normalize_snyk_report_data(
    data: Any,
    *,
    source_path: str | None,
    run_id: str,
    source_kind: str = "fixture",
    command: str | None = None,
    exit_code: int | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        return gate_evidence(
            gate="snyk",
            status="manual_review",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code,
            risk_level="unknown",
            reasons=["parse_or_schema_error: Snyk report must be a JSON object"],
            observed_at=observed_at,
        )

    vulns = _vulnerabilities(data)
    severities = [str(item.get("severity", "unknown")).lower() for item in vulns]
    deny_vulns = [item for item in vulns if str(item.get("severity", "")).lower() in DENY_SEVERITIES]
    if deny_vulns:
        return gate_evidence(
            gate="snyk",
            status="deny",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code if exit_code is not None else 1,
            risk_level=_max_risk([str(item.get("severity", "unknown")).lower() for item in deny_vulns]),
            reasons=[_vuln_reason(item) for item in deny_vulns],
            observed_at=observed_at,
        )

    residual = [item for item in vulns if str(item.get("severity", "")).lower() in LOW_MEDIUM_SEVERITIES]
    if residual:
        reasons = ["residual risk retained after Snyk pass: " + _vuln_reason(item) for item in residual]
        return gate_evidence(
            gate="snyk",
            status="pass",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code if exit_code is not None else 0,
            risk_level=_max_risk(severities),
            reasons=reasons,
            observed_at=observed_at,
        )

    return gate_evidence(
        gate="snyk",
        status="pass",
        run_id=run_id,
        source_kind=source_kind,
        source_path=source_path,
        command=command,
        exit_code=exit_code if exit_code is not None else 0,
        risk_level="none",
        reasons=["Snyk report has no high or critical vulnerabilities."],
        observed_at=observed_at,
    )


def normalize_snyk_report(path: str | Path, *, run_id: str) -> dict[str, Any]:
    try:
        data = _load_json_report(path)
    except Exception as exc:  # report is fixture evidence; save only sanitized parse reason
        return _safe_parse_error("snyk", path, exc, run_id=run_id)
    return normalize_snyk_report_data(data, source_path=str(path), run_id=run_id)


def _socket_reasons(data: dict[str, Any]) -> tuple[list[str], str]:
    reasons: list[str] = []
    risk = "none"
    if data.get("healthy") is False:
        reasons.append("unhealthy dependency health reported by Socket")
        risk = "high"

    policy = data.get("policy") if isinstance(data.get("policy"), dict) else {}
    violations = policy.get("violations") if isinstance(policy, dict) else None
    if isinstance(violations, list) and violations:
        names = [str(item.get("name") or item.get("title") or "policy violation") for item in violations if isinstance(item, dict)]
        reasons.append("organization policy violation: " + "; ".join(names or ["policy violation"]))
        risk = _max_risk([risk, "high"])

    alerts = data.get("alerts") if isinstance(data.get("alerts"), list) else []
    for alert in [item for item in alerts if isinstance(item, dict)]:
        alert_type = str(alert.get("type") or alert.get("category") or "").lower()
        title = str(alert.get("title") or alert.get("name") or alert_type or "Socket alert")
        severity = str(alert.get("severity") or "high").lower()
        if "malware" in alert_type:
            reasons.append(f"malware risk: {title}")
            risk = _max_risk([risk, severity, "critical"])
        if "supply" in alert_type or "typosquat" in alert_type:
            reasons.append(f"supply-chain risk: {title}")
            risk = _max_risk([risk, severity, "high"])
    if data.get("supply_chain_risk") is True:
        reasons.append("supply-chain risk flag reported by Socket")
        risk = _max_risk([risk, "high"])
    return reasons, risk


def normalize_socket_report_data(
    data: Any,
    *,
    source_path: str | None,
    run_id: str,
    source_kind: str = "fixture",
    command: str | None = None,
    exit_code: int | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        return gate_evidence(
            gate="socket",
            status="manual_review",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code,
            risk_level="unknown",
            reasons=["parse_or_schema_error: Socket report must be a JSON object"],
            observed_at=observed_at,
        )
    reasons, risk = _socket_reasons(data)
    if reasons:
        return gate_evidence(
            gate="socket",
            status="deny",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code if exit_code is not None else 1,
            risk_level=risk,
            reasons=reasons,
            observed_at=observed_at,
        )
    return gate_evidence(
        gate="socket",
        status="pass",
        run_id=run_id,
        source_kind=source_kind,
        source_path=source_path,
        command=command,
        exit_code=exit_code if exit_code is not None else 0,
        risk_level="none",
        reasons=["Socket report has no unhealthy, policy, malware, or supply-chain risk findings."],
        observed_at=observed_at,
    )


def normalize_socket_report(path: str | Path, *, run_id: str) -> dict[str, Any]:
    try:
        data = _load_json_report(path)
    except Exception as exc:
        return _safe_parse_error("socket", path, exc, run_id=run_id)
    return normalize_socket_report_data(data, source_path=str(path), run_id=run_id)


def socket_evidence_from_classification(
    classification: str,
    *,
    exit_code: int | None,
    command: str | None,
    run_id: str,
    source_kind: str = "live",
    source_path: str | None = None,
) -> dict[str, Any]:
    if classification == "policy_failure":
        return gate_evidence(
            gate="socket",
            status="deny",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code,
            risk_level="high",
            reasons=["policy_failure: Socket CI policy/security/license failure"],
        )
    return gate_evidence(
        gate="socket",
        status="manual_review",
        run_id=run_id,
        source_kind=source_kind,
        source_path=source_path,
        command=command,
        exit_code=exit_code,
        risk_level="unknown",
        reasons=[f"{classification}: Socket live scanner did not provide usable pass/deny evidence"],
    )
