from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import sanitize_text

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 5}
DENY_SEVERITIES = {"high", "critical"}
LOW_MEDIUM_SEVERITIES = {"low", "medium"}


class ReportSanitizationError(ValueError):
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("sanitizer rejected report: " + ", ".join(reasons))


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
    if isinstance(exc, ReportSanitizationError):
        reasons = ["sanitizer rejected report: " + reason for reason in exc.reasons]
    else:
        reasons = [f"parse_or_schema_error: could not parse sanitized {gate} report ({type(exc).__name__})"]
    return gate_evidence(
        gate=gate,
        status="manual_review",
        run_id=run_id,
        source_path=str(path),
        risk_level="unknown",
        reasons=reasons,
    )


def _load_json_report(path: str | Path) -> Any:
    raw = Path(path).read_text(encoding="utf-8")
    result = sanitize_text(raw)
    if not result.safe:
        raise ReportSanitizationError(result.reasons)
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


REQUIRED_OPENSHELL_EVENTS = {
    "filesystem_read": "file read block",
    "network_egress": "egress block",
}

OCSF_NET_DENY_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+OCSF\s+NET:OPEN\s+\[(?P<severity>[A-Z]+)\]\s+DENIED\s+"
    r"(?P<binary>\S+)\(\d+\)\s+->\s+(?P<host>[^:\s]+):(?P<port>\d+)\s+\[policy:(?P<policy>[^\]]*)",
    re.IGNORECASE,
)
OCSF_FILE_DENY_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+OCSF\s+FILE:[A-Z_]+\s+\[(?P<severity>[A-Z]+)\]\s+DENIED\s+"
    r"(?P<path>\S+).*\[policy:(?P<policy>[^\]]*)",
    re.IGNORECASE,
)


def _parse_openshell_event(line: str, *, source_path: str | None, source_kind: str) -> dict[str, Any] | None:
    stripped = line.strip()
    if not stripped:
        return None
    ocsf_net = OCSF_NET_DENY_RE.match(stripped)
    if ocsf_net:
        host = ocsf_net.group("host")
        port = ocsf_net.group("port")
        policy = (ocsf_net.group("policy") or "").strip() or "opa.denied"
        scheme = "https" if port == "443" else "tcp"
        return {
            "event_type": "network_egress",
            "blocked_path": None,
            "blocked_target": f"{scheme}://{host}" if port == "443" else f"{host}:{port}",
            "policy_rule_id": policy,
            "result": "blocked",
            "timestamp": ocsf_net.group("timestamp"),
            "artifact_path": str(source_path or ""),
            "source_kind": source_kind,
            "sanitized": True,
        }
    ocsf_file = OCSF_FILE_DENY_RE.match(stripped)
    if ocsf_file:
        policy = (ocsf_file.group("policy") or "").strip() or "landlock.denied"
        return {
            "event_type": "filesystem_read",
            "blocked_path": ocsf_file.group("path"),
            "blocked_target": None,
            "policy_rule_id": policy,
            "result": "blocked",
            "timestamp": ocsf_file.group("timestamp"),
            "artifact_path": str(source_path or ""),
            "source_kind": source_kind,
            "sanitized": True,
        }
    if not stripped.startswith("{"):
        return None
    data = json.loads(stripped)
    if not isinstance(data, dict):
        raise ValueError("OpenShell event must be a JSON object")
    event_type = str(data.get("event_type") or data.get("type") or "")
    result = str(data.get("result") or "").lower()
    blocked_path = data.get("blocked_path")
    blocked_target = data.get("blocked_target")
    event = {
        "event_type": event_type,
        "blocked_path": blocked_path,
        "blocked_target": blocked_target,
        "policy_rule_id": str(data.get("policy_rule_id") or data.get("rule") or ""),
        "result": result,
        "timestamp": str(data.get("timestamp") or utc_now()),
        "artifact_path": str(data.get("artifact_path") or source_path or ""),
        "source_kind": str(data.get("source_kind") or source_kind),
        "sanitized": bool(data.get("sanitized", False)),
    }
    if not event["policy_rule_id"]:
        raise ValueError("OpenShell event missing policy_rule_id")
    if event["source_kind"] not in {"live", "fixture"}:
        raise ValueError("OpenShell event source_kind must be live or fixture")
    if result != "blocked":
        raise ValueError("OpenShell event result must be blocked")
    if event_type == "filesystem_read" and not blocked_path:
        raise ValueError("OpenShell filesystem event missing blocked_path")
    if event_type == "network_egress" and not blocked_target:
        raise ValueError("OpenShell network event missing blocked_target")
    if event["sanitized"] is not True:
        raise ValueError("OpenShell event must be sanitized")
    return event


def normalize_openshell_log_data(
    raw_log: str,
    *,
    source_path: str | None,
    run_id: str,
    source_kind: str = "fixture",
    command: str | None = None,
    exit_code: int | None = 0,
    observed_at: str | None = None,
) -> dict[str, Any]:
    result = sanitize_text(raw_log)
    if not result.safe:
        return gate_evidence(
            gate="openshell",
            status="manual_review",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code,
            risk_level="unknown",
            reasons=["sanitizer rejected OpenShell log: " + ", ".join(result.reasons)],
            observed_at=observed_at,
        )

    events: list[dict[str, Any]] = []
    parse_errors: list[str] = []
    for line in raw_log.splitlines():
        try:
            event = _parse_openshell_event(line, source_path=source_path, source_kind=source_kind)
        except (json.JSONDecodeError, ValueError) as exc:
            parse_errors.append(f"parse_or_schema_error: {type(exc).__name__}")
            continue
        if event is not None and event["event_type"] in REQUIRED_OPENSHELL_EVENTS:
            events.append(event)

    present = {event["event_type"] for event in events}
    missing = [label for event_type, label in REQUIRED_OPENSHELL_EVENTS.items() if event_type not in present]
    if parse_errors or missing:
        reasons = parse_errors + [f"missing containment evidence: {item}" for item in missing]
        evidence = gate_evidence(
            gate="openshell",
            status="manual_review",
            run_id=run_id,
            source_kind=source_kind,
            source_path=source_path,
            command=command,
            exit_code=exit_code,
            risk_level="unknown",
            reasons=reasons,
            observed_at=observed_at,
        )
        evidence["containment_events"] = events
        return evidence

    evidence = gate_evidence(
        gate="openshell",
        status="pass",
        run_id=run_id,
        source_kind=source_kind,
        source_path=source_path,
        command=command,
        exit_code=exit_code,
        risk_level="none",
        reasons=["OpenShell file read block evidence present.", "OpenShell egress block evidence present."],
        observed_at=observed_at,
    )
    evidence["containment_events"] = events
    return evidence


def normalize_openshell_log(path: str | Path, *, run_id: str, source_kind: str = "fixture") -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return gate_evidence(
            gate="openshell",
            status="manual_review",
            run_id=run_id,
            source_kind=source_kind,
            source_path=str(path),
            risk_level="unknown",
            reasons=[f"missing OpenShell evidence log: {type(exc).__name__}"],
        )
    return normalize_openshell_log_data(raw, source_path=str(path), run_id=run_id, source_kind=source_kind)
