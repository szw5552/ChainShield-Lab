from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SanitizeResult:
    safe: bool
    reasons: list[str]
    stop_execution: bool = False


class ArtifactWriteError(RuntimeError):
    pass


SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(Authorization:\s*Bearer\s+(?!\[REDACTED\]\b)\S+|"
            r"['\"]?(?:NVIDIA_)?API[_-]?KEY['\"]?\s*[:=]\s*['\"]?(?!\[REDACTED\]['\"]?)[^\s,'\"]+|"
            r"['\"]?TOKEN['\"]?\s*[:=]\s*['\"]?(?!\[REDACTED\]['\"]?)[^\s,'\"]+|"
            r"\bsk-[A-Za-z0-9_-]{16,})",
            re.I,
        ),
        "token/API key",
    ),
    (re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----"), "SSH private key"),
    (re.compile(r"aws_access_key_id\s*=|aws_secret_access_key\s*=|\[profile [^\]]+\]", re.I), "cloud profile"),
    (re.compile(r"/(?:Users|home)/[^\s/]+/\.env\b|\.env\s+contains", re.I), "personal .env"),
    (re.compile(r"raw (?:scanner|sandbox) log|npm ERR! stack", re.I), "raw scanner/sandbox log"),
    (re.compile(r"/(?:Users|home)/[^\s]+/(?:\.ssh|\.aws|\.config/gcloud)", re.I), "unmasked host-sensitive path"),
]


def sanitize_text(text: str) -> SanitizeResult:
    reasons: list[str] = []
    for pattern, reason in SENSITIVE_PATTERNS:
        if pattern.search(text) and reason not in reasons:
            reasons.append(reason)
    return SanitizeResult(safe=not reasons, reasons=reasons, stop_execution=bool(reasons))


def redact_text(text: str) -> str:
    redacted = re.sub(r"(Authorization:\s*Bearer\s+)\S+", r"\1[REDACTED]", text, flags=re.I)
    redacted = re.sub(
        r"((?:['\"]?(?:NVIDIA_)?API[_-]?KEY['\"]?\s*[:=]\s*['\"]?))[^\s,'\"]+",
        r"\1[REDACTED]",
        redacted,
        flags=re.I,
    )
    redacted = re.sub(
        r"((?:['\"]?TOKEN['\"]?\s*[:=]\s*['\"]?))[^\s,'\"]+",
        r"\1[REDACTED]",
        redacted,
        flags=re.I,
    )
    redacted = re.sub(r"\bsk-[A-Za-z0-9_-]{16,}", "[REDACTED]", redacted)
    return redacted


def build_sanitized_failure_artifact(gate: str, result: SanitizeResult, *, run_id: str) -> dict[str, Any]:
    return {
        "gate": gate,
        "run_id": run_id,
        "status": "manual_review",
        "source_kind": "manual_observation",
        "source_path": None,
        "command": None,
        "exit_code": None,
        "risk_level": "unknown",
        "reasons": [f"sanitizer rejected artifact: {reason}" for reason in result.reasons],
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sanitized": True,
    }


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(tmp, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def write_json_artifact(path: str | Path, payload: Any) -> None:
    target = Path(path)
    if target.exists():
        raise ArtifactWriteError(f"artifact already exists: {target}")
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    result = sanitize_text(text)
    if not result.safe:
        raise ArtifactWriteError("refusing to save unsanitized artifact: " + ", ".join(result.reasons))
    atomic_write_text(target, text + "\n")


def _artifact_list_line(label: str, items: list[str] | None) -> str:
    if not items:
        return f"- {label}: none"
    return f"- {label}: " + ", ".join(f"`{item}`" for item in items)


def render_markdown_summary(decision: dict[str, Any]) -> str:
    missing = decision.get("missing_gates") or ["none"]
    next_actions = decision.get("next_actions") or ["No next action recorded."]
    reasons = decision.get("primary_reasons") or ["No primary reason recorded."]
    artifacts = decision.get("artifacts") or {}
    lines = [
        f"# ChainShield Decision: {decision['decision']}",
        "",
        f"Result: `{decision['decision']}`",
        "Primary reasons: " + "; ".join(reasons),
        "Missing gates: " + ", ".join(missing),
        "Next actions: " + "; ".join(next_actions),
        "",
        "## Gate Evidence",
    ]
    for item in decision.get("gate_results", []):
        source = item.get("source_path") or "none"
        lines.append(f"- {item.get('gate')}: {item.get('status')} ({item.get('risk_level')}) from `{source}`")
        for reason in item.get("reasons", []):
            lines.append(f"  - {reason}")

    lines.extend(["", "## Agent Invocations"])
    invocations = decision.get("agent_invocations", [])
    if invocations:
        for item in invocations:
            lines.append(
                f"- {item.get('provider')}: {item.get('status')} finding={item.get('finding_status')} "
                f"boundary_violation={item.get('boundary_violation')}"
            )
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Artifacts",
            f"- Decision JSON: `{artifacts.get('decision_json')}`",
            f"- Markdown summary: `{artifacts.get('markdown_summary')}`",
            _artifact_list_line("Reports", artifacts.get("reports")),
            _artifact_list_line("Logs", artifacts.get("logs")),
            _artifact_list_line("Worker", artifacts.get("worker")),
            "",
            "## Scope Disclaimer",
            "Demo-only npm supply-chain defense PoC; not a production CI/CD rollout, SOC/SIEM integration, or general malware-analysis framework.",
        ]
    )
    return "\n".join(lines) + "\n"
