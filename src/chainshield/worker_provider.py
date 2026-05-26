from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def redact_provider_text(text: str) -> str:
    redacted = re.sub(r"(Authorization:\s*Bearer\s+)\S+", r"\1[REDACTED]", text, flags=re.I)
    redacted = re.sub(r"(NVIDIA_API_KEY\s*=)\S+", r"\1[REDACTED]", redacted, flags=re.I)
    redacted = re.sub(r"(API[_-]?KEY\s*=)\S+", r"\1[REDACTED]", redacted, flags=re.I)
    return redacted


def build_agent_invocation(
    *,
    provider: str,
    model: str,
    status: str,
    request_id: str,
    run_id: str,
    errors: list[str] | None = None,
    observations: list[str] | None = None,
) -> dict[str, Any]:
    clean_errors = [redact_provider_text(error) for error in (errors or [])]
    return {
        "provider": provider,
        "model": model,
        "status": status,
        "request_id": request_id,
        "run_id": run_id,
        "finding_status": None if status in {"failed", "skipped"} else "inconclusive",
        "boundary_violation": False,
        "boundary_violation_reasons": [],
        "task_packet_path": "reports/worker-task-packet.json",
        "input_artifacts": [],
        "output_artifact_path": None,
        "observations": [redact_provider_text(item) for item in (observations or [])],
        "missing_evidence": [],
        "errors": clean_errors,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sanitized": True,
    }
