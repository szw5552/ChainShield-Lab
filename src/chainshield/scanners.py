from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .evidence import (
    gate_evidence,
    normalize_snyk_report,
    normalize_snyk_report_data,
    normalize_socket_report,
    normalize_socket_report_data,
)

LIVE_TIMEOUT_SECONDS = 120
LIVE_COMMANDS = {
    "snyk": ["snyk", "test", "--json"],
    "socket": ["socket", "ci", "--json"],
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _command_summary(command: list[str]) -> str:
    return " ".join(command)


def manual_review_evidence(
    *,
    gate: str,
    run_id: str,
    source_kind: str,
    source_path: str | None,
    command: str | None,
    exit_code: int | None,
    reasons: list[str],
) -> dict[str, Any]:
    return gate_evidence(
        gate=gate,
        status="manual_review",
        run_id=run_id,
        source_kind=source_kind,
        source_path=source_path,
        command=command,
        exit_code=exit_code,
        risk_level="unknown",
        reasons=reasons,
    )


def _classify_unavailable(stderr: str, exit_code: int | None) -> str:
    text = stderr.lower()
    if any(token in text for token in ("auth", "login", "unauthorized", "network", "dns", "tls", "timeout", "service")):
        return "auth_or_network_unavailable"
    if exit_code not in (None, 0):
        return "unknown_exit_code"
    return "parse_or_schema_error"


def _is_error_envelope(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "error" in data:
        return True
    errors = data.get("errors")
    return isinstance(errors, dict) or isinstance(errors, str)


def _has_report_shape(gate: str, data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if gate == "snyk":
        return any(key in data for key in ("ok", "vulnerabilities", "issues", "dependencyCount", "packageManager"))
    return any(key in data for key in ("healthy", "alerts", "policy", "supply_chain_risk"))


def _nonzero_pass_is_usable(gate: str, evidence: dict[str, Any]) -> bool:
    if gate == "snyk":
        return evidence.get("risk_level") in {"low", "medium"}
    return False


def _live_unavailable_from_json_error(
    *,
    gate: str,
    run_id: str,
    command: str,
    exit_code: int,
    started_at: str,
    ended_at: str,
    stderr: str,
    reason: str,
) -> dict[str, Any]:
    classification = _classify_unavailable(f"{stderr} {reason}", exit_code)
    return manual_review_evidence(
        gate=gate,
        run_id=run_id,
        source_kind="live",
        source_path=None,
        command=command,
        exit_code=exit_code,
        reasons=[f"live_unavailable: {classification}; {reason}; started_at={started_at}; ended_at={ended_at}"],
    )


def run_live_scanner(
    gate: str,
    command: list[str] | None = None,
    *,
    run_id: str,
    cwd: str | Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout_seconds: int = LIVE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    command = command or LIVE_COMMANDS[gate]
    summary = _command_summary(command)
    started_at = _utc_now()
    try:
        completed = runner(command, cwd=cwd, capture_output=True, text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        ended_at = _utc_now()
        return manual_review_evidence(
            gate=gate,
            run_id=run_id,
            source_kind="live",
            source_path=None,
            command=summary,
            exit_code=None,
            reasons=[f"timeout: live scanner exceeded {timeout_seconds} seconds; started_at={started_at}; ended_at={ended_at}"],
        )
    except FileNotFoundError:
        ended_at = _utc_now()
        return manual_review_evidence(
            gate=gate,
            run_id=run_id,
            source_kind="live",
            source_path=None,
            command=summary,
            exit_code=None,
            reasons=[f"live_unavailable: command not found; started_at={started_at}; ended_at={ended_at}"],
        )

    ended_at = _utc_now()
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        classification = _classify_unavailable(stderr, completed.returncode)
        return manual_review_evidence(
            gate=gate,
            run_id=run_id,
            source_kind="live",
            source_path=None,
            command=summary,
            exit_code=completed.returncode,
            reasons=[f"{classification}: live scanner output was not usable JSON; started_at={started_at}; ended_at={ended_at}"],
        )

    if completed.returncode not in (0, None) and not data:
        evidence = _live_unavailable_from_json_error(
            gate=gate,
            run_id=run_id,
            command=summary,
            exit_code=completed.returncode,
            started_at=started_at,
            ended_at=ended_at,
            stderr=stderr,
            reason="live scanner did not provide usable JSON data",
        )
    elif _is_error_envelope(data):
        reason = "live scanner returned JSON error envelope"
        classification_text = f"{stderr} {json.dumps(data, ensure_ascii=False, sort_keys=True)}"
        if completed.returncode not in (0, None):
            evidence = _live_unavailable_from_json_error(
                gate=gate,
                run_id=run_id,
                command=summary,
                exit_code=completed.returncode,
                started_at=started_at,
                ended_at=ended_at,
                stderr=classification_text,
                reason=reason,
            )
        else:
            evidence = manual_review_evidence(
                gate=gate,
                run_id=run_id,
                source_kind="live",
                source_path=None,
                command=summary,
                exit_code=completed.returncode,
                reasons=[f"parse_or_schema_error: {reason}; started_at={started_at}; ended_at={ended_at}"],
            )
    elif not _has_report_shape(gate, data):
        reason = "live scanner JSON did not match a recognized report shape"
        if completed.returncode not in (0, None):
            evidence = _live_unavailable_from_json_error(
                gate=gate,
                run_id=run_id,
                command=summary,
                exit_code=completed.returncode,
                started_at=started_at,
                ended_at=ended_at,
                stderr=stderr,
                reason=reason,
            )
        else:
            evidence = manual_review_evidence(
                gate=gate,
                run_id=run_id,
                source_kind="live",
                source_path=None,
                command=summary,
                exit_code=completed.returncode,
                reasons=[f"parse_or_schema_error: {reason}; started_at={started_at}; ended_at={ended_at}"],
            )
    elif gate == "snyk":
        evidence = normalize_snyk_report_data(
            data,
            source_path=None,
            run_id=run_id,
            source_kind="live",
            command=summary,
            exit_code=completed.returncode,
            observed_at=ended_at,
        )
    else:
        evidence = normalize_socket_report_data(
            data,
            source_path=None,
            run_id=run_id,
            source_kind="live",
            command=summary,
            exit_code=completed.returncode,
            observed_at=ended_at,
        )
    if completed.returncode not in (0, None) and evidence.get("status") == "pass" and not _nonzero_pass_is_usable(gate, evidence):
        evidence = _live_unavailable_from_json_error(
            gate=gate,
            run_id=run_id,
            command=summary,
            exit_code=completed.returncode,
            started_at=started_at,
            ended_at=ended_at,
            stderr=stderr,
            reason="live scanner exited non-zero without deny findings",
        )
    evidence["reasons"].append(f"live scanner timing: started_at={started_at}; ended_at={ended_at}")
    return evidence


def _fixture_path(fixtures: dict[str, str | None], gate: str) -> str | None:
    return fixtures.get(f"{gate}_report")


def _load_fixture(gate: str, path: str, run_id: str) -> dict[str, Any]:
    if gate == "snyk":
        return normalize_snyk_report(path, run_id=run_id)
    return normalize_socket_report(path, run_id=run_id)


def _with_live_unavailable(fixture_evidence: dict[str, Any], live_evidence: dict[str, Any]) -> dict[str, Any]:
    merged = dict(fixture_evidence)
    merged["reasons"] = ["live_unavailable fallback used fixture evidence"] + list(live_evidence.get("reasons", [])) + list(
        fixture_evidence.get("reasons", [])
    )
    return merged


def run_scanners(
    config: Any | None = None,
    *,
    scanner_mode: dict[str, str] | None = None,
    fixtures: dict[str, str | None] | None = None,
    run_id: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[dict[str, Any]]:
    if config is not None:
        scanner_mode = config.scanner_mode
        fixtures = config.fixtures
        run_id = run_id or getattr(config, "run_id", None) or "run-us1"
    scanner_mode = scanner_mode or {"snyk": "fixture", "socket": "fixture"}
    fixtures = fixtures or {}
    run_id = run_id or "run-us1"
    live_cwd = fixtures.get("poc_app")

    results: list[dict[str, Any]] = []
    for gate in ("snyk", "socket"):
        mode = scanner_mode.get(gate, "skip")
        path = _fixture_path(fixtures, gate)
        if mode == "skip":
            continue
        if mode == "fixture":
            if path is None:
                results.append(
                    manual_review_evidence(
                        gate=gate,
                        run_id=run_id,
                        source_kind="fixture",
                        source_path=None,
                        command=None,
                        exit_code=None,
                        reasons=[f"missing {gate} fixture report"],
                    )
                )
            else:
                results.append(_load_fixture(gate, path, run_id))
            continue

        live_evidence = run_live_scanner(gate, run_id=run_id, cwd=live_cwd, runner=runner)
        if live_evidence["status"] == "manual_review" and any("live_unavailable" in reason for reason in live_evidence["reasons"]):
            if path:
                results.append(_with_live_unavailable(_load_fixture(gate, path, run_id), live_evidence))
            else:
                results.append(live_evidence)
        else:
            results.append(live_evidence)
    return results
