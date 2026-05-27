from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .evidence import gate_evidence, normalize_openshell_log, normalize_openshell_log_data

LIVE_SANDBOX_TIMEOUT_SECONDS = 300
MANUAL_SANDBOX_VERIFICATION_PATH = "specs/001-orbstack-sandbox-gates/quickstart.md#manual-sandbox-verification"
DEFAULT_OPENSHELL_POLICY = "policies/openshell-npm-install.yaml"
SAFE_ENV_KEYS = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_sandbox_env(canary_path: str) -> dict[str, str]:
    safe_env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_KEYS and value}
    safe_env.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
    safe_env["CHAINSHIELD_CANARY_PATH"] = str(Path(canary_path))
    return safe_env


@dataclass(frozen=True)
class SandboxReadiness:
    status: str
    reasons: list[str] = field(default_factory=list)
    runtime: str | None = None
    openshell_available: bool = False
    host_fallback_attempted: bool = False
    unauthorized_runtime_attempted: bool = False
    fixture_evidence_path: str | None = None
    manual_verification_path: str = MANUAL_SANDBOX_VERIFICATION_PATH

    @property
    def ready(self) -> bool:
        return self.status == "pass"


def manual_observation_evidence(*, run_id: str, reasons: list[str], source_path: str | None = None) -> dict[str, Any]:
    return gate_evidence(
        gate="openshell",
        status="manual_review",
        run_id=run_id,
        source_kind="manual_observation",
        source_path=source_path,
        command=None,
        exit_code=None,
        risk_level="unknown",
        reasons=reasons + ["manual observation is explanatory only and cannot satisfy allow."],
    )


def _completed_text(completed: Any) -> str:
    return f"{getattr(completed, 'stdout', '')}\n{getattr(completed, 'stderr', '')}"


def check_sandbox_readiness(
    *,
    run_id: str,
    runner: Callable[..., Any] = subprocess.run,
    fixture_evidence_path: str | None = None,
) -> SandboxReadiness:
    reasons: list[str] = []
    try:
        docker_info = runner(["docker", "info", "--format", "{{.OperatingSystem}}"], capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        reasons.append("OrbStack unavailable; docker info could not confirm the OrbStack runtime.")
        reasons.append("Host fallback is prohibited for the malicious npm lifecycle demo.")
        return SandboxReadiness(
            status="manual_review",
            reasons=reasons,
            fixture_evidence_path=fixture_evidence_path,
        )

    runtime_text = _completed_text(docker_info)
    if "orbstack" not in runtime_text.lower():
        reasons.append("OrbStack unavailable; general Docker runtime is not authorized by this spec.")
        reasons.append("Host fallback is prohibited for the malicious npm lifecycle demo.")
        return SandboxReadiness(
            status="manual_review",
            reasons=reasons,
            runtime=runtime_text.strip() or "unknown",
            fixture_evidence_path=fixture_evidence_path,
        )

    try:
        openshell_version = runner(["openshell", "--version"], capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        reasons.append("OpenShell unavailable; containment policy cannot be verified live.")
        reasons.append("Use the sanitized fixture evidence path or the manual verification path before reviewing.")
        return SandboxReadiness(
            status="manual_review",
            reasons=reasons,
            runtime="OrbStack",
            fixture_evidence_path=fixture_evidence_path,
        )

    if getattr(openshell_version, "returncode", 0) not in (0, None):
        reasons.append("OpenShell unavailable; version command returned a non-zero exit status.")
        return SandboxReadiness(
            status="manual_review",
            reasons=reasons,
            runtime="OrbStack",
            fixture_evidence_path=fixture_evidence_path,
        )

    return SandboxReadiness(
        status="pass",
        reasons=["OrbStack runtime and OpenShell CLI are available; host fallback remains prohibited."],
        runtime="OrbStack",
        openshell_available=True,
        fixture_evidence_path=fixture_evidence_path,
    )


def readiness_failure_evidence(readiness: SandboxReadiness, *, run_id: str) -> dict[str, Any]:
    source_path = readiness.fixture_evidence_path or readiness.manual_verification_path
    return gate_evidence(
        gate="openshell",
        status="manual_review",
        run_id=run_id,
        source_kind="manual_observation",
        source_path=source_path,
        command=None,
        exit_code=None,
        risk_level="unknown",
        reasons=list(readiness.reasons)
        + [
            f"readiness status={readiness.status}",
            f"manual verification path={readiness.manual_verification_path}",
            "host fallback prohibited",
        ],
    )


def run_live_sandbox_install(
    *,
    poc_app_path: str,
    policy_path: str,
    canary_path: str,
    run_id: str,
    readiness: SandboxReadiness,
    runner: Callable[..., Any] = subprocess.run,
    timeout_seconds: int = LIVE_SANDBOX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not readiness.ready:
        return readiness_failure_evidence(readiness, run_id=run_id)

    started_at = _utc_now()
    command = [
        "openshell",
        "run",
        "--policy",
        policy_path,
        "--",
        "npm",
        "install",
        "--ignore-scripts=false",
    ]
    try:
        completed = runner(
            command,
            cwd=poc_app_path,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=build_sandbox_env(canary_path),
        )
    except subprocess.TimeoutExpired:
        ended_at = _utc_now()
        return gate_evidence(
            gate="openshell",
            status="manual_review",
            run_id=run_id,
            source_kind="live",
            source_path=None,
            command="openshell run --policy [policy] -- npm install --ignore-scripts=false",
            exit_code=None,
            risk_level="unknown",
            reasons=[
                f"timeout: live sandbox install exceeded {timeout_seconds} seconds; started_at={started_at}; ended_at={ended_at}",
                f"readiness status={readiness.status}",
                "containment evidence status=missing",
                "host fallback prohibited",
            ],
            observed_at=ended_at,
        )

    ended_at = _utc_now()
    raw_log = f"{getattr(completed, 'stdout', '')}\n{getattr(completed, 'stderr', '')}"
    evidence = normalize_openshell_log_data(
        raw_log,
        source_path=None,
        run_id=run_id,
        source_kind="live",
        command="openshell run --policy [policy] -- npm install --ignore-scripts=false",
        exit_code=getattr(completed, "returncode", None),
        observed_at=ended_at,
    )
    evidence["reasons"].append(f"live sandbox timing: started_at={started_at}; ended_at={ended_at}")
    evidence["reasons"].append("host fallback prohibited")
    return evidence


def run_sandbox(config: Any, *, run_id: str, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any] | None:
    sandbox_mode = getattr(config, "sandbox_mode", config.raw.get("sandbox_mode", "disabled"))
    fixtures = config.fixtures
    openshell_log = fixtures.get("openshell_log")
    if sandbox_mode == "disabled":
        return None
    if sandbox_mode == "fixture":
        if not openshell_log:
            return gate_evidence(
                gate="openshell",
                status="manual_review",
                run_id=run_id,
                source_kind="fixture",
                source_path=None,
                risk_level="unknown",
                reasons=["missing OpenShell fixture evidence log"],
            )
        return normalize_openshell_log(openshell_log, run_id=run_id, source_kind="fixture")
    if sandbox_mode == "live":
        readiness = check_sandbox_readiness(run_id=run_id, runner=runner, fixture_evidence_path=openshell_log)
        policy_path = fixtures.get("openshell_policy") or DEFAULT_OPENSHELL_POLICY
        return run_live_sandbox_install(
            poc_app_path=fixtures["poc_app"],
            policy_path=policy_path,
            canary_path=fixtures.get("canary_secret") or "fixtures/canary/canary-secret.txt",
            run_id=run_id,
            readiness=readiness,
            runner=runner,
        )
    return gate_evidence(
        gate="openshell",
        status="manual_review",
        run_id=run_id,
        source_kind="manual_observation",
        source_path=None,
        risk_level="unknown",
        reasons=[f"unsupported sandbox mode: {sandbox_mode}"],
    )
