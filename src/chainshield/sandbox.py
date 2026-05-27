from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .artifacts import ArtifactWriteError, atomic_write_text, redact_text, sanitize_text
from .evidence import gate_evidence, normalize_openshell_log, normalize_openshell_log_data
from .schemas import REPO_ROOT

LIVE_SANDBOX_TIMEOUT_SECONDS = 300
MANUAL_SANDBOX_VERIFICATION_PATH = "specs/001-orbstack-sandbox-gates/quickstart.md#manual-sandbox-verification"
DEFAULT_OPENSHELL_POLICY = "policies/openshell-npm-install.yaml"
SAFE_ENV_KEYS = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE"}
SANDBOX_BUNDLE_ROOT = "/tmp/chainshield-bundle"
SANDBOX_FIXTURES_ROOT = f"{SANDBOX_BUNDLE_ROOT}/chainshield-fixtures"
SANDBOX_POC_APP_PATH = f"{SANDBOX_FIXTURES_ROOT}/poc-app"
SANDBOX_MALICIOUS_PACKAGE_PATH = f"{SANDBOX_FIXTURES_ROOT}/malicious-poc-pkg"
SANDBOX_CANARY_ROOT = f"{SANDBOX_BUNDLE_ROOT}/chainshield-canary"
SANDBOX_CANARY_PATH = f"{SANDBOX_CANARY_ROOT}/canary-secret.txt"
SANDBOX_PROBE_ENV = "CHAINSHIELD_SANDBOX_PROBE"
SANDBOX_PROBE_COMMAND = (
    "openshell sandbox create --name [sandbox] --policy [policy] "
    "--upload [fixtures_root] -- "
    "sh -lc 'pwd; ls -la /tmp; ls -la /tmp/chainshield-bundle; ls -la /tmp/chainshield-bundle/chainshield-fixtures; "
    "ls -la /tmp/chainshield-bundle/chainshield-canary; "
    "find /tmp/chainshield-bundle -maxdepth 4 -type d | sort; "
    "find /tmp/chainshield-bundle/chainshield-canary -maxdepth 2 -type f | sort'"
)
LIVE_SANDBOX_COMMAND = (
    "openshell sandbox create --name [sandbox] --policy [policy] "
    "--upload [fixtures_root] -- "
    "sh -lc 'cd /tmp/chainshield-bundle/chainshield-fixtures/poc-app && "
    "chmod 000 /tmp/chainshield-bundle/chainshield-canary/canary-secret.txt && "
    "CHAINSHIELD_CANARY_PATH=/tmp/chainshield-bundle/chainshield-canary/canary-secret.txt "
    "npm install --ignore-scripts=false --install-links'"
)
LIVE_SANDBOX_LOG_DIR = "reports/sandbox"
UPLOAD_STAGING_PREFIX = "chainshield-openshell-upload-"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sandbox_name(run_id: str) -> str:
    collapsed = re.sub(r"[^a-zA-Z0-9-]+", "-", run_id).strip("-").lower() or "chainshield-demo"
    return f"chainshield-{collapsed}"[:63]


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


def _timeout_text(exc: subprocess.TimeoutExpired) -> str:
    stdout = getattr(exc, "stdout", None)
    if stdout is None:
        stdout = getattr(exc, "output", None)
    stderr = getattr(exc, "stderr", None)
    return f"{stdout or ''}\n{stderr or ''}"


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


def _build_live_install_command(
    *,
    sandbox_name: str,
    policy_path: str,
    probe_only: bool = False,
) -> list[str]:
    command = [
        "openshell",
        "sandbox",
        "create",
        "--name",
        sandbox_name,
        "--policy",
        policy_path,
        "--upload",
        f"{SANDBOX_FIXTURES_ROOT}:/tmp",
    ]
    command.extend(
        [
            "--no-tty",
            "--",
            "sh",
            "-lc",
            _probe_shell_script() if probe_only else _live_install_shell_script(),
        ]
    )
    return command


def _live_install_shell_script() -> str:
    return (
        f"chmod 000 {shlex.quote(SANDBOX_CANARY_PATH)} && "
        f"cd {shlex.quote(SANDBOX_POC_APP_PATH)} && "
        f"CHAINSHIELD_CANARY_PATH={shlex.quote(SANDBOX_CANARY_PATH)} "
        "npm install --ignore-scripts=false --install-links"
    )


def _probe_shell_script() -> str:
    return (
        "pwd; "
        "ls -la /tmp; "
        f"ls -la {shlex.quote(SANDBOX_BUNDLE_ROOT)}; "
        f"ls -la {shlex.quote(SANDBOX_FIXTURES_ROOT)}; "
        f"ls -la {shlex.quote(SANDBOX_CANARY_ROOT)}; "
        f"find {shlex.quote(SANDBOX_BUNDLE_ROOT)} -maxdepth 4 -type d | sort; "
        f"find {shlex.quote(SANDBOX_CANARY_ROOT)} -maxdepth 2 -type f | sort"
    )


def _probe_mode_enabled() -> bool:
    return os.environ.get(SANDBOX_PROBE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def _copy_path(source: str, destination: Path) -> None:
    source_path = Path(source)
    if source_path.is_dir():
        shutil.copytree(source_path, destination)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination)


def _prepare_upload_bundle(
    *,
    poc_app_path: str,
    malicious_package_path: str | None,
    canary_path: str,
) -> tempfile.TemporaryDirectory[str]:
    bundle_dir = tempfile.TemporaryDirectory(prefix=UPLOAD_STAGING_PREFIX)
    bundle_root = Path(bundle_dir.name) / "chainshield-bundle"
    _copy_path(poc_app_path, bundle_root / "chainshield-fixtures" / "poc-app")
    if malicious_package_path:
        _copy_path(malicious_package_path, bundle_root / "chainshield-fixtures" / "malicious-poc-pkg")
    _copy_path(canary_path, bundle_root / "chainshield-canary" / "canary-secret.txt")
    return bundle_dir


def _fetch_sandbox_logs(
    sandbox_name: str,
    *,
    runner: Callable[..., Any],
    timeout_seconds: int,
) -> tuple[str, str | None]:
    logs: list[str] = []
    errors: list[str] = []

    stream_command = [
        "openshell",
        "logs",
        sandbox_name,
        "--source",
        "sandbox",
        "--source",
        "gateway",
        "--level",
        "debug",
    ]
    try:
        completed = runner(
            stream_command,
            capture_output=True,
            text=True,
            timeout=min(timeout_seconds, 30),
            check=False,
        )
        stream_text = _completed_text(completed)
        if stream_text.strip():
            logs.append(stream_text)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"sandbox stream log collection failed: {type(exc).__name__}")

    file_command = [
        "openshell",
        "sandbox",
        "exec",
        "--name",
        sandbox_name,
        "--no-tty",
        "--",
        "sh",
        "-lc",
        'for f in /var/log/openshell*.log /var/log/openshell-ocsf*.log; do [ -f "$f" ] && cat "$f"; done',
    ]
    try:
        completed = runner(
            file_command,
            capture_output=True,
            text=True,
            timeout=min(timeout_seconds, 30),
            check=False,
        )
        file_text = _completed_text(completed)
        if file_text.strip():
            logs.append(file_text)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"sandbox file log collection failed: {type(exc).__name__}")

    combined = "\n".join(part for part in logs if part.strip())
    return combined, "; ".join(errors) if errors else None


def _probe_canary_read(
    sandbox_name: str,
    *,
    runner: Callable[..., Any],
    timeout_seconds: int,
) -> tuple[str, dict[str, Any] | None, str | None]:
    command = [
        "openshell",
        "sandbox",
        "exec",
        "--name",
        sandbox_name,
        "--no-tty",
        "--",
        "sh",
        "-lc",
        f"cat {shlex.quote(SANDBOX_CANARY_PATH)}",
    ]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=min(timeout_seconds, 30),
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return "", None, f"canary read probe failed: {type(exc).__name__}"

    text = _completed_text(completed)
    lowered = text.lower()
    if getattr(completed, "returncode", 0) not in (0, None) and (
        "permission denied" in lowered or "operation not permitted" in lowered or "eacces" in lowered
    ):
        event = {
            "event_type": "filesystem_read",
            "blocked_path": SANDBOX_CANARY_PATH,
            "blocked_target": None,
            "policy_rule_id": "manual_probe.permission_denied",
            "result": "blocked",
            "timestamp": _utc_now(),
            "artifact_path": "",
            "source_kind": "live",
            "sanitized": True,
        }
        return text, event, None
    if getattr(completed, "returncode", 0) == 0:
        return "[canary read probe succeeded; stdout redacted]\n", None, "canary read probe unexpectedly succeeded; filesystem deny not observed"
    return text, None, "canary read probe completed without a permission-denied signal"


def _delete_sandbox(sandbox_name: str, *, runner: Callable[..., Any]) -> None:
    try:
        runner(
            ["openshell", "sandbox", "delete", sandbox_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return


def _timeout_log_path(run_id: str) -> Path:
    safe_run_id = re.sub(r"[^0-9A-Za-z_.-]+", "-", run_id).strip("-") or "run"
    return REPO_ROOT / LIVE_SANDBOX_LOG_DIR / f"openshell-timeout-{safe_run_id}.log"


def _live_log_path(run_id: str) -> Path:
    safe_run_id = re.sub(r"[^0-9A-Za-z_.-]+", "-", run_id).strip("-") or "run"
    return REPO_ROOT / LIVE_SANDBOX_LOG_DIR / f"openshell-live-{safe_run_id}.log"


def _probe_log_path(run_id: str) -> Path:
    safe_run_id = re.sub(r"[^0-9A-Za-z_.-]+", "-", run_id).strip("-") or "run"
    return REPO_ROOT / LIVE_SANDBOX_LOG_DIR / f"openshell-probe-{safe_run_id}.log"


def _write_live_log_artifact(
    raw_log: str,
    *,
    run_id: str,
    path_builder: Callable[[str], Path] = _timeout_log_path,
) -> tuple[str | None, str | None]:
    if not raw_log.strip():
        return None, "sandbox log artifact skipped: no live log content captured"
    target = path_builder(run_id)
    text = redact_text(raw_log)
    result = sanitize_text(text)
    if not result.safe:
        return None, "sandbox log artifact skipped: " + ", ".join(result.reasons)
    try:
        atomic_write_text(target, text if text.endswith("\n") else text + "\n")
    except (ArtifactWriteError, OSError) as exc:
        return None, f"sandbox log artifact write failed: {type(exc).__name__}"
    return str(target.relative_to(REPO_ROOT)), None


def _probe_evidence(
    *,
    run_id: str,
    source_path: str | None,
    exit_code: int | None,
    observed_at: str,
    started_at: str,
    artifact_error: str | None = None,
    logs_error: str | None = None,
) -> dict[str, Any]:
    reasons = [
        "sandbox probe mode enabled; listed uploaded sandbox paths instead of running npm install",
        f"live sandbox timing: started_at={started_at}; ended_at={observed_at}",
        "host fallback prohibited",
    ]
    if logs_error:
        reasons.append(logs_error)
    if artifact_error:
        reasons.append(artifact_error)
    return gate_evidence(
        gate="openshell",
        status="manual_review",
        run_id=run_id,
        source_kind="live",
        source_path=source_path,
        command=SANDBOX_PROBE_COMMAND,
        exit_code=exit_code,
        risk_level="unknown",
        reasons=reasons + ["manual observation is explanatory only and cannot satisfy allow."],
        observed_at=observed_at,
    )


def run_live_sandbox_install(
    *,
    poc_app_path: str,
    policy_path: str,
    canary_path: str,
    malicious_package_path: str | None = None,
    run_id: str,
    readiness: SandboxReadiness,
    runner: Callable[..., Any] = subprocess.run,
    timeout_seconds: int = LIVE_SANDBOX_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not readiness.ready:
        return readiness_failure_evidence(readiness, run_id=run_id)

    started_at = _utc_now()
    sandbox_name = _sandbox_name(run_id)
    probe_only = _probe_mode_enabled()
    command = _build_live_install_command(
        sandbox_name=sandbox_name,
        policy_path=policy_path,
        probe_only=probe_only,
    )
    with _prepare_upload_bundle(
        poc_app_path=poc_app_path,
        malicious_package_path=malicious_package_path,
        canary_path=canary_path,
    ) as upload_root:
        upload_source = Path(upload_root) / "chainshield-bundle"
        command[command.index("--upload") + 1] = f"{upload_source}:/tmp"
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
        except subprocess.TimeoutExpired as exc:
            ended_at = _utc_now()
            raw_log = _timeout_text(exc)
            logs_text, logs_error = _fetch_sandbox_logs(sandbox_name, runner=runner, timeout_seconds=timeout_seconds)
            combined_log = "\n".join(part for part in (raw_log, logs_text) if part.strip())
            log_path, artifact_error = _write_live_log_artifact(combined_log, run_id=run_id)
            _delete_sandbox(sandbox_name, runner=runner)
            if probe_only:
                return _probe_evidence(
                    run_id=run_id,
                    source_path=log_path,
                    exit_code=None,
                    observed_at=ended_at,
                    started_at=started_at,
                    artifact_error=artifact_error,
                    logs_error=logs_error,
                )
            evidence = normalize_openshell_log_data(
                combined_log,
                source_path=log_path,
                run_id=run_id,
                source_kind="live",
                command=LIVE_SANDBOX_COMMAND,
                exit_code=None,
                observed_at=ended_at,
            )
            evidence["status"] = "manual_review"
            evidence["risk_level"] = "unknown"
            evidence["reasons"] = list(evidence.get("reasons", [])) + [
                f"timeout: live sandbox install exceeded {timeout_seconds} seconds; started_at={started_at}; ended_at={ended_at}",
                f"readiness status={readiness.status}",
                "host fallback prohibited",
            ]
            if evidence.get("containment_events"):
                evidence["reasons"].append("containment evidence status=partial_or_captured_before_timeout")
            else:
                evidence["reasons"].append("containment evidence status=missing")
            if logs_error:
                evidence["reasons"].append(logs_error)
            if artifact_error:
                evidence["reasons"].append(artifact_error)
            return evidence
        except (FileNotFoundError, OSError) as exc:
            ended_at = _utc_now()
            _delete_sandbox(sandbox_name, runner=runner)
            return gate_evidence(
                gate="openshell",
                status="manual_review",
                run_id=run_id,
                source_kind="live",
                source_path=None,
                command=LIVE_SANDBOX_COMMAND,
                exit_code=None,
                risk_level="unknown",
                reasons=[
                    f"process launch failed: {type(exc).__name__}",
                    f"readiness status={readiness.status}",
                    "containment evidence status=missing",
                    "host fallback prohibited",
                ],
                observed_at=ended_at,
            )

    ended_at = _utc_now()
    try:
        raw_log = _completed_text(completed)
        probe_text, probe_event, probe_reason = _probe_canary_read(
            sandbox_name,
            runner=runner,
            timeout_seconds=timeout_seconds,
        )
        logs_text, logs_error = _fetch_sandbox_logs(sandbox_name, runner=runner, timeout_seconds=timeout_seconds)
        combined_log = "\n".join(part for part in (raw_log, probe_text, logs_text) if part.strip())
        path_builder = _probe_log_path if probe_only else _live_log_path
        log_path, artifact_error = _write_live_log_artifact(combined_log, run_id=run_id, path_builder=path_builder)
        if probe_only:
            probe_exit_code = getattr(completed, "returncode", None)
            return _probe_evidence(
                run_id=run_id,
                source_path=log_path,
                exit_code=probe_exit_code,
                observed_at=ended_at,
                started_at=started_at,
                artifact_error=artifact_error,
                logs_error=logs_error,
            )
        evidence = normalize_openshell_log_data(
            combined_log,
            source_path=log_path,
            run_id=run_id,
            source_kind="live",
            command=LIVE_SANDBOX_COMMAND,
            exit_code=getattr(completed, "returncode", None),
            observed_at=ended_at,
        )
        if probe_event is not None:
            probe_event["artifact_path"] = log_path or ""
            events = list(evidence.get("containment_events", []))
            events.append(probe_event)
            evidence["containment_events"] = events
            present = {event["event_type"] for event in events}
            missing = []
            if "filesystem_read" not in present:
                missing.append("file read block")
            if "network_egress" not in present:
                missing.append("egress block")
            if not missing:
                evidence["status"] = "pass"
                evidence["risk_level"] = "none"
                evidence["reasons"] = [
                    "OpenShell file read block evidence present.",
                    "OpenShell egress block evidence present.",
                    "filesystem read block confirmed by sandbox exec probe against chmod-hardened synthetic canary.",
                ]
            else:
                evidence["reasons"] = [f"missing containment evidence: {item}" for item in missing]
    finally:
        _delete_sandbox(sandbox_name, runner=runner)
    if logs_error:
        evidence["reasons"].append(logs_error)
    if artifact_error:
        evidence["reasons"].append(artifact_error)
    if probe_reason:
        evidence["reasons"].append(probe_reason)
    evidence["reasons"].append(f"live sandbox timing: started_at={started_at}; ended_at={ended_at}")
    evidence["reasons"].append("host fallback prohibited")
    return evidence


def _repo_path(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        return str(candidate)
    return str((REPO_ROOT / candidate).resolve(strict=False))


def run_sandbox(config: Any, *, run_id: str, runner: Callable[..., Any] = subprocess.run) -> dict[str, Any] | None:
    sandbox_mode = getattr(config, "sandbox_mode", None)
    if sandbox_mode is None:
        sandbox_mode = getattr(config, "raw", {}).get("sandbox_mode", "disabled")
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
            poc_app_path=_repo_path(fixtures["poc_app"]),
            policy_path=_repo_path(policy_path),
            canary_path=_repo_path(fixtures.get("canary_secret") or "fixtures/canary/canary-secret.txt"),
            malicious_package_path=_repo_path(fixtures["malicious_package"]) if fixtures.get("malicious_package") else None,
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
