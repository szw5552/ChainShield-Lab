from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from chainshield import sandbox
from chainshield.schemas import REPO_ROOT
from chainshield.sandbox import (
    SANDBOX_CANARY_PATH,
    SANDBOX_CANARY_ROOT,
    SANDBOX_MALICIOUS_PACKAGE_PATH,
    SANDBOX_PROBE_ENV,
    SANDBOX_FIXTURES_ROOT,
    SANDBOX_POC_APP_PATH,
    SandboxReadiness,
    build_sandbox_env,
    check_sandbox_readiness,
    manual_observation_evidence,
    run_live_sandbox_install,
)


class Completed:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_readiness_requires_orbstack_and_openshell_without_host_fallback():
    def runner(command, **kwargs):
        if command[:2] == ["docker", "info"]:
            return Completed(stdout="Docker Desktop")
        raise AssertionError(f"unexpected command: {command}")

    readiness = check_sandbox_readiness(
        run_id="run-sandbox",
        runner=runner,
        fixture_evidence_path="fixtures/reports/openshell-deny.log",
    )

    assert readiness.status == "manual_review"
    assert readiness.host_fallback_attempted is False
    assert readiness.unauthorized_runtime_attempted is False
    assert readiness.fixture_evidence_path == "fixtures/reports/openshell-deny.log"
    assert readiness.manual_verification_path == "specs/001-orbstack-sandbox-gates/quickstart.md#manual-sandbox-verification"
    assert any("OrbStack" in reason for reason in readiness.reasons)
    assert any("host fallback" in reason.lower() for reason in readiness.reasons)


def test_readiness_does_not_use_general_docker_when_orbstack_is_absent():
    commands: list[list[str]] = []

    def runner(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "info"]:
            return Completed(stdout="Docker Engine - Community")
        raise AssertionError(f"unexpected command: {command}")

    readiness = check_sandbox_readiness(run_id="run-sandbox", runner=runner)

    assert readiness.status == "manual_review"
    assert ["docker", "run"] not in [command[:2] for command in commands]
    assert any("general Docker runtime is not authorized" in reason for reason in readiness.reasons)


def test_openshell_unavailable_reports_manual_review_path():
    def runner(command, **kwargs):
        if command[:2] == ["docker", "info"]:
            return Completed(stdout="OrbStack")
        if command[0] == "openshell":
            raise FileNotFoundError("openshell")
        raise AssertionError(f"unexpected command: {command}")

    readiness = check_sandbox_readiness(run_id="run-sandbox", runner=runner)

    assert readiness.status == "manual_review"
    assert any("OpenShell" in reason for reason in readiness.reasons)
    assert readiness.manual_verification_path.endswith("#manual-sandbox-verification")


def test_manual_observation_never_satisfies_allow():
    evidence = manual_observation_evidence(
        run_id="run-sandbox",
        reasons=["operator observed expected deny events in local tool"],
    )

    assert evidence["gate"] == "openshell"
    assert evidence["source_kind"] == "manual_observation"
    assert evidence["status"] == "manual_review"
    assert evidence["status"] != "pass"


def test_openshell_policy_template_uses_verified_schema_keys():
    policy = Path("policies/openshell-npm-install.yaml").read_text(encoding="utf-8")

    assert "filesystem_policy:" in policy
    assert "network_policies:" in policy
    assert "\nfilesystem:" not in policy
    assert "\nnetwork:" not in policy


def test_live_sandbox_timeout_records_failure_evidence_without_host_fallback():
    readiness = check_sandbox_readiness(
        run_id="run-sandbox",
        runner=lambda *args, **kwargs: Completed(stdout="OrbStack") if args[0][0] == "docker" else Completed(stdout="OpenShell 0.1"),
    )

    def timeout_runner(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs["timeout"])

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox",
        readiness=readiness,
        runner=timeout_runner,
        timeout_seconds=300,
    )

    assert evidence["status"] == "manual_review"
    joined = " ".join(evidence["reasons"])
    assert "timeout" in joined.lower()
    assert "300" in joined
    assert "readiness status=pass" in joined
    assert "host fallback prohibited" in joined.lower()
    assert "containment evidence status=missing" in joined.lower()


def test_live_sandbox_timeout_captures_logs_before_cleanup(monkeypatch):
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)
    created_paths: list[Path] = []
    calls: list[list[str]] = []

    def timeout_runner(command, **kwargs):
        calls.append(command)
        if command[:2] == ["openshell", "logs"]:
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "exec"]:
            return Completed(
                stdout='{"event_type":"filesystem_read","blocked_path":"/sandbox/canary/canary-secret.txt","policy_rule_id":"fs.default_deny","result":"blocked","timestamp":"2026-05-27T00:00:00Z","artifact_path":"reports/sandbox/example.log","source_kind":"live","sanitized":true}\n'
            )
        if command[:3] == ["openshell", "sandbox", "delete"]:
            return Completed(stdout="")
        raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs["timeout"])

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox-timeout-logs",
        readiness=readiness,
        runner=timeout_runner,
        timeout_seconds=300,
    )

    assert evidence["status"] == "manual_review"
    assert evidence["source_path"] is not None
    log_path = Path(evidence["source_path"])
    created_paths.append(log_path)
    assert log_path.exists()
    joined = " ".join(evidence["reasons"])
    assert "containment evidence status=partial_or_captured_before_timeout" in joined
    assert ["openshell", "logs"] in [command[:2] for command in calls]
    assert ["openshell", "sandbox", "exec"] in [command[:3] for command in calls]
    assert ["openshell", "sandbox", "delete"] in [command[:3] for command in calls]

    for path in created_paths:
        path.unlink(missing_ok=True)


def test_live_sandbox_parse_failure_persists_live_log_artifact():
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)
    created_paths: list[Path] = []

    def runner(command, **kwargs):
        if command[:3] == ["openshell", "sandbox", "create"]:
            return Completed(stdout='sandbox created\n{"broken":', returncode=1)
        if command[:2] == ["openshell", "logs"]:
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "exec"]:
            return Completed(stdout="gateway event text\nanother non-json line")
        if command[:3] == ["openshell", "sandbox", "delete"]:
            return Completed(stdout="")
        raise AssertionError(f"unexpected command: {command}")

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox-parse-failure",
        readiness=readiness,
        runner=runner,
        timeout_seconds=300,
    )

    assert evidence["status"] == "manual_review"
    assert evidence["source_path"] is not None
    log_path = Path(evidence["source_path"])
    created_paths.append(log_path)
    assert log_path.exists()
    assert log_path.read_text(encoding="utf-8")
    assert any("parse_or_schema_error" in reason for reason in evidence["reasons"])
    assert any("live sandbox timing:" in reason for reason in evidence["reasons"])

    for path in created_paths:
        path.unlink(missing_ok=True)


def test_live_sandbox_probe_mode_persists_probe_log(monkeypatch):
    monkeypatch.setenv(SANDBOX_PROBE_ENV, "1")
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)
    created_paths: list[Path] = []
    calls = {}

    def runner(command, **kwargs):
        if command[:3] == ["openshell", "sandbox", "create"]:
            calls["command"] = command
            return Completed(stdout="/tmp\n/tmp/chainshield-fixtures\n/tmp/chainshield-fixtures/poc-app\n")
        if command[:2] == ["openshell", "logs"]:
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "exec"]:
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "delete"]:
            return Completed(stdout="")
        raise AssertionError(f"unexpected command: {command}")

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox-probe",
        readiness=readiness,
        runner=runner,
        timeout_seconds=300,
    )

    assert evidence["status"] == "manual_review"
    assert evidence["source_path"] is not None
    assert "sandbox probe mode enabled" in " ".join(evidence["reasons"])
    assert evidence["command"] is not None and "find /tmp/chainshield-bundle" in evidence["command"]
    shell_script = calls["command"][-1]
    assert "find /tmp/chainshield-bundle -maxdepth 4 -type d | sort" in shell_script
    assert "find /tmp/chainshield-bundle/chainshield-canary -maxdepth 2 -type f | sort" in shell_script
    log_path = Path(evidence["source_path"])
    created_paths.append(log_path)
    assert log_path.exists()
    assert "chainshield-fixtures" in log_path.read_text(encoding="utf-8")

    for path in created_paths:
        path.unlink(missing_ok=True)


def test_sandbox_env_keeps_path_and_filters_secret_bearing_variables(monkeypatch):
    monkeypatch.setenv("PATH", "/opt/homebrew/bin:/usr/bin:/bin")
    monkeypatch.setenv("NVIDIA_API_KEY", "secret")
    monkeypatch.setenv("TOKEN", "secret")

    env = build_sandbox_env("fixtures/canary/canary-secret.txt")

    assert env["PATH"] == "/opt/homebrew/bin:/usr/bin:/bin"
    assert env["CHAINSHIELD_CANARY_PATH"] == "fixtures/canary/canary-secret.txt"
    assert "NVIDIA_API_KEY" not in env
    assert "TOKEN" not in env


def test_live_sandbox_passes_safe_env_to_runner():
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)
    calls = {}

    def runner(command, **kwargs):
        if command[:3] == ["openshell", "sandbox", "create"]:
            calls["env"] = kwargs["env"]
        raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs["timeout"])

    run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox-env",
        readiness=readiness,
        runner=runner,
    )

    assert "PATH" in calls["env"]
    assert calls["env"]["CHAINSHIELD_CANARY_PATH"] == "fixtures/canary/canary-secret.txt"


def test_live_sandbox_launch_failure_records_manual_review_without_crash():
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)

    def failing_runner(command, **kwargs):
        raise OSError("cannot launch")

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        run_id="run-sandbox-launch-failure",
        readiness=readiness,
        runner=failing_runner,
    )

    assert evidence["status"] == "manual_review"
    joined = " ".join(evidence["reasons"])
    assert "process launch failed" in joined
    assert "host fallback prohibited" in joined


def test_live_sandbox_resolves_policy_and_canary_paths_against_repo_root():
    calls = {}

    def runner(command, **kwargs):
        if command[:2] == ["docker", "info"]:
            return Completed(stdout="OrbStack")
        if command[:2] == ["openshell", "--version"]:
            return Completed(stdout="OpenShell 0.1")
        if command[:3] == ["openshell", "sandbox", "create"]:
            calls["command"] = command
            calls["cwd"] = kwargs["cwd"]
            calls["env"] = kwargs["env"]
            upload_root = Path(command[command.index("--upload") + 1].split(":", 1)[0])
            calls["upload_snapshot"] = {
                "root_exists": upload_root.is_dir(),
                "poc_app_exists": (upload_root / "chainshield-fixtures" / "poc-app").is_dir(),
                "malicious_package_exists": (upload_root / "chainshield-fixtures" / "malicious-poc-pkg").is_dir(),
                "canary_exists": (upload_root / "chainshield-canary" / "canary-secret.txt").is_file(),
            }
            return Completed(stdout="")
        if command[:2] == ["openshell", "logs"]:
            calls["logs_command"] = command
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "exec"]:
            if command[-1] == f"cat {SANDBOX_CANARY_PATH}":
                calls["probe_command"] = command
                return Completed(stdout="cat: permission denied", stderr="", returncode=1)
            calls["exec_command"] = command
            return Completed(
                stdout="\n".join(
                    [
                        '{"event_type":"network_egress","blocked_target":"https://chainshield-egress-test.invalid/collect","policy_rule_id":"net.default_deny","result":"blocked","timestamp":"2026-05-27T00:00:01Z","source_kind":"live","sanitized":true}',
                    ]
                )
            )
        if command[:3] == ["openshell", "sandbox", "delete"]:
            calls["delete_command"] = command
            return Completed(stdout="")
        raise AssertionError(f"unexpected command: {command}")

    config = SimpleNamespace(
        raw={"sandbox_mode": "live"},
        sandbox_mode="live",
        fixtures={
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "openshell_policy": "policies/openshell-npm-install.yaml",
            "canary_secret": "fixtures/canary/canary-secret.txt",
            "openshell_log": "fixtures/reports/openshell-deny.log",
        },
    )

    evidence = sandbox.run_sandbox(config, run_id="run-sandbox-paths", runner=runner)

    assert evidence["status"] == "pass"
    assert calls["command"][:3] == ["openshell", "sandbox", "create"]
    assert "--policy" in calls["command"]
    assert calls["command"][calls["command"].index("--policy") + 1] == str(
        (REPO_ROOT / "policies/openshell-npm-install.yaml").resolve(strict=False)
    )
    uploads = [calls["command"][index + 1] for index, item in enumerate(calls["command"]) if item == "--upload"]
    assert len(uploads) == 1
    assert uploads[0].endswith(":/tmp")
    assert calls["upload_snapshot"] == {
        "root_exists": True,
        "poc_app_exists": True,
        "malicious_package_exists": True,
        "canary_exists": True,
    }
    assert calls["cwd"] == str((REPO_ROOT / "fixtures/poc-app").resolve(strict=False))
    assert calls["env"]["CHAINSHIELD_CANARY_PATH"] == str((REPO_ROOT / "fixtures/canary/canary-secret.txt").resolve(strict=False))
    sandbox_command = calls["command"]
    shell_script = sandbox_command[-1]
    assert f"cd {SANDBOX_POC_APP_PATH}" in shell_script
    assert f"chmod 000 {SANDBOX_CANARY_PATH}" in shell_script
    assert f"CHAINSHIELD_CANARY_PATH={SANDBOX_CANARY_PATH}" in shell_script
    assert "npm install --ignore-scripts=false --install-links" in shell_script
    assert calls["logs_command"][:2] == ["openshell", "logs"]
    assert calls["probe_command"][:3] == ["openshell", "sandbox", "exec"]
    assert calls["exec_command"][:3] == ["openshell", "sandbox", "exec"]
    assert calls["delete_command"][:3] == ["openshell", "sandbox", "delete"]


def test_live_sandbox_redacts_successful_canary_probe_output():
    readiness = SandboxReadiness(status="pass", runtime="OrbStack", openshell_available=True)
    created_paths: list[Path] = []

    def runner(command, **kwargs):
        if command[:3] == ["openshell", "sandbox", "create"]:
            return Completed(stdout="")
        if command[:2] == ["openshell", "logs"]:
            return Completed(
                stdout="2026-05-27T17:09:27.031Z OCSF NET:OPEN [MED] DENIED /usr/bin/node(72) -> chainshield-egress-test.invalid:443 [policy:- engine:opa]"
            )
        if command[:3] == ["openshell", "sandbox", "exec"]:
            if command[-1] == f"cat {SANDBOX_CANARY_PATH}":
                return Completed(stdout="POC-ONLY synthetic ChainShield canary secret.\n", returncode=0)
            return Completed(stdout="")
        if command[:3] == ["openshell", "sandbox", "delete"]:
            return Completed(stdout="")
        raise AssertionError(f"unexpected command: {command}")

    evidence = run_live_sandbox_install(
        poc_app_path="fixtures/poc-app",
        policy_path="policies/openshell-npm-install.yaml",
        canary_path="fixtures/canary/canary-secret.txt",
        malicious_package_path="fixtures/malicious-poc-pkg",
        run_id="run-sandbox-canary-redaction",
        readiness=readiness,
        runner=runner,
    )

    assert evidence["status"] == "manual_review"
    assert any("canary read probe unexpectedly succeeded" in reason for reason in evidence["reasons"])
    log_path = Path(evidence["source_path"])
    created_paths.append(log_path)
    log_text = log_path.read_text(encoding="utf-8")
    assert "stdout redacted" in log_text
    assert "POC-ONLY synthetic ChainShield canary secret" not in log_text

    for path in created_paths:
        path.unlink(missing_ok=True)
