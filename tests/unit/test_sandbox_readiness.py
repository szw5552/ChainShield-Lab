from __future__ import annotations

import subprocess
from pathlib import Path

from chainshield.sandbox import (
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
