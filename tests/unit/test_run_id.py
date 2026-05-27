import os

from chainshield.cli import _evidence_hash
from chainshield.config import build_run_id
from chainshield.config import validate_demo_config


def test_run_id_is_reproducible_for_fixed_inputs():
    run_id_1 = build_run_id(
        config_path="fixtures/configs/demo-fixture-deny.json",
        fixture_identity={"snyk": "fixtures/reports/snyk-high-critical.json"},
        timestamp="2026-05-27T00:00:00Z",
        evidence_hash="abc123",
    )
    run_id_2 = build_run_id(
        config_path="fixtures/configs/demo-fixture-deny.json",
        fixture_identity={"snyk": "fixtures/reports/snyk-high-critical.json"},
        timestamp="2026-05-27T00:00:00Z",
        evidence_hash="abc123",
    )

    assert run_id_1 == run_id_2
    assert run_id_1.startswith("run-20260527T000000Z-")


def test_run_id_changes_when_fixture_or_evidence_hash_changes():
    base = build_run_id("fixtures/configs/demo.json", {"snyk": "a"}, "2026-05-27T00:00:00Z", "abc")
    changed_fixture = build_run_id("fixtures/configs/demo.json", {"snyk": "b"}, "2026-05-27T00:00:00Z", "abc")
    changed_hash = build_run_id("fixtures/configs/demo.json", {"snyk": "a"}, "2026-05-27T00:00:00Z", "def")

    assert base != changed_fixture
    assert base != changed_hash


def test_evidence_hash_reads_fixture_paths_from_repo_root_when_cwd_changes(tmp_path):
    raw = {
        "version": 1,
        "request_id": "REQ-hash",
        "package_manager": "npm",
        "scanner_mode": {"snyk": "fixture", "socket": "fixture"},
        "sandbox_mode": "disabled",
        "fixtures": {
            "poc_app": "fixtures/poc-app",
            "malicious_package": "fixtures/malicious-poc-pkg",
            "snyk_report": "fixtures/reports/snyk-pass.json",
            "socket_report": "fixtures/reports/socket-pass.json",
            "openshell_log": None,
            "canary_secret": "fixtures/canary/synthetic-canary.txt",
        },
        "outputs": {"decision_json": "reports/test-hash-decision.json", "markdown_summary": None},
        "safety": {
            "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
            "sandbox_demo_override": {"enabled": False, "reason": None},
        },
    }
    config = validate_demo_config(raw)
    repo_hash = _evidence_hash(config)
    original_cwd = os.getcwd()

    try:
        os.chdir(tmp_path)
        other_cwd_hash = _evidence_hash(config)
    finally:
        os.chdir(original_cwd)

    assert other_cwd_hash == repo_hash
