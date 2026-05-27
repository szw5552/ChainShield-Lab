import json
import tomllib
from pathlib import Path

import pytest

from chainshield.config import ConfigValidationError, DemoConfig, validate_demo_config
from chainshield.schemas import validate_contract


BASE_CONFIG = {
    "version": 1,
    "request_id": "REQ-foundation",
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
    "outputs": {
        "decision_json": "reports/foundation-decision.json",
        "markdown_summary": "reports/foundation-summary.md",
    },
    "safety": {
        "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
        "sandbox_demo_override": {"enabled": False, "reason": None},
    },
}


def test_valid_demo_config_schema_and_model(tmp_path):
    config = dict(BASE_CONFIG)
    config["outputs"] = {
        "decision_json": "reports/test-valid-demo-config.json",
        "markdown_summary": "reports/test-valid-demo-config.md",
    }

    validate_contract("demo-config.schema.json", config)
    parsed = validate_demo_config(config, config_path=Path("fixtures/configs/demo-valid.json"))

    assert isinstance(parsed, DemoConfig)
    assert parsed.request_id == "REQ-foundation"
    assert parsed.sandbox_demo_override_enabled is False


def test_jsonschema_is_runtime_dependency_not_test_only():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert "jsonschema>=4.21" in pyproject["project"]["dependencies"]
    assert "jsonschema>=4.21" not in pyproject["project"]["optional-dependencies"]["test"]


def test_sandbox_demo_override_requires_a_reason():
    config = dict(BASE_CONFIG)
    config["safety"] = {
        "synthetic_egress_target": "https://chainshield-egress-test.invalid/collect",
        "sandbox_demo_override": {"enabled": True, "reason": "too short"},
    }

    with pytest.raises(ConfigValidationError) as excinfo:
        validate_demo_config(config, config_path=Path("fixtures/configs/override.json"))

    assert "sandbox_demo_override.reason" in str(excinfo.value)


def test_demo_config_rejects_additional_fields():
    config = dict(BASE_CONFIG)
    config["unexpected"] = True

    with pytest.raises(ConfigValidationError) as excinfo:
        validate_demo_config(config, config_path=Path("fixtures/configs/additional.json"))

    assert "Additional properties" in str(excinfo.value)


@pytest.mark.parametrize(
    "bad_path, expected",
    [
        ("../outside/report.json", "parent traversal"),
        ("~/chainshield/report.json", "home expansion"),
        ("$HOME/chainshield/report.json", "home expansion"),
        ("/Users/demo/.ssh/id_rsa", "absolute path"),
        ("fixtures/configs/.npmrc", "sensitive path"),
        ("fixtures/configs/auth-token.json", "sensitive path"),
        ("fixtures/configs/.aws/credentials", "sensitive path"),
    ],
)
def test_demo_config_rejects_unsafe_paths(bad_path, expected):
    config = dict(BASE_CONFIG)
    config["fixtures"] = dict(BASE_CONFIG["fixtures"])
    config["fixtures"]["snyk_report"] = bad_path

    with pytest.raises(ConfigValidationError) as excinfo:
        validate_demo_config(config, config_path=Path("fixtures/configs/bad-path.json"))

    assert expected in str(excinfo.value)


def test_demo_config_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside-report.json"
    outside.write_text("{}", encoding="utf-8")
    link = Path("fixtures/configs/symlink-escape.json")
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(outside)
    try:
        config = dict(BASE_CONFIG)
        config["fixtures"] = dict(BASE_CONFIG["fixtures"])
        config["fixtures"]["snyk_report"] = str(link)

        with pytest.raises(ConfigValidationError) as excinfo:
            validate_demo_config(config, config_path=Path("fixtures/configs/symlink.json"))

        assert "symlink escape" in str(excinfo.value)
    finally:
        link.unlink(missing_ok=True)


def test_demo_config_rejects_broken_symlink_without_crashing():
    link = Path("fixtures/configs/broken-symlink-report.json")
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to("missing-target.json")
    try:
        config = dict(BASE_CONFIG)
        config["fixtures"] = dict(BASE_CONFIG["fixtures"])
        config["fixtures"]["snyk_report"] = str(link)

        with pytest.raises(ConfigValidationError) as excinfo:
            validate_demo_config(config, config_path=Path("fixtures/configs/broken-symlink.json"))

        assert "broken symlink" in str(excinfo.value)
    finally:
        link.unlink(missing_ok=True)


def test_demo_config_allows_author_filename_without_sensitive_path_false_positive():
    config = dict(BASE_CONFIG)
    config["fixtures"] = dict(BASE_CONFIG["fixtures"])
    config["fixtures"]["snyk_report"] = "fixtures/configs/demo-author-allow.json"
    config["outputs"] = {
        "decision_json": "reports/test-author-path-decision.json",
        "markdown_summary": "reports/test-author-path-summary.md",
    }

    parsed = validate_demo_config(config, config_path=Path("fixtures/configs/author.json"))

    assert parsed.fixtures["snyk_report"] == "fixtures/configs/demo-author-allow.json"


def test_demo_config_rejects_output_collision(tmp_path):
    collision = Path("reports/collision-decision.json")
    collision.parent.mkdir(exist_ok=True)
    collision.write_text("{}", encoding="utf-8")
    try:
        config = dict(BASE_CONFIG)
        config["outputs"] = {
            "decision_json": str(collision),
            "markdown_summary": "reports/collision-summary.md",
        }

        with pytest.raises(ConfigValidationError) as excinfo:
            validate_demo_config(config, config_path=Path("fixtures/configs/collision.json"))

        assert "already exists" in str(excinfo.value)
    finally:
        collision.unlink(missing_ok=True)
