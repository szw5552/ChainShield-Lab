from pathlib import Path

import pytest

from chainshield.artifacts import ArtifactWriteError, build_sanitized_failure_artifact, sanitize_text, write_json_artifact
from chainshield.artifacts import redact_text


@pytest.mark.parametrize(
    "raw, expected_reason",
    [
        ("Authorization: Bearer sk-live-token-value", "token/API key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "SSH private key"),
        ("[profile demo]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE", "cloud profile"),
        ("/Users/vincent5552/.env contains SECRET=value", "personal .env"),
        ("scanner raw log: npm ERR! stack with host details", "raw scanner/sandbox log"),
    ],
)
def test_sanitizer_rejects_sensitive_artifacts(raw, expected_reason):
    result = sanitize_text(raw)

    assert result.safe is False
    assert result.stop_execution is True
    assert any(expected_reason in reason for reason in result.reasons)


def test_sanitizer_failure_artifact_requires_manual_review():
    result = sanitize_text("Authorization: Bearer socket-secret-token")
    artifact = build_sanitized_failure_artifact("snyk", result, run_id="run-sanitize")

    assert artifact["status"] == "manual_review"
    assert artifact["sanitized"] is True
    assert "token/API key" in " ".join(artifact["reasons"])


def test_writer_refuses_to_save_raw_artifact(tmp_path):
    path = tmp_path / "decision.json"

    with pytest.raises(ArtifactWriteError):
        write_json_artifact(path, {"token": "NVIDIA_API_KEY=nvapi-secret-value"})

    assert not path.exists()


def test_sanitizer_and_redactor_catch_json_style_tokens(tmp_path):
    raw = '{"NVIDIA_API_KEY": "nvapi-secret-value", "token": "socket-secret-value"}'

    result = sanitize_text(raw)
    redacted = redact_text(raw)

    assert result.safe is False
    assert any("token/API key" in reason for reason in result.reasons)
    assert "nvapi-secret-value" not in redacted
    assert "socket-secret-value" not in redacted

    with pytest.raises(ArtifactWriteError):
        write_json_artifact(tmp_path / "unsafe.json", {"NVIDIA_API_KEY": "nvapi-secret-value"})
