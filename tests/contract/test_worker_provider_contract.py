from chainshield.config import DEFAULT_PROVIDER_CHAIN, DEFAULT_WORKER_TIMEOUT_SECONDS, WorkerProviderConfig
from chainshield.schemas import validate_contract
from chainshield.worker_provider import build_agent_invocation, redact_provider_text


def test_worker_provider_defaults_and_canonical_order():
    provider = WorkerProviderConfig.default_enabled("reports/worker-summary.json")

    assert provider.enabled is True
    assert provider.timeout_seconds == DEFAULT_WORKER_TIMEOUT_SECONDS == 60
    assert provider.provider_chain == DEFAULT_PROVIDER_CHAIN
    assert provider.fallback_order_after_primary_failure == [
        "codex_subagent",
        "claude_subagent",
        "manual_review",
    ]


def test_agent_invocation_schema_and_api_key_redaction():
    invocation = build_agent_invocation(
        provider="nemotron_api",
        model="nvidia/nemotron-3-nano-30b-a3b",
        status="failed",
        request_id="REQ-worker",
        run_id="run-worker",
        errors=["Authorization failed for NVIDIA_API_KEY=nvapi-secret-token"],
    )

    assert "nvapi-secret-token" not in " ".join(invocation["errors"])
    assert "[REDACTED]" in " ".join(invocation["errors"])
    validate_contract("agent-invocation-evidence.schema.json", invocation)


def test_provider_redaction_covers_bearer_and_api_key_values():
    raw = "Authorization: Bearer abc.def.ghi NVIDIA_API_KEY=nvapi-1234567890"

    redacted = redact_provider_text(raw)

    assert "abc.def.ghi" not in redacted
    assert "nvapi-1234567890" not in redacted
    assert redacted.count("[REDACTED]") >= 2
