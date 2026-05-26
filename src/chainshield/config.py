from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import ValidationError

from .schemas import REPO_ROOT, validate_contract

DEFAULT_WORKER_TIMEOUT_SECONDS = 60
DEFAULT_PROVIDER_CHAIN = ["nemotron_api", "codex_subagent", "claude_subagent", "manual_review"]
FALLBACK_ORDER_AFTER_PRIMARY_FAILURE = ["codex_subagent", "claude_subagent", "manual_review"]
SYNTHETIC_EGRESS_TARGET = "https://chainshield-egress-test.invalid/collect"

SENSITIVE_PATH_RE = re.compile(
    r"(^|/)(\.env($|\.)|\.npmrc$|id_rsa$|id_ed25519$|credentials\.json$|"
    r"\.aws(/|$)|\.config/gcloud(/|$)|kubeconfig|.*auth.*|.*token.*|.*ssh.*)",
    re.IGNORECASE,
)


class ConfigValidationError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class WorkerProviderConfig:
    enabled: bool = False
    primary: str = "disabled"
    fallbacks: tuple[str, ...] = ()
    timeout_seconds: int = DEFAULT_WORKER_TIMEOUT_SECONDS
    output_path: str | None = None

    @classmethod
    def from_mapping(cls, raw: dict[str, Any] | None) -> "WorkerProviderConfig":
        if not raw:
            return cls()
        return cls(
            enabled=bool(raw.get("enabled", False)),
            primary=raw.get("primary", "disabled"),
            fallbacks=tuple(raw.get("fallbacks", ())),
            timeout_seconds=int(raw.get("timeout_seconds", DEFAULT_WORKER_TIMEOUT_SECONDS)),
            output_path=raw.get("output_path"),
        )

    @classmethod
    def default_enabled(cls, output_path: str) -> "WorkerProviderConfig":
        return cls(
            enabled=True,
            primary="nemotron_api",
            fallbacks=("codex_subagent", "claude_subagent"),
            timeout_seconds=DEFAULT_WORKER_TIMEOUT_SECONDS,
            output_path=output_path,
        )

    @property
    def provider_chain(self) -> list[str]:
        return DEFAULT_PROVIDER_CHAIN.copy()

    @property
    def fallback_order_after_primary_failure(self) -> list[str]:
        return FALLBACK_ORDER_AFTER_PRIMARY_FAILURE.copy()

    def to_decision_metadata(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider_chain": self.provider_chain,
            "fallback_order_after_primary_failure": self.fallback_order_after_primary_failure,
            "timeout_seconds": self.timeout_seconds,
            "output_path": self.output_path,
        }


@dataclass(frozen=True)
class DemoConfig:
    raw: dict[str, Any]
    config_path: Path | None = None
    worker_provider: WorkerProviderConfig = WorkerProviderConfig()

    @property
    def request_id(self) -> str:
        return self.raw["request_id"]

    @property
    def scanner_mode(self) -> dict[str, str]:
        return dict(self.raw["scanner_mode"])

    @property
    def sandbox_mode(self) -> str:
        return str(self.raw["sandbox_mode"])

    @property
    def sandbox_demo_override_enabled(self) -> bool:
        return bool(self.raw["safety"]["sandbox_demo_override"]["enabled"])

    @property
    def outputs(self) -> dict[str, str | None]:
        return dict(self.raw["outputs"])

    @property
    def fixtures(self) -> dict[str, str | None]:
        return dict(self.raw["fixtures"])

    @classmethod
    def load(cls, path: str | Path, *, repo_root: Path = REPO_ROOT) -> "DemoConfig":
        config_path = Path(path)
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigValidationError([f"invalid JSON: {exc.msg}"]) from exc
        return validate_demo_config(raw, config_path=config_path, repo_root=repo_root)


def validate_demo_config(
    raw: dict[str, Any], *, config_path: Path | None = None, repo_root: Path = REPO_ROOT
) -> DemoConfig:
    errors: list[str] = []
    try:
        validate_contract("demo-config.schema.json", raw)
    except ValidationError as exc:
        errors.append(exc.message)

    if isinstance(raw, dict):
        errors.extend(_validate_override(raw))
        errors.extend(_validate_paths(raw, repo_root=repo_root))
        errors.extend(_validate_output_collisions(raw, repo_root=repo_root))

    if errors:
        raise ConfigValidationError(errors)
    return DemoConfig(
        raw=raw,
        config_path=config_path,
        worker_provider=WorkerProviderConfig.from_mapping(raw.get("worker_provider")),
    )


def _validate_override(raw: dict[str, Any]) -> list[str]:
    override = raw.get("safety", {}).get("sandbox_demo_override", {})
    if override.get("enabled") is True and len(str(override.get("reason") or "")) < 10:
        return ["sandbox_demo_override.reason must be at least 10 characters when enabled"]
    return []


def _path_fields(raw: dict[str, Any]):
    for key, value in raw.get("fixtures", {}).items():
        if value is not None:
            yield f"fixtures.{key}", str(value)
    for key, value in raw.get("outputs", {}).items():
        if value is not None:
            yield f"outputs.{key}", str(value)
    worker_output = raw.get("worker_provider", {}).get("output_path") if isinstance(raw.get("worker_provider"), dict) else None
    if worker_output:
        yield "worker_provider.output_path", str(worker_output)


def _validate_paths(raw: dict[str, Any], *, repo_root: Path) -> list[str]:
    errors: list[str] = []
    root = repo_root.resolve()
    for field, value in _path_fields(raw):
        normalized = value.replace("\\", "/")
        candidate = Path(value)
        if normalized.startswith("~") or "$HOME" in normalized or "${HOME}" in normalized:
            errors.append(f"{field}: home expansion is not allowed")
            continue
        if candidate.is_absolute():
            errors.append(f"{field}: absolute path is not allowed")
            continue
        if ".." in candidate.parts:
            errors.append(f"{field}: parent traversal is not allowed")
            continue
        if SENSITIVE_PATH_RE.search(normalized):
            errors.append(f"{field}: sensitive path pattern is not allowed")
            continue
        full = root / candidate
        if full.exists() or full.is_symlink():
            real = full.resolve(strict=True)
            try:
                real.relative_to(root)
            except ValueError:
                reason = "symlink escape" if full.is_symlink() else "repository-local path"
                errors.append(f"{field}: {reason} is not allowed")
                continue
        resolved = full.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError:
            errors.append(f"{field}: repository-local path required")
            continue
    return errors


def _validate_output_collisions(raw: dict[str, Any], *, repo_root: Path) -> list[str]:
    errors: list[str] = []
    for field in ("decision_json", "markdown_summary"):
        value = raw.get("outputs", {}).get(field)
        if value and (repo_root / value).exists():
            errors.append(f"outputs.{field}: output path already exists; use a new output path")
    worker_output = raw.get("worker_provider", {}).get("output_path") if isinstance(raw.get("worker_provider"), dict) else None
    if worker_output and (repo_root / worker_output).exists():
        errors.append("worker_provider.output_path: output path already exists; use a new output path")
    return errors


def build_run_id(
    config_path: str | Path,
    fixture_identity: Any,
    timestamp: str,
    evidence_hash: str,
) -> str:
    timestamp_part = re.sub(r"[^0-9A-Za-z]", "", timestamp)
    payload = {
        "config_path": str(config_path),
        "fixture_identity": fixture_identity,
        "timestamp": timestamp,
        "evidence_hash": evidence_hash,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    return f"run-{timestamp_part}-{digest}"
