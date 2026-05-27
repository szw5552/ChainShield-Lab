from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import ArtifactWriteError, atomic_write_text, render_markdown_summary, sanitize_text, write_json_artifact
from .config import ConfigValidationError, DemoConfig, build_run_id, validate_output_path
from .evidence import gate_evidence
from .schemas import REPO_ROOT
from .sandbox import run_sandbox
from .scanners import run_scanners
from .supervisor import SupervisorDecision, decide_static_gates
from .worker_provider import run_worker_provider

EXIT_CODES = {"allow": 0, "deny": 1, "manual_review": 2}


def _safe_outputs_from_raw_config(path: Path) -> dict[str, str | None]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {"decision_json": "reports/manual-review-invalid-config.json", "markdown_summary": None}
    outputs = raw.get("outputs") if isinstance(raw, dict) else None
    if not isinstance(outputs, dict):
        return {"decision_json": "reports/manual-review-invalid-config.json", "markdown_summary": None}
    decision_json = _safe_raw_output("outputs.decision_json", outputs.get("decision_json"), "reports/manual-review-invalid-config.json")
    markdown_summary = _safe_raw_output("outputs.markdown_summary", outputs.get("markdown_summary"), None)
    return {"decision_json": decision_json, "markdown_summary": markdown_summary}


def _safe_raw_output(field: str, value: Any, default: str | None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return default
    if validate_output_path(field, value, repo_root=REPO_ROOT):
        return default
    return value


def _manual_review_for_invalid_config(config_path: Path, errors: list[str]) -> dict[str, Any]:
    outputs = _safe_outputs_from_raw_config(config_path)
    decision = SupervisorDecision(
        decision="manual_review",
        summary="Demo config validation failed; scanner and sandbox execution were blocked.",
        primary_reasons=["Config validation failed: " + "; ".join(errors)],
        gate_results=[],
        missing_gates=["snyk", "socket", "openshell"],
        next_actions=["Fix demo config and choose a new output path before rerunning."],
        request_id="REQ-invalid-config",
        run_id="run-invalid-config",
        artifacts={
            "decision_json": str(outputs["decision_json"]),
            "markdown_summary": outputs.get("markdown_summary"),
            "reports": [],
            "logs": [],
            "worker": [],
        },
    )
    return decision.to_dict()


def _unique_artifact_path(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    candidate = path.with_name(f"{path.stem}-{timestamp}{path.suffix}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}-{timestamp}-{counter}{path.suffix}")
        counter += 1
    return candidate


def _write_invalid_config_decision(decision: dict[str, Any]) -> None:
    output_path = Path(decision["artifacts"]["decision_json"])
    if output_path.exists():
        replacement = _unique_artifact_path(output_path)
        decision["primary_reasons"].append(
            f"artifact_path_rotated: requested invalid-config decision artifact already exists; wrote {replacement}"
        )
        decision["artifacts"]["decision_json"] = str(replacement)
        output_path = replacement
    try:
        write_json_artifact(output_path, decision)
    except ArtifactWriteError as exc:
        decision["primary_reasons"].append(f"artifact_skipped: invalid-config decision artifact was not written: {exc}")


def _evidence_hash(config: DemoConfig) -> str:
    digest = hashlib.sha256()
    for key, value in sorted(config.fixtures.items()):
        digest.update(str(key).encode("utf-8"))
        digest.update(str(value).encode("utf-8"))
        if value and Path(value).exists() and Path(value).is_file():
            digest.update(Path(value).read_bytes())
    return digest.hexdigest()[:16]


def _markdown_summary(decision: dict[str, Any]) -> str:
    return render_markdown_summary(decision)


def _write_decision_artifacts(decision: dict[str, Any]) -> None:
    write_json_artifact(decision["artifacts"]["decision_json"], decision)
    markdown_summary = decision["artifacts"].get("markdown_summary")
    if markdown_summary:
        markdown = _markdown_summary(decision)
        result = sanitize_text(markdown)
        if not result.safe:
            raise ArtifactWriteError("refusing to save unsanitized markdown summary: " + ", ".join(result.reasons))
        if Path(markdown_summary).exists():
            raise ArtifactWriteError(f"artifact already exists: {markdown_summary}")
        atomic_write_text(Path(markdown_summary), markdown)


def _sandbox_requested(config: DemoConfig) -> bool:
    return config.sandbox_mode in {"fixture", "live"}


def _can_enter_sandbox(static_decision: SupervisorDecision, config: DemoConfig) -> bool:
    if static_decision.decision == "allow":
        return True
    if static_decision.decision == "deny" and config.sandbox_demo_override_enabled:
        return True
    return False


def _manual_review_for_sandbox(static_decision: SupervisorDecision, sandbox_evidence: dict[str, Any]) -> SupervisorDecision:
    missing = list(dict.fromkeys([*static_decision.missing_gates, "openshell"]))
    reasons = sandbox_evidence.get("reasons") or ["OpenShell containment evidence is incomplete."]
    return SupervisorDecision(
        decision="manual_review",
        summary="Sandbox containment gate requires manual review.",
        primary_reasons=list(reasons),
        gate_results=[*static_decision.gate_results, sandbox_evidence],
        missing_gates=missing,
        next_actions=[
            "Provide complete sanitized OpenShell file-read and egress-block evidence before allowing install.",
            "Do not run npm lifecycle scripts on the host.",
        ],
        request_id=static_decision.request_id,
        run_id=static_decision.run_id,
        artifacts=static_decision.artifacts,
        worker_provider=static_decision.worker_provider,  # type: ignore[arg-type]
    )


def _sandbox_only_missing_evidence(*, run_id: str) -> dict[str, Any]:
    return gate_evidence(
        gate="openshell",
        status="manual_review",
        run_id=run_id,
        source_kind="manual_observation",
        source_path=None,
        command=None,
        exit_code=None,
        risk_level="unknown",
        reasons=["--sandbox-only requires sandbox_mode to be fixture or live."],
    )


def evaluate(args: argparse.Namespace) -> int:
    sandbox_only = bool(getattr(args, "sandbox_only", False))
    config_path = Path(args.config)
    try:
        config = DemoConfig.load(config_path)
    except ConfigValidationError as exc:
        decision = _manual_review_for_invalid_config(config_path, exc.errors)
        _write_invalid_config_decision(decision)
        print(json.dumps(decision, ensure_ascii=False))
        return 2

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    run_id = build_run_id(config_path, config.fixtures, timestamp, _evidence_hash(config))
    scanner_results = run_scanners(config, run_id=run_id)
    artifacts = {
        "decision_json": config.outputs["decision_json"],
        "markdown_summary": config.outputs.get("markdown_summary"),
        "reports": [str(item["source_path"]) for item in scanner_results if item.get("source_path")],
        "logs": [],
        "worker": [],
    }
    static_decision = decide_static_gates(
        scanner_results,
        scanner_mode=config.scanner_mode,
        sandbox_demo_override=config.sandbox_demo_override_enabled,
        request_id=config.request_id,
        run_id=run_id,
        artifacts=artifacts,
        worker_provider=config.worker_provider,
    )

    sandbox_evidence = None
    combined_results = list(scanner_results)
    if sandbox_only and not _sandbox_requested(config) and static_decision.decision != "deny":
        sandbox_evidence = _sandbox_only_missing_evidence(run_id=run_id)
        combined_results = [*scanner_results, sandbox_evidence]
        decision = _manual_review_for_sandbox(static_decision, sandbox_evidence).to_dict()
    elif _sandbox_requested(config) and _can_enter_sandbox(static_decision, config):
        sandbox_evidence = run_sandbox(config, run_id=run_id)
        if sandbox_evidence and sandbox_evidence.get("source_path"):
            artifacts["logs"].append(str(sandbox_evidence["source_path"]))
        combined_results = [*scanner_results, *([sandbox_evidence] if sandbox_evidence else [])]
        if sandbox_evidence and sandbox_evidence.get("status") != "pass" and static_decision.decision != "deny":
            decision = _manual_review_for_sandbox(static_decision, sandbox_evidence).to_dict()
        else:
            decision = decide_static_gates(
                combined_results,
                scanner_mode=config.scanner_mode,
                sandbox_demo_override=config.sandbox_demo_override_enabled,
                request_id=config.request_id,
                run_id=run_id,
                artifacts=artifacts,
                worker_provider=config.worker_provider,
            ).to_dict()
    else:
        decision = static_decision.to_dict()

    if config.worker_provider.enabled and decision["decision"] != "deny":
        agent_invocations, worker_paths = run_worker_provider(
            config.worker_provider,
            request_id=config.request_id,
            run_id=run_id,
            gate_results=combined_results,
            artifacts=artifacts,
        )
        artifacts["worker"] = list(dict.fromkeys([*artifacts.get("worker", []), *worker_paths]))
        decision = decide_static_gates(
            combined_results,
            scanner_mode=config.scanner_mode,
            sandbox_demo_override=config.sandbox_demo_override_enabled,
            request_id=config.request_id,
            run_id=run_id,
            artifacts=artifacts,
            worker_provider=config.worker_provider,
            agent_invocations=agent_invocations,
        ).to_dict()
    _write_decision_artifacts(decision)
    print(json.dumps(decision, ensure_ascii=False))
    return EXIT_CODES[decision["decision"]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chainshield")
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--config", required=True)
    evaluate_parser.add_argument("--sandbox-only", action="store_true")
    evaluate_parser.set_defaults(func=evaluate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
