from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import ArtifactWriteError, atomic_write_text, sanitize_text, write_json_artifact
from .config import ConfigValidationError, DemoConfig, build_run_id
from .scanners import run_scanners
from .supervisor import SupervisorDecision, decide_static_gates


def run_sandbox(*args, **kwargs):
    return None


def _safe_outputs_from_raw_config(path: Path) -> dict[str, str | None]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"decision_json": "reports/manual-review-invalid-config.json", "markdown_summary": None}
    outputs = raw.get("outputs") if isinstance(raw, dict) else None
    if not isinstance(outputs, dict):
        return {"decision_json": "reports/manual-review-invalid-config.json", "markdown_summary": None}
    return {
        "decision_json": outputs.get("decision_json") or "reports/manual-review-invalid-config.json",
        "markdown_summary": outputs.get("markdown_summary"),
    }


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


def _evidence_hash(config: DemoConfig) -> str:
    digest = hashlib.sha256()
    for key, value in sorted(config.fixtures.items()):
        digest.update(str(key).encode("utf-8"))
        digest.update(str(value).encode("utf-8"))
        if value and Path(value).exists() and Path(value).is_file():
            digest.update(Path(value).read_bytes())
    return digest.hexdigest()[:16]


def _markdown_summary(decision: dict[str, Any]) -> str:
    lines = [
        f"# ChainShield Decision: {decision['decision']}",
        "",
        f"- Request: `{decision['request_id']}`",
        f"- Run: `{decision['run_id']}`",
        f"- Summary: {decision['summary']}",
        "",
        "## Primary Reasons",
    ]
    lines.extend(f"- {reason}" for reason in decision["primary_reasons"])
    lines.extend(["", "## Gate Evidence"])
    for item in decision["gate_results"]:
        lines.append(f"- {item['gate']}: {item['status']} ({item['risk_level']})")
        lines.extend(f"  - {reason}" for reason in item.get("reasons", []))
    lines.extend(["", "## Next Actions"])
    lines.extend(f"- {action}" for action in decision["next_actions"])
    return "\n".join(lines) + "\n"


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


def evaluate(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    try:
        config = DemoConfig.load(config_path)
    except ConfigValidationError as exc:
        decision = _manual_review_for_invalid_config(config_path, exc.errors)
        output_path = Path(decision["artifacts"]["decision_json"])
        if not output_path.exists():
            try:
                write_json_artifact(output_path, decision)
            except ArtifactWriteError:
                pass
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
    decision = decide_static_gates(
        scanner_results,
        scanner_mode=config.scanner_mode,
        sandbox_demo_override=config.sandbox_demo_override_enabled,
        request_id=config.request_id,
        run_id=run_id,
        artifacts=artifacts,
        worker_provider=config.worker_provider,
    ).to_dict()
    _write_decision_artifacts(decision)

    if args.sandbox_only and decision["decision"] != "deny":
        run_sandbox(config)
    print(json.dumps(decision, ensure_ascii=False))
    return {"allow": 0, "deny": 1, "manual_review": 2}[decision["decision"]]


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
