from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .artifacts import ArtifactWriteError, write_json_artifact
from .config import ConfigValidationError, DemoConfig
from .supervisor import SupervisorDecision


def run_scanners(*args, **kwargs):
    return []


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

    scanner_results = run_scanners(config)
    if args.sandbox_only:
        run_sandbox(config)
    print(json.dumps({"request_id": config.request_id, "scanner_results": scanner_results}, ensure_ascii=False))
    return 0


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
