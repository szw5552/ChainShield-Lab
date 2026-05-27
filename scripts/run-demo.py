#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _unique_output_path(path: str, suffix: str) -> str:
    candidate = Path(path)
    return str(candidate.with_name(f"{candidate.stem}-{suffix}{candidate.suffix}"))


def _prepare_runtime_config(config_path: str) -> str:
    path = Path(config_path)
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return config_path

    outputs = config.get("outputs")
    worker_provider = config.get("worker_provider")
    if not isinstance(outputs, dict):
        return config_path

    existing_outputs: list[tuple[dict[str, object], str]] = []
    for key in ("decision_json", "markdown_summary"):
        value = outputs.get(key)
        if isinstance(value, str) and value and Path(value).exists():
            existing_outputs.append((outputs, key))
    if isinstance(worker_provider, dict):
        worker_output = worker_provider.get("output_path")
        if isinstance(worker_output, str) and worker_output and Path(worker_output).exists():
            existing_outputs.append((worker_provider, "output_path"))

    if not existing_outputs:
        return config_path

    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    for section, key in existing_outputs:
        current = section.get(key)
        if isinstance(current, str):
            section[key] = _unique_output_path(current, suffix)

    temp_path = path.with_name(f"{path.stem}-{suffix}{path.suffix}")
    temp_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(temp_path)


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    src = repo_root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))

    from chainshield.cli import main as chainshield_main

    parser = argparse.ArgumentParser(
        prog="run-demo.py",
        description="Run the ChainShield npm supply-chain defense demo with a sanitized config.",
    )
    parser.add_argument("--config", required=True, metavar="PATH", help="Path to a ChainShield demo config JSON file.")
    parser.add_argument(
        "--sandbox-only",
        action="store_true",
        help="Require configured sandbox evidence while preserving static gate safety checks.",
    )
    args = parser.parse_args(argv)

    runtime_config = _prepare_runtime_config(args.config)
    cli_args = ["evaluate", "--config", runtime_config]
    if args.sandbox_only:
        cli_args.append("--sandbox-only")
    return chainshield_main(cli_args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
