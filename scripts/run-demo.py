#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


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

    cli_args = ["evaluate", "--config", args.config]
    if args.sandbox_only:
        cli_args.append("--sandbox-only")
    return chainshield_main(cli_args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
