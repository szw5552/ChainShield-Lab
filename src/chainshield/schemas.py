from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "specs" / "001-orbstack-sandbox-gates" / "contracts"


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    path = CONTRACTS_DIR / name
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _schema_registry() -> Registry:
    resources = []
    for path in CONTRACTS_DIR.glob("*.schema.json"):
        schema = load_schema(path.name)
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        resources.append((path.name, resource))
        if "$id" in schema:
            resources.append((schema["$id"], resource))
            resources.append((schema["$id"].rsplit("/", 1)[-1], resource))
    return Registry().with_resources(resources)


@lru_cache(maxsize=1)
def _format_checker() -> FormatChecker:
    checker = FormatChecker()

    @checker.checks("date-time", raises=ValueError)
    def is_date_time(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None

    return checker


def validator_for(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    return Draft202012Validator(
        schema,
        registry=_schema_registry(),
        format_checker=_format_checker(),
    )


def validate_contract(name: str, instance: Any, *, raise_on_error: bool = True):
    validator = validator_for(name)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors and raise_on_error:
        raise errors[0]
    return errors
