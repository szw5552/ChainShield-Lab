from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, RefResolver

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_DIR = REPO_ROOT / "specs" / "001-orbstack-sandbox-gates" / "contracts"


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    path = CONTRACTS_DIR / name
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _schema_store() -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = {}
    for path in CONTRACTS_DIR.glob("*.schema.json"):
        schema = load_schema(path.name)
        store[path.name] = schema
        if "$id" in schema:
            store[schema["$id"]] = schema
            store[schema["$id"].rsplit("/", 1)[-1]] = schema
    return store


def validator_for(name: str) -> Draft202012Validator:
    schema = load_schema(name)
    resolver = RefResolver.from_schema(schema, store=_schema_store())
    return Draft202012Validator(schema, resolver=resolver)


def validate_contract(name: str, instance: Any, *, raise_on_error: bool = True):
    validator = validator_for(name)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors and raise_on_error:
        raise errors[0]
    return errors
