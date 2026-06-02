"""VerificationResult construction and JSON Schema validation."""

from __future__ import annotations

import copy
import json
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    with (SCHEMA_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _schema_registry() -> Registry:
    registry = Registry()
    for path in SCHEMA_DIR.glob("*.schema.json"):
        schema = load_schema(path.name)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def validate_with_schema(instance: Any, schema_name: str) -> None:
    schema = load_schema(schema_name)
    Draft202012Validator(schema, registry=_schema_registry()).validate(instance)


def validate_verification_result(result: dict[str, Any]) -> None:
    validate_with_schema(result, "verification_result.schema.json")


def build_verification_result(
    component: dict[str, Any],
    vulnerability: dict[str, Any],
    verdict: dict[str, Any],
    evidence: list[dict[str, Any]],
    risk_factors: dict[str, Any],
    recommended_actions: list[dict[str, Any]],
    project_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and validate a VerificationResult without inferring verdict fields."""

    result = {
        "analysis_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "component": copy.deepcopy(component),
        "vulnerability": copy.deepcopy(vulnerability),
        "project_context": copy.deepcopy(project_context),
        "verdict": copy.deepcopy(verdict),
        "evidence": copy.deepcopy(evidence),
        "risk_factors": copy.deepcopy(risk_factors),
        "recommended_actions": copy.deepcopy(recommended_actions),
    }
    validate_verification_result(result)
    return result
