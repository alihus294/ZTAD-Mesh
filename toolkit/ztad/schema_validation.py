from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .errors import ConfigurationError
from .util import load_data


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[str]:
    """Validate an instance with Draft 2020-12 and return stable, reviewable errors."""
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
    except SchemaError as exc:
        raise ConfigurationError(f"Invalid JSON Schema: {exc.message}") from exc
    errors: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=lambda item: (list(item.absolute_path), item.message)):
        location = "/".join(str(part) for part in error.absolute_path) or "$"
        errors.append(f"{location}: {error.message}")
    return errors


def _strict_model_schema_errors(value: Any, *, path: str = "$") -> list[str]:
    """Return violations of the strict structured-output object contract.

    Model-facing object schemas must be closed and must list every declared
    property in ``required``. Optional values are represented as nullable fields,
    not omitted properties. The walk intentionally follows every alternative so
    an object hidden inside anyOf/oneOf/allOf cannot bypass the rule.
    """
    errors: list[str] = []
    if isinstance(value, dict):
        raw_type = value.get("type")
        types = {raw_type} if isinstance(raw_type, str) else set(raw_type or []) if isinstance(raw_type, list) else set()
        has_object_shape = "object" in types or "properties" in value
        if has_object_shape:
            if value.get("additionalProperties") is not False:
                errors.append(f"{path}: object schema must set additionalProperties=false")
            properties = value.get("properties", {})
            if not isinstance(properties, dict):
                errors.append(f"{path}: object properties must be an object")
            else:
                required = value.get("required")
                if not isinstance(required, list):
                    errors.append(f"{path}: strict object schema must declare required")
                else:
                    missing = sorted(set(properties) - {str(item) for item in required})
                    if missing:
                        errors.append(f"{path}: strict object properties missing from required: {', '.join(missing)}")
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                errors.extend(_strict_model_schema_errors(child, path=f"{path}/{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                errors.extend(_strict_model_schema_errors(child, path=f"{path}/{index}"))
    return errors


def validate_strict_model_schema(schema: dict[str, Any]) -> list[str]:
    """Validate JSON Schema syntax plus strict model structured-output rules."""
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise ConfigurationError(f"Invalid JSON Schema: {exc.message}") from exc
    return _strict_model_schema_errors(schema)


def load_strict_model_schema(schema_path: Path) -> dict[str, Any]:
    schema = load_data(schema_path)
    if not isinstance(schema, dict):
        raise ConfigurationError(f"Schema must be an object: {schema_path}")
    errors = validate_strict_model_schema(schema)
    if errors:
        raise ConfigurationError("Invalid strict model output schema: " + "; ".join(errors))
    return schema


def validate_file(instance_path: Path, schema_path: Path) -> list[str]:
    instance = load_data(instance_path)
    schema = load_data(schema_path)
    if not isinstance(schema, dict):
        raise ConfigurationError(f"Schema must be an object: {schema_path}")
    return validate_instance(instance, schema)
