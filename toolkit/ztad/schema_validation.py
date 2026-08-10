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


def validate_file(instance_path: Path, schema_path: Path) -> list[str]:
    instance = load_data(instance_path)
    schema = load_data(schema_path)
    if not isinstance(schema, dict):
        raise ConfigurationError(f"Schema must be an object: {schema_path}")
    return validate_instance(instance, schema)
