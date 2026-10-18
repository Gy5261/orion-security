"""Bounded validation for the explicitly supported ORION schema vocabulary."""

from __future__ import annotations

import math
import re
from typing import Any, Mapping

from orion.jsonio import canonical_json

from .errors import InputValidationError

_JSON_TYPES: dict[str, type[Any] | tuple[type[Any], ...]] = {
    "object": dict, "array": list, "string": str, "integer": int,
    "number": (int, float), "boolean": bool, "null": type(None),
}

_SCHEMA_KEYWORDS = {
    "type", "oneOf", "anyOf", "allOf", "not", "const", "enum", "properties", "required",
    "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength",
    "pattern", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minProperties", "maxProperties",
    "$schema", "$id", "$comment", "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly",
}


def _is_type(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _JSON_TYPES[expected])


def _json_equal(left: Any, right: Any) -> bool:
    """Use JSON scalar identity; Python treats True == 1, but JSON does not."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_json_equal(left[k], right[k]) for k in left)
    return bool(left == right)


def _json_identity(value: Any) -> Any:
    """A hashable JSON identity with numbers equivalent and booleans distinct."""
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, (int, float)):
        return ("number", value)
    if isinstance(value, list):
        return ("array", tuple(_json_identity(item) for item in value))
    if isinstance(value, dict):
        return ("object", tuple((key, _json_identity(item)) for key, item in sorted(value.items())))
    return (type(value).__name__, value)


def validate_json_schema(value: Any, schema: Mapping[str, Any] | bool, path: str = "$") -> None:
    """Validate bounded JSON against ORION's supported schema vocabulary.

    Unsupported assertion keywords fail closed; this is intentionally not a
    general-purpose JSON Schema 2020-12 implementation.
    """
    try:
        canonical_json(value)
        canonical_json(dict(schema) if isinstance(schema, Mapping) else schema)
    except ValueError as exc:
        raise InputValidationError(f"{path}: {exc}") from exc
    _validate_schema_definition(schema, path)
    _validate_schema_node(value, schema, path)


def _validate_schema_definition(schema: Mapping[str, Any] | bool, path: str) -> None:
    """Check every branch before evaluation, including unused anyOf/not branches."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, Mapping):
        raise InputValidationError(f"{path}: schema must be an object or boolean")
    unknown = set(schema) - _SCHEMA_KEYWORDS
    if unknown:
        raise InputValidationError(f"{path}: unsupported schema keywords: {sorted(unknown)}")
    if "type" in schema:
        expected = schema["type"]
        types = [expected] if isinstance(expected, str) else expected
        if (not isinstance(types, list) or not types
                or any(not isinstance(item, str) or item not in _JSON_TYPES for item in types)
                or len(set(types)) != len(types)):
            raise InputValidationError(f"{path}: invalid schema type declaration")
    for keyword in ("oneOf", "anyOf", "allOf"):
        if keyword in schema:
            choices = schema[keyword]
            if not isinstance(choices, list) or not choices:
                raise InputValidationError(f"{path}: {keyword} must contain schemas")
            for index, candidate in enumerate(choices):
                _validate_schema_definition(candidate, f"{path}.{keyword}[{index}]")
    for keyword in ("not", "items", "additionalProperties"):
        if keyword in schema:
            _validate_schema_definition(schema[keyword], f"{path}.{keyword}")
    if "properties" in schema:
        properties = schema["properties"]
        if not isinstance(properties, Mapping):
            raise InputValidationError(f"{path}: properties must be an object")
        for key, candidate in properties.items():
            _validate_schema_definition(candidate, f"{path}.properties.{key}")
    if "required" in schema:
        required = schema["required"]
        if (not isinstance(required, list) or any(not isinstance(item, str) for item in required)
                or len(set(required)) != len(required)):
            raise InputValidationError(f"{path}: required must contain unique property names")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise InputValidationError(f"{path}: enum must be a nonempty array")
    for keyword in ("minItems", "maxItems", "minLength", "maxLength", "minProperties", "maxProperties"):
        if keyword in schema and (type(schema[keyword]) is not int or schema[keyword] < 0):
            raise InputValidationError(f"{path}: {keyword} must be a nonnegative integer")
    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        if keyword in schema and type(schema[keyword]) not in {int, float}:
            raise InputValidationError(f"{path}: {keyword} must be a finite number")
    if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
        raise InputValidationError(f"{path}: uniqueItems must be boolean")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            raise InputValidationError(f"{path}: pattern must be a regular expression string")
        try:
            re.compile(schema["pattern"])
        except re.error as exc:
            raise InputValidationError(f"{path}: pattern is not a valid regular expression") from exc


def _validate_schema_node(value: Any, schema: Mapping[str, Any] | bool, path: str) -> None:
    if isinstance(schema, bool):
        if not schema:
            raise InputValidationError(f"{path}: schema does not permit this value")
        return
    if not isinstance(schema, Mapping):
        raise InputValidationError(f"{path}: schema must be an object or boolean")
    if isinstance(value, float) and not math.isfinite(value):
        raise InputValidationError(f"{path}: numbers must be finite")
    if "oneOf" in schema:
        successes = 0
        errors: list[str] = []
        for candidate in schema["oneOf"]:
            try:
                _validate_schema_node(value, candidate, path)
                successes += 1
            except InputValidationError as exc:
                errors.append(str(exc))
        if successes != 1:
            raise InputValidationError(f"{path}: expected exactly one oneOf match; matches={successes}; details={errors[:3]}")
    if "anyOf" in schema:
        errors = []
        for candidate in schema["anyOf"]:
            try:
                _validate_schema_node(value, candidate, path)
                break
            except InputValidationError as exc:
                errors.append(str(exc))
        else:
            raise InputValidationError(f"{path}: no anyOf variant matched; details={errors[:3]}")
    for candidate in schema.get("allOf", []):
        _validate_schema_node(value, candidate, path)
    if "not" in schema:
        try:
            _validate_schema_node(value, schema["not"], path)
        except InputValidationError:
            pass
        else:
            raise InputValidationError(f"{path}: value matches a forbidden schema")
    expected = schema.get("type")
    if expected:
        expected_types = [expected] if isinstance(expected, str) else list(expected)
        unknown = [item for item in expected_types if item not in _JSON_TYPES]
        if unknown:
            raise InputValidationError(f"{path}: unsupported schema types: {unknown}")
        if not any(_is_type(value, item) for item in expected_types):
            raise InputValidationError(f"{path}: expected {expected_types}, received {type(value).__name__}")
    if "const" in schema and not _json_equal(value, schema["const"]):
        raise InputValidationError(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
        raise InputValidationError(f"{path}: value is outside the allowed enum")
    if isinstance(value, dict):
        missing = [key for key in schema.get("required", []) if key not in value]
        if missing:
            raise InputValidationError(f"{path}: missing required fields {missing}")
        properties: Mapping[str, Any] = schema.get("properties", {})
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            raise InputValidationError(f"{path}: too few object properties")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            raise InputValidationError(f"{path}: too many object properties")
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(value) - set(properties))
            if unexpected:
                raise InputValidationError(f"{path}: unknown fields {unexpected}")
        for key, child_schema in properties.items():
            if key in value:
                _validate_schema_node(value[key], child_schema, f"{path}.{key}")
        additional = schema.get("additionalProperties")
        if isinstance(additional, Mapping):
            for key in set(value) - set(properties):
                _validate_schema_node(value[key], additional, f"{path}.{key}")
    if isinstance(value, list):
        if schema.get("minItems") is not None and len(value) < schema["minItems"]:
            raise InputValidationError(f"{path}: requires at least {schema['minItems']} items")
        if schema.get("maxItems") is not None and len(value) > schema["maxItems"]:
            raise InputValidationError(f"{path}: allows at most {schema['maxItems']} items")
        if schema.get("uniqueItems"):
            rendered = [_json_identity(item) for item in value]
            if len(set(rendered)) != len(rendered):
                raise InputValidationError(f"{path}: duplicate items are not allowed")
        if "items" in schema:
            for index, item in enumerate(value):
                _validate_schema_node(item, schema["items"], f"{path}[{index}]")
    if isinstance(value, str):
        if schema.get("minLength") is not None and len(value) < schema["minLength"]:
            raise InputValidationError(f"{path}: minimum length is {schema['minLength']}")
        if schema.get("maxLength") is not None and len(value) > schema["maxLength"]:
            raise InputValidationError(f"{path}: maximum length is {schema['maxLength']}")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            raise InputValidationError(f"{path}: value does not match the required pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if schema.get("minimum") is not None and value < schema["minimum"]:
            raise InputValidationError(f"{path}: must be >= {schema['minimum']}")
        if schema.get("exclusiveMinimum") is not None and value <= schema["exclusiveMinimum"]:
            raise InputValidationError(f"{path}: must be > {schema['exclusiveMinimum']}")
        if schema.get("maximum") is not None and value > schema["maximum"]:
            raise InputValidationError(f"{path}: must be <= {schema['maximum']}")
        if schema.get("exclusiveMaximum") is not None and value >= schema["exclusiveMaximum"]:
            raise InputValidationError(f"{path}: must be < {schema['exclusiveMaximum']}")


