"""One bounded JSON contract for files, CLI requests, approvals and plugins.

The limits apply before serialization as well as after parsing. In particular,
repeating a large string many times cannot make the encoder allocate an
unbounded intermediate document. This module has no plugin or MCP dependency.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, BinaryIO

from orion.fileio import open_regular

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_NODES = 20_000
MAX_INTEGER_DIGITS = 1024


def _check_limit(max_bytes: int) -> None:
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * MAX_DOCUMENT_BYTES:
        raise ValueError("JSON byte limit must be between 1 byte and 16 MiB")


def _validate_tree(value: Any, max_bytes: int) -> None:
    pending = [(value, 0)]
    nodes = 0
    string_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ValueError("JSON nesting or item budget exceeded")
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, str):
            if len(item) > max_bytes:
                raise ValueError("JSON string budget exceeded")
            try:
                string_bytes += len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise ValueError("JSON strings must contain valid Unicode scalar values") from exc
            if string_bytes > max_bytes:
                raise ValueError("JSON document exceeds byte limit")
        elif isinstance(item, int):
            # Reject pathological Python integers before converting them to text.
            if item.bit_length() > MAX_INTEGER_DIGITS * 4 or len(str(abs(item))) > MAX_INTEGER_DIGITS:
                raise ValueError("JSON integer exceeds digit limit")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
        elif isinstance(item, dict):
            if len(item) * 2 + nodes + len(pending) > MAX_NODES:
                raise ValueError("JSON item budget exceeded")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) + nodes + len(pending) > MAX_NODES:
                raise ValueError("JSON item budget exceeded")
            pending.extend((child, depth + 1) for child in item)
        else:
            raise ValueError("value is not JSON-compatible")


def canonical_json(value: Any, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> str:
    """Return sorted compact UTF-8 JSON within byte, depth and node budgets."""
    _check_limit(max_bytes)
    _validate_tree(value, max_bytes)
    chunks: list[str] = []
    size = 0
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for chunk in encoder.iterencode(value):
        size += len(chunk.encode("utf-8"))
        if size > max_bytes:
            raise ValueError("JSON document exceeds byte limit")
        chunks.append(chunk)
    return "".join(chunks)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError("non-finite JSON constant is not allowed")


def _parse_integer(value: str) -> int:
    if len(value.lstrip("-")) > MAX_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds digit limit")
    return int(value)


def loads_json(raw: str | bytes, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Parse UTF-8 JSON, rejecting duplicate keys, NaN, overflow and deep trees."""
    _check_limit(max_bytes)
    if not isinstance(raw, (str, bytes)):
        raise ValueError("JSON input must be UTF-8 text or bytes")
    if len(raw) > max_bytes:
        raise ValueError("JSON input exceeds byte limit")
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        if len(text.encode("utf-8")) > max_bytes:
            raise ValueError("JSON input exceeds byte limit")
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_int=_parse_integer)
        canonical_json(value, max_bytes=max_bytes)
    except RecursionError as exc:
        raise ValueError("JSON nesting budget exceeded") from exc
    except UnicodeError as exc:
        raise ValueError("JSON input must be valid UTF-8") from exc
    return value


def read_json(stream: BinaryIO, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Read at most the allowed bytes plus one overflow sentinel from a stream."""
    _check_limit(max_bytes)
    return loads_json(stream.read(max_bytes + 1), max_bytes=max_bytes)


def read_json_file(path: str | Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Read a regular local JSON file without following a final symbolic link."""
    _check_limit(max_bytes)
    with open_regular(path) as handle:
        return read_json(handle, max_bytes=max_bytes)
