"""Schema, search and documentation checks; synthetic input only."""
from __future__ import annotations

from pathlib import Path

import pytest

from orion.plugins.core import InputValidationError, PluginMetadata, validate_json_schema
from orion.resources import ResourceCatalog
from orion.scripts import expand_markdown_docs


@pytest.mark.parametrize(("value", "schema"), [
    (True, {"const": 1}),
    (1, {"const": True}),
    (True, {"enum": [1, 2]}),
    (1, {"enum": [True, False]}),
    ({"enabled": True}, {"const": {"enabled": 1}}),
    ([True, 1], {"const": [1, True]}),
])
def test_schema_does_not_equate_boolean_with_integer(value: object, schema: dict) -> None:
    with pytest.raises(InputValidationError):
        validate_json_schema(value, schema)


def test_schema_keeps_json_numeric_equivalence() -> None:
    validate_json_schema(1, {"const": 1.0})
    validate_json_schema(1.0, {"enum": [1]})


def test_plugin_metadata_rejects_boolean_timeouts() -> None:
    kwargs = dict(plugin_id="demo_plugin", name="Demo", version="1.0.0",
                  category="test", description="Synthetic test", risk_level="low",
                  capabilities=("test",), input_schema={"type": "object"}, output_schema={"type": "object"})
    with pytest.raises(ValueError):
        PluginMetadata(**kwargs, default_timeout_seconds=True)  # type: ignore[arg-type]


def test_search_prioritizes_path_matches(tmp_path: Path) -> None:
    (tmp_path / "keyword.md").write_text("nothing else", encoding="utf-8")
    (tmp_path / "other.md").write_text("the keyword occurs here", encoding="utf-8")
    catalog = ResourceCatalog(tmp_path)
    found = catalog.search("keyword", limit=2)
    assert [item["path"] for item in found] == ["keyword.md", "other.md"]


@pytest.mark.parametrize("limit", [0, True, -1, 101])
def test_search_rejects_invalid_limits(tmp_path: Path, limit: object) -> None:
    catalog = ResourceCatalog(tmp_path)
    with pytest.raises(ValueError, match="limit"):
        catalog.search("safe", limit=limit)  # type: ignore[arg-type]


def test_historical_expander_only_reports_generated_content(tmp_path: Path) -> None:
    doc = tmp_path / "README.md"
    original = "# Source\n\n<!-- ORION-EXPANSION-2026-04-05 -->\nExample not verified\n"
    doc.write_text(original, encoding="utf-8")
    result = expand_markdown_docs.inventory(tmp_path)
    assert result["documents_with_generated_sections"] == 1
    assert result["expansion_disabled"] is True
    assert doc.read_text(encoding="utf-8") == original
    with pytest.raises(PermissionError):
        expand_markdown_docs.expand(doc, tmp_path)
