"""Offline release regressions: drifted contracts must fail before publication."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from orion import __version__
from orion.plugins.core import PluginRegistry
from tools import validate_repository as validation


@pytest.mark.parametrize("source", [
    "import os as process; process.system('unsafe')",
    "from os import popen as execute; execute('unsafe')",
    "from subprocess import getoutput as output; output('unsafe')",
    "import asyncio as aio; aio.create_subprocess_shell('unsafe')",
    "import subprocess as process; process.run(['tool'], shell=True, timeout=1)",
    "from subprocess import Popen as start; start(['tool'])",
    "from subprocess import run as execute; execute(['tool'], timeout=1)",
])
def test_source_gate_cannot_be_bypassed_by_import_aliases(tmp_path: Path, source: str) -> None:
    path = tmp_path / "adapter.py"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="forbidden process API|shell=False"):
        validation.validate_source_file(path)


@pytest.mark.parametrize("timeout", ["", ", timeout=None", ", timeout=True", ", timeout=0",
                                    ", timeout=-1", ", timeout=1e999", ", timeout='forever'"])
def test_source_gate_rejects_missing_or_invalid_timeout(tmp_path: Path, timeout: str) -> None:
    path = tmp_path / "adapter.py"
    path.write_text(f"from subprocess import run as execute\nexecute(['tool'], shell=False{timeout})\n",
                    encoding="utf-8")
    with pytest.raises(AssertionError, match="positive timeout"):
        validation.validate_source_file(path)


def test_source_gate_accepts_explicit_process_boundaries(tmp_path: Path) -> None:
    path = tmp_path / "adapter.py"
    path.write_text("from subprocess import run as execute\nexecute(['tool'], shell=False, timeout=4)\n",
                    encoding="utf-8")
    validation.validate_source_file(path)


@pytest.mark.parametrize("content", ['{"a": 1, "a": 2}', '{"nested": {"a": 1, "a": 2}}',
                                    '{"n": NaN}', '{"n": Infinity}', '{"n": -Infinity}',
                                    '{"n": 1e9999}'])
def test_json_gate_rejects_ambiguous_and_nonfinite_assets(tmp_path: Path, content: str) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(AssertionError, match="invalid JSON file"):
        validation.load_json(path)


def test_json_gate_limits_inspection_bytes(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (validation.MAX_JSON_BYTES + 1))
    with pytest.raises(AssertionError, match="inspection budget"):
        validation.load_json(path)


def _write_manifest_fixture(root: Path, manifest: dict[str, Any]) -> None:
    (root / "skills").mkdir(exist_ok=True)
    (root / "skills" / "skills.json").write_text(json.dumps(manifest), encoding="utf-8")
    schema = (validation.ROOT / "skills" / "plugin.schema.json").read_text(encoding="utf-8")
    (root / "skills" / "plugin.schema.json").write_text(schema, encoding="utf-8")


def _static_manifest() -> dict[str, Any]:
    manifest = PluginRegistry(load_external=False).manifest()
    manifest["runtime"]["python_runtime"] = "not_recorded_static_catalog"
    return manifest


@pytest.mark.parametrize("field", ["requires_authorization", "network_access", "side_effects"])
def test_manifest_gate_detects_permission_drift_with_same_ids(tmp_path: Path, field: str) -> None:
    manifest = _static_manifest()
    manifest["plugins"][0][field] = not manifest["plugins"][0][field]
    _write_manifest_fixture(tmp_path, manifest)
    with pytest.raises(AssertionError, match="metadata or schemas"):
        validation.validate_manifest(tmp_path)


def test_manifest_gate_detects_schema_drift_with_same_version(tmp_path: Path) -> None:
    manifest = _static_manifest()
    manifest["plugins"][0]["input_schema"]["properties"]["unexpected"] = {"type": "string"}
    _write_manifest_fixture(tmp_path, manifest)
    with pytest.raises(AssertionError, match="metadata or schemas"):
        validation.validate_manifest(tmp_path)


def test_manifest_gate_accepts_complete_portable_runtime_catalog(tmp_path: Path) -> None:
    _write_manifest_fixture(tmp_path, _static_manifest())
    validation.validate_manifest(tmp_path)


def test_manifest_gate_rejects_host_specific_python_version(tmp_path: Path) -> None:
    manifest = _static_manifest()
    manifest["runtime"]["python_runtime"] = "3.12.0"
    _write_manifest_fixture(tmp_path, manifest)
    with pytest.raises(AssertionError, match="metadata or schemas"):
        validation.validate_manifest(tmp_path)


def test_project_gate_rejects_exporting_a_different_callable(monkeypatch: pytest.MonkeyPatch) -> None:
    project = copy.deepcopy(validation.read_project())
    project["version"] = __version__
    project["entry-points"]["orion.plugins"]["ioc_enricher"] = "orion.plugins.osint:PhotonPlugin"
    monkeypatch.setattr(validation, "read_project", lambda root: project)
    with pytest.raises(AssertionError, match="entry points"):
        validation.validate_project()


def test_project_gate_rejects_a_silent_python_floor_change(monkeypatch: pytest.MonkeyPatch) -> None:
    project = copy.deepcopy(validation.read_project())
    project["version"] = __version__
    project["requires-python"] = ">=3.12"
    monkeypatch.setattr(validation, "read_project", lambda root: project)
    with pytest.raises(AssertionError, match="installation floor"):
        validation.validate_project()
