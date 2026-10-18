"""Offline repository contracts, independent of the installed checkout revision.

The AST checks flag common unsafe process APIs, including import aliases. They
are a review gate, not a sandbox or a proof that arbitrary Python code is safe.
Development dependencies are required; the ORION runtime itself stays stdlib-only.
"""

from __future__ import annotations

import ast
import json
import math
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
# A direct invocation must inspect this checkout, even with an older wheel installed.
sys.path.insert(0, str(ROOT))

from orion import __version__  # noqa: E402
from orion.plugins.core import PluginRegistry  # noqa: E402
from orion.resources import ResourceCatalog  # noqa: E402

EXPECTED_PLUGINS = {
    "findings_ticket_sync", "ioc_enricher", "tls_posture_audit", "spiderfoot",
    "theharvester", "sherlock", "osint_spy", "phoneinfoga", "photon",
}
FORBIDDEN_CALLS = {
    "os.system", "os.popen", "subprocess.call", "subprocess.check_output",
    "subprocess.getoutput", "subprocess.getstatusoutput", "asyncio.create_subprocess_shell",
}
JSON_ROOTS = ("samples", "skills", "schemas", "evals", "eval-results")
MAX_JSON_BYTES = 1024 * 1024


def dotted_name(node: ast.AST) -> str:
    """Return a syntactic call target without executing source code."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def validate_source_file(path: Path) -> None:
    """Reject shell process calls and missing explicit subprocess boundaries."""
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    aliases = _import_aliases(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        head, separator, tail = name.partition(".")
        name = aliases.get(head, head) + (separator + tail if separator else "")
        location = f"{path}:{node.lineno}"
        if name in FORBIDDEN_CALLS:
            raise AssertionError(f"forbidden process API {name} in {location}")
        if name in {"subprocess.run", "subprocess.Popen"}:
            keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
            shell = keywords.get("shell")
            if not isinstance(shell, ast.Constant) or shell.value is not False:
                raise AssertionError(f"{name} must set shell=False in {location}")
            if name == "subprocess.run":
                timeout = keywords.get("timeout")
                invalid = timeout is None
                if isinstance(timeout, (ast.Constant, ast.UnaryOp)):
                    try:
                        value = ast.literal_eval(timeout)
                    except (ValueError, TypeError):
                        invalid = True
                    else:
                        invalid = (not isinstance(value, (int, float)) or isinstance(value, bool)
                                   or value <= 0 or (isinstance(value, float) and not math.isfinite(value)))
                if invalid:
                    raise AssertionError(f"{name} must set a positive timeout in {location}")


def validate_source(roots: Iterable[Path] | None = None) -> None:
    """Inspect runtime and maintenance tools, including legacy script entry points."""
    for folder in roots if roots is not None else (ROOT / "orion", ROOT / "tools"):
        for path in sorted(folder.rglob("*.py")):
            validate_source_file(path)


def _distinct_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _finite_literal(value: str) -> None:
    raise ValueError(f"nonfinite JSON literal: {value}")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"nonfinite JSON number: {value}")
    return result


def load_json(path: Path) -> Any:
    """Load a bounded JSON asset and reject ambiguous or nonstandard JSON."""
    if path.is_symlink() or not path.is_file():
        raise AssertionError(f"JSON source must be a regular non-symlink file: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise AssertionError(f"JSON file exceeds 1 MiB inspection budget: {path}")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_distinct_keys,
                          parse_constant=_finite_literal, parse_float=_finite_float)
    except (ValueError, UnicodeError) as exc:
        raise AssertionError(f"invalid JSON file {path}: {exc}") from exc


def validate_json_sources(root: Path = ROOT) -> None:
    """Reject duplicate keys and non-finite literals throughout committed fixtures."""
    for folder in JSON_ROOTS:
        for path in sorted((root / folder).rglob("*.json")):
            load_json(path)


def read_project(root: Path = ROOT) -> dict[str, Any]:
    """Read standard TOML; Python 3.10 uses the development-only tomli backport."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib
    with (root / "pyproject.toml").open("rb") as handle:
        return dict(tomllib.load(handle)["project"])


def validate_project(root: Path = ROOT) -> None:
    """Make release metadata, public entry points, and runtime identity agree."""
    project = read_project(root)
    registry = PluginRegistry(load_external=False)
    runtime = registry.manifest()["runtime"]
    if project["version"] != __version__:
        raise AssertionError("pyproject.toml version differs from orion.__version__")
    if project["name"] != runtime["name"]:
        raise AssertionError("distribution name differs from runtime identity")
    if project["requires-python"] != f">={runtime['minimum_python']}":
        raise AssertionError("Python installation floor differs from the runtime manifest")
    if project.get("dependencies") != []:
        raise AssertionError("the base runtime must remain free of third-party dependencies")
    expected = {plugin.metadata.plugin_id: f"{type(plugin).__module__}:{type(plugin).__qualname__}"
                for plugin in registry.list()}
    declared = project.get("entry-points", {}).get(registry.ENTRY_POINT_GROUP, {})
    if declared != expected:
        raise AssertionError("pyproject plugin entry points differ from the registered built-ins")
    scripts = {"orion": "orion.cli:main", "orion-mcp": "orion.mcp.server:main"}
    if project.get("scripts") != scripts:
        raise AssertionError("console entry points differ from the public CLI contract")
    extras = project.get("optional-dependencies", {})
    if not extras.get("mcp") or extras.get("all") != extras["mcp"]:
        raise AssertionError("mcp and all extras must expose the same optional SDK dependency")


def validate_plugins() -> None:
    """Keep built-in discovery deterministic and optional tools optional."""
    registry = PluginRegistry(load_external=False)
    identifiers = {plugin.metadata.plugin_id for plugin in registry.list()}
    if identifiers != EXPECTED_PLUGINS:
        raise AssertionError(f"plugin set mismatch: {sorted(identifiers)}")
    if registry.discovery_errors:
        raise AssertionError(f"plugin discovery errors: {registry.discovery_errors}")
    for plugin in registry.list():
        metadata = plugin.metadata
        if metadata.requires_authorization is not True:
            raise AssertionError(f"authorization must be enabled: {metadata.plugin_id}")
        if metadata.integration == "subprocess" and not metadata.homepage:
            raise AssertionError(f"external adapter missing homepage: {metadata.plugin_id}")


def validate_manifest(root: Path = ROOT) -> None:
    """Validate the published schema and compare every contract field, not just IDs."""
    from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

    schema = load_json(root / "skills" / "plugin.schema.json")
    static = load_json(root / "skills" / "skills.json")
    runtime = PluginRegistry(load_external=False).manifest()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(static)
    validator.validate(runtime)
    runtime["runtime"]["python_runtime"] = "not_recorded_static_catalog"
    if static != runtime:
        raise AssertionError("skills/skills.json differs from runtime metadata or schemas; regenerate the static catalog")
    for plugin in runtime["plugins"]:
        for name in ("input_schema", "output_schema"):
            Draft202012Validator.check_schema(plugin[name])


def validate_resources(root: Path = ROOT) -> None:
    """Check catalog availability and the public traversal boundary without I/O effects."""
    catalog = ResourceCatalog(root)
    if len(catalog.index()["resources"]) < 10:
        raise AssertionError("MCP resource catalog is unexpectedly small")
    try:
        catalog.read("../outside.txt")
    except ValueError:
        return
    raise AssertionError("resource catalog allowed path traversal")


def main() -> int:
    validate_source()
    validate_json_sources()
    validate_project()
    validate_plugins()
    validate_manifest()
    validate_resources()
    print("ORION repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
