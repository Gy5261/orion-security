"""Verify a distribution from an unrelated directory using its installed entry points.

Invoke with the target environment's Python and -I. No development dependencies,
network access, third-party executables, or checkout imports are needed.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import importlib.util
import json
import os
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

REQUIRED_RESOURCES = {
    "SKILL.md", "ARCHITECTURE.md", "references/00-index.md",
    "playbooks/01-authorized-assessment-playbook.md",
    "scripts/install-safe-tooling.sh", "scripts/install-safe-tooling.ps1",
}


def _command(executable: str, *arguments: str) -> dict[str, Any]:
    suffix = ".exe" if os.name == "nt" else ""
    command = str(Path(sysconfig.get_path("scripts")) / f"{executable}{suffix}")
    result = subprocess.run([command, *arguments], shell=False, check=True, capture_output=True,
                            text=True, encoding="utf-8", timeout=30)
    return dict(json.loads(result.stdout))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-mcp", choices=("absent", "present"), required=True)
    arguments = parser.parse_args()
    if not sys.flags.isolated:
        raise RuntimeError("run this check with python -I to exclude checkout and PYTHONPATH imports")
    for name in tuple(os.environ):
        if name.startswith("ORION_"):
            del os.environ[name]

    import orion
    from orion.plugins.core import PluginRegistry
    from orion.resources import ResourceCatalog

    distribution = importlib.metadata.distribution("orion-hacking-etico")
    installed_root = Path(str(distribution.locate_file("orion/__init__.py"))).resolve().parent
    assert Path(orion.__file__).resolve().parent == installed_root, "import is outside the installed distribution"
    assert distribution.version == orion.__version__, "distribution and runtime versions disagree"
    assert installed_root.is_relative_to(Path(sys.prefix).resolve()), "import escaped the target virtual environment"
    present = importlib.util.find_spec("mcp") is not None
    assert present is (arguments.expect_mcp == "present"), "MCP extra is not in the expected installation state"

    previous_directory = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="orion-package-smoke-") as working:
        os.chdir(working)
        try:
            # A repository-shaped current directory must never become a published root.
            Path("orion").mkdir()
            Path("README.md").write_text("PRIVATE WORKING DIRECTORY", encoding="utf-8")
            os.environ["ORION_AUDIT_DATABASE"] = str(Path(working) / "audit.sqlite3")
            catalog = ResourceCatalog()
            assert catalog.root == installed_root, "installed catalog adopted an unrelated working directory"
            paths = {resource.path for resource in catalog.list()}
            assert REQUIRED_RESOURCES <= paths, f"missing packaged resources: {sorted(REQUIRED_RESOURCES - paths)}"
            assert "PRIVATE WORKING DIRECTORY" not in catalog.read("SKILL.md")
            for path in REQUIRED_RESOURCES:
                assert catalog.read(path).strip(), f"empty resource: {path}"

            doctor = _command("orion", "plugins", "doctor")
            assert doctor["ok"] is True and doctor["plugin_count"] == 9, doctor
            manifest = _command("orion", "plugins", "list", "--json")
            assert manifest == PluginRegistry(load_external=False).manifest()
            config = _command("orion-mcp", "--transport", "stdio", "--print-config")
            assert config["transport"] == "stdio", config

            request = Path(working) / "request.json"
            request.write_text('{"iocs": ["198.51.100.4", "example.invalid"], "external_sources": false}',
                               encoding="utf-8")
            result = _command("orion", "plugins", "run", "ioc_enricher", "--input", str(request),
                              "--authorization", "PACKAGE-SMOKE-OFFLINE-001")
            assert result["ok"] is True and result["data"]["count"] == 2, result
            assert all(item["local"]["dns_performed"] is False for item in result["data"]["items"])

            if present:
                from orion.mcp.server import build_server

                server = build_server()
                tools = asyncio.run(server.list_tools())
                assert "orion_run_plugin" in {tool.name for tool in tools}
            print(json.dumps({"package": distribution.metadata["Name"], "version": distribution.version,
                              "python": sys.version.split()[0], "mcp": arguments.expect_mcp,
                              "pip": importlib.metadata.version("pip"),
                              "catalog_resources": len(paths), "offline_iocs": result["data"]["count"]}))
        finally:
            os.chdir(previous_directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
