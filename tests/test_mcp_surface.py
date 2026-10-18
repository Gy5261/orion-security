"""Exercise every exposed tool and a four-mode HTTP matrix with official SDK clients."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]


def decoded(result: Any) -> dict[str, Any]:
    if isinstance(result.structuredContent, dict):
        return result.structuredContent
    for item in result.content:
        if getattr(item, "type", None) == "text":
            data = json.loads(item.text)
            if isinstance(data, dict):
                return data
    raise AssertionError("missing structured result")


def child_environment(root: Path | None = None) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ORION_")}
    environment["PYTHONPATH"] = str(ROOT)
    if root is not None:
        environment["ORION_RESOURCE_ROOT"] = str(root)
    return environment


def test_every_mcp_tool_and_resource_contract(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("synthetic laboratory knowledge", encoding="utf-8")
    (tmp_path / "sample.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    async def scenario() -> None:
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "orion.mcp.server"],
                                            env=child_environment(tmp_path))
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.protocolVersion
                tools = (await session.list_tools()).tools
                assert len(tools) == 13
                assert all(tool.annotations is not None for tool in tools)
                calls = {
                    "orion_mcp_capabilities": {},
                    "orion_client_config": {"client": "generic"},
                    "orion_list_plugins": {"include_health": False},
                    "orion_get_plugin": {"plugin_id": "tls_posture_audit"},
                    "orion_doctor": {},
                    "orion_run_plugin": {"plugin_id": "ioc_enricher", "payload": {"iocs": ["127.0.0.1"]},
                                         "authorization": "MCP-SYNTHETIC-TEST-001"},
                    "orion_search_resources": {"query": "synthetic"},
                    "orion_resource_links": {"query": "README", "limit": 1},
                    "orion_read_resource": {"path": "README.md"},
                    "orion_read_resource_content": {"path": "sample.png"},
                    "orion_control_status": {},
                    "orion_request_review": {"plugin_id": "tls_posture_audit", "payload": {"targets": ["127.0.0.1:8443"]}},
                    "orion_protocol_audit": {},
                }
                assert set(calls) == {tool.name for tool in tools}
                results: dict[str, Any] = {}
                for name, arguments in calls.items():
                    results[name] = await session.call_tool(name, arguments)
                    assert not results[name].isError, (name, results[name])
                assert decoded(results["orion_run_plugin"])["ok"] is True
                assert decoded(results["orion_request_review"])["authorization_granted"] is False
                assert decoded(results["orion_protocol_audit"])["conforms_to_2026_07_28"] is False
                assert decoded(results["orion_read_resource_content"])["encoding"] == "base64"
                links = [item for item in results["orion_resource_links"].content if item.type == "resource_link"]
                assert len(links) == 1 and str(links[0].uri).endswith("README.md")
                for uri in ("orion://manifest", "orion://controls", "orion://mcp/audit",
                            "orion://repository/README.md", "orion://plugins/tls_posture_audit"):
                    assert (await session.read_resource(uri)).contents
                assert len((await session.list_resource_templates()).resourceTemplates) == 2
                assert len((await session.list_prompts()).prompts) == 3
                prompt = await session.get_prompt("controlled_lab_workflow", {"objective": "synthetic test"})
                assert prompt.messages
                for name, arguments in [
                    ("orion_read_resource", {"path": "../outside.txt"}),
                    ("orion_run_plugin", {"plugin_id": "tls_posture_audit", "payload": {"targets": ["127.0.0.1:8443"]},
                                          "authorization": "MCP-SYNTHETIC-TEST-001", "allow_network": True}),
                    ("orion_get_plugin", {"plugin_id": "not-installed"}),
                ]:
                    assert (await session.call_tool(name, arguments)).isError is True
    asyncio.run(scenario())


@pytest.mark.parametrize("stateful", [False, True])
@pytest.mark.parametrize("stream", [False, True])
def test_http_state_and_response_matrix(stateful: bool, stream: bool) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    command = [sys.executable, "-m", "orion.mcp.server", "--transport", "streamable-http", "--port", str(port),
               "--stateful" if stateful else "--stateless", "--stream-response" if stream else "--json-response"]
    process = subprocess.Popen(command, cwd=ROOT, env=child_environment(), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, shell=False)
    try:
        deadline = time.monotonic() + 20
        while True:
            if process.poll() is not None:
                raise AssertionError("MCP matrix server exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError("MCP matrix server startup timed out")
                time.sleep(0.05)

        async def scenario() -> None:
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("orion_control_status", {})
                    assert not result.isError
                    assert decoded(result)["default_network"] == "deny"
        asyncio.run(scenario())
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
