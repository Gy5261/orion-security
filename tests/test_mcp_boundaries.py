"""MCP schemas, error privacy, bounded workers and real SDK ASGI integration."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from orion.mcp.boundary import CallbackRunner, ResponseLimitError, ServerBusyError, bound_response
from orion.mcp.compat import McpServerConfig
from orion.mcp.server import build_http_app, build_server
from orion.plugins.execution import check_execution
from orion.resources import ResourceCatalog


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    (tmp_path / "README.md").write_text("Synthetic public resource.", encoding="utf-8")
    monkeypatch.setenv("ORION_RESOURCE_ROOT", str(tmp_path))
    return build_server()


@pytest.mark.parametrize("arguments", [
    {"include_health": "true"}, {"include_health": 1},
    {"include_health": None}, {"unknown_option": "private request value"},
])
def test_tool_arguments_are_validated_before_sdk_coercion(server: Any, arguments: dict[str, Any]) -> None:
    result = asyncio.run(server.call_tool("orion_list_plugins", arguments))
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "invalid_arguments"
    assert "private request value" not in result.model_dump_json()


@pytest.mark.parametrize("name,arguments", [
    ("orion_run_plugin", {"plugin_id": "ioc_enricher", "payload": '{"iocs":["127.0.0.1"]}',
                          "authorization": "SYNTHETIC-REVIEW-001"}),
    ("orion_run_plugin", {"plugin_id": "ioc_enricher", "payload": {"iocs": ["127.0.0.1"]},
                          "authorization": "SYNTHETIC-REVIEW-001", "allow_network": 1}),
    ("orion_resource_links", {"limit": True}),
    ("orion_resource_links", {"limit": 0}),
    ("orion_search_resources", {"query": "x" * 513}),
    ("orion_read_resource", {"path": "x" * 4097}),
    ("orion_run_plugin", {"plugin_id": "ioc_enricher", "payload": {"iocs": ["127.0.0.1"]},
                          "authorization": "SYNTHETIC-REVIEW-001", "timeout_seconds": float("nan")}),
])
def test_invalid_bounded_inputs_return_tool_errors(server: Any, name: str, arguments: dict[str, Any]) -> None:
    result = asyncio.run(server.call_tool(name, arguments))
    assert result.isError is True
    assert result.structuredContent["error"]["code"] == "invalid_arguments"


def test_discovery_advertises_enforced_schemas(server: Any) -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert len(tools) == 13
    assert all(tool.inputSchema["additionalProperties"] is False for tool in tools.values())
    assert tools["orion_run_plugin"].inputSchema["properties"]["allow_network"]["type"] == "boolean"
    assert tools["orion_resource_links"].inputSchema["properties"]["limit"]["maximum"] == 100
    assert tools["orion_read_resource"].inputSchema["properties"]["path"]["maxLength"] == 4096


def test_resource_errors_do_not_export_server_paths_or_credentials(server: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    private = "/operator/private/approval.json?token=synthetic-secret"

    def fail(self: ResourceCatalog, path: str) -> str:
        raise PermissionError(private)

    monkeypatch.setattr(ResourceCatalog, "read", fail)

    async def scenario() -> None:
        result = await server.call_tool("orion_read_resource", {"path": "README.md"})
        assert result.isError is True
        assert private not in result.model_dump_json()
        assert "synthetic-secret" not in result.model_dump_json()
        with pytest.raises(Exception) as error:
            await server.read_resource("orion://repository/README.md")
        assert private not in str(error.value)
        assert "synthetic-secret" not in str(error.value)

    asyncio.run(scenario())


def test_prompt_arguments_have_explicit_limits(server: Any) -> None:
    async def scenario() -> None:
        with pytest.raises(ValueError, match="8192"):
            await server.get_prompt("controlled_lab_workflow", {"objective": "x" * 8193})

    asyncio.run(scenario())


def test_custom_sse_route_is_used_verbatim_in_generated_client_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORION_RESOURCE_ROOT", str(tmp_path))
    config = McpServerConfig(transport="sse", sse_path="/events/mcp")
    sdk = build_server(config)

    async def scenario() -> None:
        result = await sdk.call_tool("orion_client_config", {"client": "generic", "transport": "sse"})
        structured = result[1]
        assert structured["payload"]["mcpServers"]["orion"]["url"] == "http://127.0.0.1:8000/events/mcp"

    asyncio.run(scenario())


def test_response_budget_counts_utf8_and_structured_content() -> None:
    from mcp.types import CallToolResult, TextContent

    result = CallToolResult(content=[TextContent(type="text", text="é" * 64)],
                            structuredContent={"text": "é" * 64})
    with pytest.raises(ResponseLimitError):
        bound_response(result, maximum=200)
    bound_response(result, maximum=1024)


async def _event_is_set(event: threading.Event) -> None:
    while not event.is_set():
        await asyncio.sleep(0.001)


def test_worker_cancellation_keeps_cleanup_and_event_loop_responsive() -> None:
    started = threading.Event()
    cleaned = threading.Event()

    def operation() -> dict[str, bool]:
        started.set()
        try:
            while True:
                check_execution()
                time.sleep(0.005)
        finally:
            cleaned.set()

    async def scenario() -> None:
        runner = CallbackRunner(workers=1, pending=2)
        task = asyncio.create_task(runner.call(operation))
        await asyncio.wait_for(_event_is_set(started), timeout=1)
        # Reaching this point while the worker is active proves the protocol
        # loop remains available to receive cancellation and other requests.
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)
        assert cleaned.is_set()
        assert await runner.call(lambda: {"ok": True}) == {"ok": True}

    asyncio.run(scenario())


def test_callback_queue_and_worker_count_are_bounded() -> None:
    started = threading.Event()
    release = threading.Event()
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    def operation() -> bool:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            started.set()
            assert release.wait(2), "test failed to release worker"
            return True
        finally:
            with lock:
                active -= 1

    async def scenario() -> None:
        runner = CallbackRunner(workers=1, pending=2)
        first = asyncio.create_task(runner.call(operation))
        await asyncio.wait_for(_event_is_set(started), timeout=1)
        second = asyncio.create_task(runner.call(operation))
        await asyncio.sleep(0)
        try:
            with pytest.raises(ServerBusyError):
                await runner.call(operation)
        finally:
            release.set()
            assert await asyncio.gather(first, second) == [True, True]

    asyncio.run(scenario())
    assert maximum_active == 1
    assert active == 0


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_sdk_and_http_guard_share_exact_origins(host: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    monkeypatch.setenv("ORION_RESOURCE_ROOT", str(tmp_path))
    config = McpServerConfig(transport="streamable-http", host=host,
                             streamable_http_path="/orion/mcp", cors_origins=("https://reviewer.example",))
    sdk = build_server(config)
    app = build_http_app(sdk, config)

    async def scenario() -> None:
        async with sdk.session_manager.run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=config.endpoint) as client:
                headers = {"Origin": "https://reviewer.example", "Accept": "application/json, text/event-stream"}
                response = await client.post(config.endpoint, headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "offline-regression", "version": "1"}},
                })
                assert response.status_code == 200, response.text
                assert response.headers["access-control-allow-origin"] == "https://reviewer.example"
                assert response.json()["result"]["serverInfo"]["name"] == "ORION Security Runtime"
                rejected = await client.post(config.endpoint, headers={**headers, "Origin": "https://unapproved.invalid"}, json={})
                assert rejected.status_code == 403

    asyncio.run(scenario())
