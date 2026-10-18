from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]


def _structured(result: Any) -> dict[str, Any]:
    payload = getattr(result, "structuredContent", None)
    if isinstance(payload, dict):
        return payload
    for item in result.content:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            decoded = json.loads(text)
            if isinstance(decoded, dict):
                return decoded
    raise AssertionError("tool result did not include structured JSON or a JSON text fallback")


async def _verify_session(session: ClientSession) -> None:
    await session.initialize()
    tools = await session.list_tools()
    names = {tool.name for tool in tools.tools}
    assert {
        "orion_mcp_capabilities",
        "orion_client_config",
        "orion_list_plugins",
        "orion_run_plugin",
    }.issubset(names)

    resources = await session.list_resources()
    uris = {str(resource.uri) for resource in resources.resources}
    assert "orion://manifest" in uris
    assert "orion://mcp/capabilities" in uris

    prompts = await session.list_prompts()
    prompt_names = {prompt.name for prompt in prompts.prompts}
    assert {"authorized_security_workflow", "mcp_integration_guide"}.issubset(prompt_names)

    result = await session.call_tool("orion_mcp_capabilities", {})
    assert getattr(result, "isError", False) is False
    capability = _structured(result)
    assert capability["protocol"]["rpc"] == "JSON-RPC 2.0"


def test_stdio_round_trip() -> None:
    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "orion.mcp.server", "--transport", "stdio"],
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await _verify_session(session)

    asyncio.run(scenario())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


@contextmanager
def _server_process(transport: str, port: int) -> Iterator[subprocess.Popen[str]]:
    command = [
        sys.executable,
        "-m",
        "orion.mcp.server",
        "--transport",
        transport,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    if transport == "streamable-http":
        command.extend(["--path", "/mcp", "--stateless", "--json-response"])
    else:
        command.extend(["--sse-path", "/sse", "--message-path", "/messages/"])

    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                error = process.stderr.read() if process.stderr else ""
                raise AssertionError(f"MCP server exited before accepting connections: {error}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("MCP server did not start within 20 seconds")
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_streamable_http_round_trip() -> None:
    port = _free_port()
    with _server_process("streamable-http", port):
        async def scenario() -> None:
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
                read_stream, write_stream, _ = streams
                async with ClientSession(read_stream, write_stream) as session:
                    await _verify_session(session)

        asyncio.run(scenario())


def test_legacy_sse_round_trip() -> None:
    port = _free_port()
    with _server_process("sse", port):
        async def scenario() -> None:
            async with sse_client(f"http://127.0.0.1:{port}/sse") as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await _verify_session(session)

        asyncio.run(scenario())
