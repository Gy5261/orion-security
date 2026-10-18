from __future__ import annotations

import json
import shlex

import pytest

from orion.mcp.compat import McpServerConfig, capability_document, client_configuration, render_configuration


def test_default_config_is_local_and_stdio() -> None:
    config = McpServerConfig().validated()
    assert config.transport == "stdio"
    assert config.host == "127.0.0.1"
    assert config.endpoint == "http://127.0.0.1:8000/mcp"
    assert config.json_response is True


def test_remote_binding_and_origins_are_explicit() -> None:
    config = McpServerConfig(
        transport="streamable-http",
        cors_origins=("https://client.example",),
    ).validated()
    assert config.cors_origins == ("https://client.example",)

    with pytest.raises(ValueError, match="wildcard"):
        McpServerConfig(
            transport="streamable-http",
            cors_origins=("*", "https://client.example"),
        ).validated()


def test_client_configuration_shapes() -> None:
    generic = client_configuration("cursor", "stdio")
    assert generic["payload"]["mcpServers"]["orion"]["command"] == "orion-mcp"

    vscode = client_configuration("vscode", "streamable-http", endpoint="https://orion.example/mcp")
    assert vscode["payload"]["servers"]["orion"]["type"] == "http"
    assert vscode["payload"]["servers"]["orion"]["url"] == "https://orion.example/mcp"

    claude_code = client_configuration("claude-code", "stdio")
    assert "claude mcp add" in render_configuration(claude_code)


def test_capability_document_is_machine_readable() -> None:
    document = capability_document(McpServerConfig(transport="streamable-http"))
    assert document["protocol"]["rpc"] == "JSON-RPC 2.0"
    assert document["protocol"]["transports"]["streamable-http"]["supported"] is True
    json.dumps(document)


def test_ipv6_endpoints_use_brackets_and_preserve_configured_routes() -> None:
    config = McpServerConfig(transport="sse", host="::1", sse_path="/orion/events").validated()
    assert config.endpoint == "http://[::1]:8000/mcp"
    assert config.sse_endpoint == "http://[::1]:8000/orion/events"


@pytest.mark.parametrize("path", ["//mcp", "/api//mcp", "/./mcp", "/../mcp", "/%2e%2e/mcp",
                                 "/%252e%252e/mcp", "/mcp?key=1", "/mcp#fragment", "/{path}", "/mcp\x7f"])
def test_ambiguous_route_configuration_is_rejected(path: str) -> None:
    with pytest.raises(ValueError):
        McpServerConfig(streamable_http_path=path).validated()


@pytest.mark.parametrize("port", [True, 8000.5, 0, 65536])
def test_ports_require_a_native_bounded_integer(port: object) -> None:
    with pytest.raises(ValueError):
        McpServerConfig(port=port).validated()  # type: ignore[arg-type]


def test_client_command_and_endpoint_are_shell_quoted_as_single_arguments() -> None:
    command = "/local path/python; do-not-execute"
    stdio = client_configuration("claude-code", "stdio", command=command)
    assert shlex.split(stdio["payload"]) == stdio["argv"]
    assert command in stdio["argv"]
    endpoint = "https://server.example/mcp?label=one&value=$(do-not-execute)"
    http = client_configuration("claude-code", "streamable-http", endpoint=endpoint)
    assert shlex.split(http["payload"]) == http["argv"]
    assert http["argv"][-1] == endpoint
    assert http["shell"] == "posix"


def test_sse_configuration_preserves_the_exact_explicit_endpoint() -> None:
    endpoint = "https://mcp.example/team/mcp/archive/mcp?next=/mcp"
    configuration = client_configuration("claude-code", "sse", endpoint=endpoint)
    assert configuration["server"]["url"] == endpoint
    assert configuration["argv"][4] == "sse"
    vscode = client_configuration("vscode", "sse")
    assert vscode["payload"]["servers"]["orion"]["type"] == "sse"
    assert vscode["payload"]["servers"]["orion"]["url"] == "http://127.0.0.1:8000/sse"


@pytest.mark.parametrize("endpoint", ["file:///private/mcp", "https://user:secret@host.example/mcp",
                                     "https://host.example:99999/mcp", "https://host.example/mcp#fragment",
                                     "https://host.example/\n/mcp", "http://host.example:0/mcp"])
def test_unsafe_client_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(ValueError):
        client_configuration("generic", "streamable-http", endpoint=endpoint)
