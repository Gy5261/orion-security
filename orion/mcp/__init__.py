"""MCP integration for ORION."""

from typing import Any

from orion.mcp.compat import McpServerConfig, capability_document, client_configuration


def build_server(config: McpServerConfig | None = None) -> Any:
    """Lazily construct the optional SDK server without importing its CLI early."""
    from orion.mcp.server import build_server as construct

    return construct(config)


def build_http_app(server: Any, config: McpServerConfig, *, legacy_sse: bool = False) -> Any:
    """Lazily construct the guarded ASGI application."""
    from orion.mcp.server import build_http_app as construct

    return construct(server, config, legacy_sse=legacy_sse)

__all__ = [
    "McpServerConfig",
    "build_http_app",
    "build_server",
    "capability_document",
    "client_configuration",
]
