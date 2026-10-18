"""MCP interoperability helpers independent from the optional MCP SDK."""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import asdict, dataclass
from importlib import metadata
from typing import Any, Literal, cast
from urllib.parse import urlsplit, urlunsplit

from orion import __version__

Transport = Literal["stdio", "streamable-http", "sse"]
ResponseMode = Literal["json", "stream"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _plain_text(value: str, name: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must contain 1 to {maximum} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} must not contain control characters")


def _url_path(value: str, name: str) -> None:
    """Validate a literal route, without ambiguous percent decoding or patterns."""
    _plain_text(value, name, 2048)
    if not value.startswith("/") or "//" in value or any(char in value for char in "?#\\%{}"):
        raise ValueError(f"{name} must be a literal local absolute URL path")
    if any(char.isspace() for char in value) or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError(f"{name} must not contain traversal or whitespace")


def _endpoint_url(value: str) -> str:
    _plain_text(value, "endpoint", 4096)
    if any(char.isspace() for char in value) or "\\" in value:
        raise ValueError("endpoint must be an absolute HTTP(S) URL without whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint has an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or port == 0:
        raise ValueError("endpoint must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("endpoint must not contain credentials or a fragment")
    return value


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _path(value: str, default: str) -> str:
    normalized = (value or default).strip()
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


@dataclass(frozen=True, slots=True)
class McpServerConfig:
    """Validated runtime settings shared by stdio and HTTP transports."""

    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    streamable_http_path: str = "/mcp"
    sse_path: str = "/sse"
    message_path: str = "/messages/"
    stateless_http: bool = True
    response_mode: ResponseMode = "json"
    cors_origins: tuple[str, ...] = ()
    log_level: LogLevel = "INFO"

    @classmethod
    def from_environment(cls) -> "McpServerConfig":
        transport = os.getenv("ORION_MCP_TRANSPORT", "stdio").strip().casefold()
        if transport not in {"stdio", "streamable-http", "sse"}:
            raise ValueError("ORION_MCP_TRANSPORT must be stdio, streamable-http, or sse")
        response_mode = os.getenv("ORION_MCP_RESPONSE_MODE", "json").strip().casefold()
        if response_mode not in {"json", "stream"}:
            raise ValueError("ORION_MCP_RESPONSE_MODE must be json or stream")
        origins = tuple(
            item.strip() for item in os.getenv("ORION_MCP_CORS_ORIGINS", "").split(",") if item.strip()
        )
        return cls(
            transport=transport,  # type: ignore[arg-type]
            host=os.getenv("ORION_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=int(os.getenv("ORION_MCP_PORT", "8000")),
            streamable_http_path=_path(os.getenv("ORION_MCP_PATH", "/mcp"), "/mcp"),
            sse_path=_path(os.getenv("ORION_MCP_SSE_PATH", "/sse"), "/sse"),
            message_path=_path(os.getenv("ORION_MCP_MESSAGE_PATH", "/messages/"), "/messages/"),
            stateless_http=_env_bool("ORION_MCP_STATELESS", True),
            response_mode=response_mode,  # type: ignore[arg-type]
            cors_origins=origins,
            log_level=cast(LogLevel, os.getenv("ORION_MCP_LOG_LEVEL", "INFO").strip().upper() or "INFO"),
        ).validated()

    def validated(self) -> "McpServerConfig":
        if self.transport not in {"stdio", "streamable-http", "sse"}:
            raise ValueError(f"unsupported MCP transport: {self.transport}")
        _plain_text(self.host, "MCP host", 253)
        if any(char.isspace() for char in self.host) or any(char in self.host for char in "/?#\\@"):
            raise ValueError("MCP host must be a hostname or an IP address")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("MCP port must be between 1 and 65535")
        if self.response_mode not in {"json", "stream"}:
            raise ValueError("response mode must be json or stream")
        for name, value in {
            "streamable_http_path": self.streamable_http_path,
            "sse_path": self.sse_path,
            "message_path": self.message_path,
        }.items():
            _url_path(value, name)
        if type(self.stateless_http) is not bool:
            raise ValueError("stateless_http must be a boolean")
        if self.log_level not in _LOG_LEVELS:
            raise ValueError("MCP log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
        if not isinstance(self.cors_origins, tuple) or not all(isinstance(origin, str) for origin in self.cors_origins):
            raise ValueError("cors_origins must be a tuple of origin strings")
        if len(self.cors_origins) > 32:
            raise ValueError("at most 32 explicit CORS origins may be configured")
        if self.transport == "stdio" and self.cors_origins:
            raise ValueError("CORS origins only apply to HTTP transports")
        if "*" in self.cors_origins and len(self.cors_origins) > 1:
            raise ValueError("wildcard CORS origin cannot be combined with explicit origins")
        return self

    @property
    def json_response(self) -> bool:
        return self.response_mode == "json"

    @property
    def endpoint(self) -> str:
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"http://{host}:{self.port}{self.streamable_http_path}"

    @property
    def sse_endpoint(self) -> str:
        """The actual configured SSE route, including non-default prefixes."""
        parsed = urlsplit(self.endpoint)
        return urlunsplit((parsed.scheme, parsed.netloc, self.sse_path, "", ""))

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["json_response"] = self.json_response
        payload["endpoint"] = self.endpoint
        return payload


def mcp_sdk_version() -> str | None:
    try:
        return metadata.version("mcp")
    except metadata.PackageNotFoundError:
        return None


def capability_document(config: McpServerConfig) -> dict[str, Any]:
    """Return a client-neutral description of the MCP surface."""

    return {
        "server": {
            "name": "ORION Security Runtime",
            "version": __version__,
            "sdk": {"name": "mcp-python", "version": mcp_sdk_version()},
        },
        "protocol": {
            "encoding": "UTF-8",
            "rpc": "JSON-RPC 2.0",
            "transports": {
                "stdio": {"supported": True, "recommended_for": "local process clients"},
                "streamable-http": {
                    "supported": True,
                    "recommended_for": "local HTTP and explicitly allowed browser clients",
                    "endpoint": config.endpoint,
                    "response_modes": ["application/json", "text/event-stream"],
                },
                "sse": {"supported": True, "legacy": True, "path": config.sse_path},
            },
            "primitives": ["tools", "resources", "resource_templates", "prompts", "logging"],
            "tool_results": ["structuredContent", "text fallback", "resource links"],
            "resource_content": ["text", "base64 blob"],
            "schema_dialect": "https://json-schema.org/draft/2020-12/schema",
        },
        "runtime": config.to_dict(),
    }


def client_configuration(
    client: str,
    transport: Transport,
    *,
    command: str = "orion-mcp",
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Generate common MCP client configuration shapes without coupling to one vendor."""

    _plain_text(client or "generic", "client", 64)
    _plain_text(command, "command", 4096)
    normalized = client.strip().casefold().replace("_", "-") or "generic"
    if transport == "stdio":
        server: dict[str, Any] = {"command": command, "args": ["--transport", "stdio"]}
    elif transport == "streamable-http":
        server = {"url": _endpoint_url(endpoint if endpoint is not None else "http://127.0.0.1:8000/mcp"),
                  "transport": "streamable-http"}
    elif transport == "sse":
        # An explicit URL identifies an exact endpoint, even if its last segment
        # happens to be named "mcp". Only an omitted URL selects the default.
        server = {"url": _endpoint_url(endpoint if endpoint is not None else "http://127.0.0.1:8000/sse"),
                  "transport": "sse"}
    else:  # pragma: no cover - guarded by callers and type checking
        raise ValueError(f"unsupported transport: {transport}")

    if normalized in {"vscode", "visual-studio-code", "github-copilot"}:
        vscode_server = dict(server)
        vscode_server["type"] = {"stdio": "stdio", "streamable-http": "http", "sse": "sse"}[transport]
        vscode_server.pop("transport", None)
        return {"client": normalized, "format": "vscode-mcp.json", "payload": {"servers": {"orion": vscode_server}}}
    if normalized in {"claude-code"}:
        if transport == "stdio":
            argv = ["claude", "mcp", "add", "orion", "--", command, "--transport", "stdio"]
        else:
            argv = ["claude", "mcp", "add", "--transport", "sse" if transport == "sse" else "http", "orion", server["url"]]
        return {"client": normalized, "format": "shell", "payload": shlex.join(argv), "server": server,
                "argv": argv, "shell": "posix",
                "note": "Shell rendering uses POSIX quoting; argv is the portable argument list. Treat it as configuration data."}
    if normalized in {"generic", "claude-desktop", "cursor", "windsurf", "cline", "roo-code"}:
        return {
            "client": normalized,
            "format": "mcpServers.json",
            "payload": {"mcpServers": {"orion": server}},
        }
    return {
        "client": normalized,
        "format": "generic-json",
        "payload": {"name": "orion", **server},
        "note": "Unknown client name; use this standards-based MCP connection descriptor.",
    }


def render_configuration(payload: dict[str, Any]) -> str:
    value = payload.get("payload")
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
