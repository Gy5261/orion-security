"""Local-only HTTP boundary and explicit MCP protocol compatibility reporting."""
from __future__ import annotations

import asyncio
import math
import time
from importlib import metadata
from typing import Any
from urllib.parse import urlsplit

from orion.jsonio import loads_json
from orion.mcp.compat import McpServerConfig

MAX_REQUEST_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_COUNT = 128
MAX_BODY_CHUNKS = 4096
MAX_HTTP_REQUESTS = 64


def require_local_configuration(config: McpServerConfig) -> None:
    """Refuse unauthenticated remote bindings and wildcard browser origins."""
    config.validated()
    if config.transport != "stdio" and config.host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("controlled MCP is local-only; remote OAuth deployment is not implemented")
    if "*" in config.cors_origins:
        raise ValueError("wildcard CORS is forbidden in the controlled profile")
    for origin in config.cors_origins:
        if len(origin) > 2048 or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in origin):
            raise ValueError("CORS origins must be bounded and must not contain whitespace or control characters")
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid CORS origin host or port") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("CORS origins must be explicit HTTP(S) origins without credentials")
        if parsed.path or parsed.query or parsed.fragment or any(char in parsed.netloc for char in "\\%*"):
            raise ValueError("CORS origins must not contain paths, queries, fragments or whitespace")
        if port == 0 or parsed.netloc.endswith(":"):
            raise ValueError("invalid CORS origin port")


def local_http_allowlists(config: McpServerConfig) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Share exact Host/Origin policy between ORION and the SDK's own guard."""
    require_local_configuration(config)
    hosts = {f"127.0.0.1:{config.port}", f"localhost:{config.port}", f"[::1]:{config.port}"}
    if config.port == 80:
        hosts.update({"127.0.0.1", "localhost", "[::1]"})
    origins = {f"http://{host}" for host in hosts} | set(config.cors_origins)
    return tuple(sorted(hosts)), tuple(sorted(origins))


def protocol_audit() -> dict[str, Any]:
    """Report the SDK baseline without presenting an SDK version as conformance proof."""
    try:
        import mcp.types as types
        sdk_version: str | None = metadata.version("mcp")
        latest: str | None = getattr(types, "LATEST_PROTOCOL_VERSION", None)
    except (ImportError, metadata.PackageNotFoundError):
        sdk_version, latest = None, None
    return {
        "requested_specification": "2026-07-28", "sdk_version": sdk_version,
        "sdk_declared_latest_protocol": latest,
        "orion_protocol_era": "initialize-handshake",
        "conforms_to_2026_07_28": False,
        "verification": "transport round trips are not full protocol conformance tests",
        "migration_requirements": [
            "server/discover and per-request protocol/capability metadata",
            "resultType on all results and required cache metadata",
            "modern HTTP method/name header validation",
            "modern cancellation and subscriptions semantics",
            "independent conformance tests before advertising the new revision",
        ],
        "remote_oauth_implemented": False,
        "unsupported_features": ["tasks extension", "MRTR", "MCP Apps", "skills-over-MCP extension"],
        "reference": "https://modelcontextprotocol.io/specification/2026-07-28/changelog",
    }


class LocalHttpGuard:
    """ASGI guard: exact Host/Origin validation and bounded request-body buffering.

    Response streams are not buffered. This is not authentication or a firewall.
    """
    def __init__(self, app: Any, config: McpServerConfig, max_body_bytes: int = MAX_REQUEST_BYTES,
                 *, body_timeout_seconds: float = 10.0, strict_json: bool = False,
                 max_concurrent_requests: int = MAX_HTTP_REQUESTS) -> None:
        if type(max_body_bytes) is not int or not 1 <= max_body_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_body_bytes must be an integer between 1 byte and 16 MiB")
        if type(body_timeout_seconds) not in {int, float} or not math.isfinite(body_timeout_seconds) or not 0 < body_timeout_seconds <= 60:
            raise ValueError("body_timeout_seconds must be finite and between 0 and 60 seconds")
        if type(strict_json) is not bool:
            raise ValueError("strict_json must be a boolean")
        if type(max_concurrent_requests) is not int or not 1 <= max_concurrent_requests <= 1024:
            raise ValueError("max_concurrent_requests must be an integer from 1 to 1024")
        hosts, origins = local_http_allowlists(config)
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.body_timeout_seconds = float(body_timeout_seconds)
        self.strict_json = strict_json
        self.max_concurrent_requests = max_concurrent_requests
        self._active_requests = 0
        self.hosts = set(hosts)
        self.origins = set(origins)

    @staticmethod
    async def _reject(send: Any, status: int, message: str) -> None:
        body = message.encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"cache-control", b"no-store"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if self._active_requests >= self.max_concurrent_requests:
            await self._reject(send, 503, "too many active MCP requests; retry after existing requests complete")
            return
        self._active_requests += 1
        try:
            await self._handle_http(scope, receive, send)
        finally:
            self._active_requests -= 1

    async def _handle_http(self, scope: Any, receive: Any, send: Any) -> None:
        pairs = [(key.lower(), value) for key, value in scope.get("headers", [])]
        if len(pairs) > MAX_HEADER_COUNT or sum(len(key) + len(value) for key, value in pairs) > MAX_HEADER_BYTES:
            await self._reject(send, 431, "request headers too large")
            return
        if any(any(char in value for char in (b"\x00", b"\r", b"\n")) for _, value in pairs):
            await self._reject(send, 400, "invalid header value")
            return
        headers = dict(pairs)
        for name in (b"host", b"origin", b"content-length", b"transfer-encoding", b"content-type",
                     b"mcp-session-id", b"mcp-protocol-version", b"last-event-id", b"authorization"):
            if sum(key == name for key, _ in pairs) > 1:
                await self._reject(send, 400, "duplicate security-sensitive header")
                return
        host = headers.get(b"host", b"").decode("latin-1").lower()
        origin = headers.get(b"origin")
        if host not in self.hosts:
            await self._reject(send, 403, "invalid Host")
            return
        if origin is not None and origin.decode("latin-1") not in self.origins:
            await self._reject(send, 403, "invalid Origin")
            return
        length = headers.get(b"content-length")
        declared_length: int | None = None
        transfer_encoding = headers.get(b"transfer-encoding")
        if transfer_encoding is not None:
            if length is not None:
                await self._reject(send, 400, "Content-Length and Transfer-Encoding must not coexist")
                return
            if transfer_encoding.strip().lower() != b"chunked":
                await self._reject(send, 400, "unsupported Transfer-Encoding")
                return
        if scope.get("method") not in {"POST", "PUT", "PATCH"} and transfer_encoding is not None:
            await self._reject(send, 400, "streamed request bodies are not allowed for this method")
            return
        if length is not None:
            # Reject pathological decimal strings before int(), including values
            # exceeding Python's integer-conversion digit limit.
            if not length.isdigit() or len(length) > 20:
                await self._reject(send, 400, "invalid Content-Length")
                return
            declared_length = int(length)
            if declared_length > self.max_body_bytes:
                await self._reject(send, 413, "request body too large")
                return
        if scope.get("method") not in {"POST", "PUT", "PATCH"}:
            if declared_length is not None and declared_length > 0:
                await self._reject(send, 400, "request body is not allowed for this method")
                return
        body = bytearray()
        deadline = time.monotonic() + self.body_timeout_seconds
        chunks = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                await self._reject(send, 408, "request body deadline exceeded")
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                await self._reject(send, 408, "request body deadline exceeded")
                return
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request" or not isinstance(message.get("body", b""), bytes):
                await self._reject(send, 400, "invalid request body frame")
                return
            chunk = message.get("body", b"")
            chunks += 1
            if chunks > MAX_BODY_CHUNKS:
                await self._reject(send, 413, "too many request body frames")
                return
            if len(body) + len(chunk) > self.max_body_bytes:
                await self._reject(send, 413, "request body too large")
                return
            body.extend(chunk)
            if scope.get("method") not in {"POST", "PUT", "PATCH"} and body:
                await self._reject(send, 400, "request body is not allowed for this method")
                return
            if declared_length is not None and len(body) > declared_length:
                await self._reject(send, 400, "request body length does not match Content-Length")
                return
            if not message.get("more_body", False):
                break
        if declared_length is not None and len(body) != declared_length:
            await self._reject(send, 400, "request body length does not match Content-Length")
            return
        if self.strict_json and scope.get("method") == "POST":
            try:
                loads_json(bytes(body), max_bytes=self.max_body_bytes)
            except ValueError:
                await self._reject(send, 400, "request must be bounded UTF-8 JSON without duplicate keys or non-finite numbers")
                return
        delivered = False

        async def bounded_receive() -> Any:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
