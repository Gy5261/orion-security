"""MCP boundary regression tests using in-memory ASGI requests only."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from orion.mcp.compat import McpServerConfig
from orion.mcp.security import LocalHttpGuard, protocol_audit, require_local_configuration
from orion.mcp.server import build_server, main

httpx = pytest.importorskip("httpx")


async def application(scope: Any, receive: Any, send: Any) -> None:
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def request(*, headers: Any = None, content: bytes = b"{}", max_bytes: int = 1024) -> httpx.Response:
    async def scenario() -> httpx.Response:
        guard = LocalHttpGuard(application, McpServerConfig(transport="streamable-http"), max_body_bytes=max_bytes)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guard), base_url="http://127.0.0.1:8000") as client:
            return await client.post("/mcp", headers=headers, content=content)
    return asyncio.run(scenario())


def test_loopback_without_browser_origin_is_accepted() -> None:
    assert request().status_code == 200


@pytest.mark.parametrize("origin", ["https://unapproved.invalid", "null", "http://127.0.0.1:9999"])
def test_unapproved_browser_origins_are_rejected(origin: str) -> None:
    assert request(headers={"Origin": origin}).status_code == 403


def test_rebinding_host_is_rejected() -> None:
    assert request(headers={"Host": "unapproved.invalid:8000"}).status_code == 403


def test_duplicate_origins_are_rejected() -> None:
    assert request(headers=[("Origin", "http://127.0.0.1:8000"), ("Origin", "https://unapproved.invalid")]).status_code == 400


def test_body_size_limit_is_enforced() -> None:
    assert request(content=b"x" * 20, max_bytes=16).status_code == 413


def test_chunked_body_size_is_checked_without_content_length() -> None:
    async def scenario() -> None:
        sent: list[dict[str, Any]] = []
        queue = [{"type": "http.request", "body": b"123456", "more_body": True},
                 {"type": "http.request", "body": b"789012", "more_body": False}]

        async def receive() -> dict[str, Any]:
            return queue.pop(0)

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        guard = LocalHttpGuard(application, McpServerConfig(transport="streamable-http"), max_body_bytes=8)
        await guard({"type": "http", "method": "POST", "headers": [(b"host", b"127.0.0.1:8000")]}, receive, send)
        assert sent[0]["status"] == 413
    asyncio.run(scenario())


def test_explicit_origin_is_allowed_by_guard() -> None:
    async def scenario() -> None:
        config = McpServerConfig(transport="streamable-http", cors_origins=("https://reviewer.example",))
        guard = LocalHttpGuard(application, config)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guard), base_url="http://127.0.0.1:8000") as client:
            result = await client.post("/mcp", headers={"Origin": "https://reviewer.example"}, content=b"{}")
            assert result.status_code == 200
    asyncio.run(scenario())


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.2", "public.example", "::"])
def test_remote_configuration_fails_closed(host: str) -> None:
    config = McpServerConfig(transport="streamable-http", host=host)
    with pytest.raises(ValueError, match="local-only"):
        build_server(config)


def test_remote_cli_override_cannot_bypass_policy() -> None:
    assert main(["--transport", "streamable-http", "--host", "0.0.0.0", "--allow-remote", "--print-config"]) == 2


def test_wildcard_cors_is_not_a_supported_override() -> None:
    assert main(["--transport", "streamable-http", "--allow-any-origin", "--print-config"]) == 2


@pytest.mark.parametrize("origin", ["*", "null", "https://client.example/path", "https://user:pass@client.example", "https://client.example?key=x"])
def test_unsafe_origin_configuration_is_rejected(origin: str) -> None:
    with pytest.raises(ValueError):
        require_local_configuration(McpServerConfig(transport="streamable-http", cors_origins=(origin,)))


def test_protocol_revision_is_not_invented() -> None:
    result = protocol_audit()
    assert result["requested_specification"] == "2026-07-28"
    assert result["conforms_to_2026_07_28"] is False
    assert result["remote_oauth_implemented"] is False


def framed_request(*, method: str = "POST", headers: list[tuple[bytes, bytes]] | None = None,
                   frames: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    async def scenario() -> list[dict[str, Any]]:
        responses: list[dict[str, Any]] = []
        incoming = list(frames if frames is not None else [{"type": "http.request", "body": b"{}"}])

        async def receive() -> dict[str, Any]:
            return incoming.pop(0)

        async def send(message: dict[str, Any]) -> None:
            responses.append(message)

        guard = LocalHttpGuard(application, McpServerConfig(transport="streamable-http"))
        await guard({"type": "http", "method": method,
                     "headers": [(b"host", b"127.0.0.1:8000"), *(headers or [])]}, receive, send)
        return responses

    return asyncio.run(scenario())


@pytest.mark.parametrize("length", [b"1", b"3", b"0", b"+2", b"1" * 5000])
def test_content_length_is_bounded_and_matches_the_received_body(length: bytes) -> None:
    result = framed_request(headers=[(b"content-length", length)])
    assert result[0]["status"] == 400


@pytest.mark.parametrize("method", ["GET", "DELETE", "OPTIONS"])
def test_undeclared_body_is_rejected_for_bodyless_methods(method: str) -> None:
    assert framed_request(method=method)[0]["status"] == 400


@pytest.mark.parametrize("name", [b"mcp-session-id", b"mcp-protocol-version", b"content-type",
                                  b"last-event-id", b"authorization"])
def test_protocol_security_headers_cannot_be_duplicated(name: bytes) -> None:
    assert framed_request(headers=[(name, b"first"), (name.upper(), b"second")])[0]["status"] == 400


def test_http_header_budget_is_enforced_before_application_dispatch() -> None:
    assert framed_request(headers=[(b"x-padding", b"x" * 32769)])[0]["status"] == 431
    assert framed_request(headers=[(b"x", b"y")] * 129)[0]["status"] == 431


def test_header_control_characters_fail_closed() -> None:
    assert framed_request(headers=[(b"x-test", b"first\r\nsecond")])[0]["status"] == 400


def test_client_disconnect_does_not_dispatch_or_write_a_response() -> None:
    assert framed_request(frames=[{"type": "http.disconnect"}]) == []


def test_unexpected_asgi_frames_are_not_treated_as_empty_request_bodies() -> None:
    assert framed_request(frames=[{"type": "lifespan.startup"}])[0]["status"] == 400


def test_endless_empty_chunks_are_bounded() -> None:
    frames = [{"type": "http.request", "body": b"", "more_body": True}] * 4097
    assert framed_request(frames=frames)[0]["status"] == 413


def test_body_deadline_is_enforced_without_waiting_for_client_completion() -> None:
    async def scenario() -> None:
        responses: list[dict[str, Any]] = []

        async def receive() -> dict[str, Any]:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def send(message: dict[str, Any]) -> None:
            responses.append(message)

        guard = LocalHttpGuard(application, McpServerConfig(transport="streamable-http"), body_timeout_seconds=0.01)
        await guard({"type": "http", "method": "POST", "headers": [(b"host", b"127.0.0.1:8000")]}, receive, send)
        assert responses[0]["status"] == 408

    asyncio.run(scenario())


@pytest.mark.parametrize("size", [0, -1, True, 1.5, 16 * 1024 * 1024 + 1])
def test_invalid_http_body_budgets_are_rejected(size: Any) -> None:
    with pytest.raises(ValueError, match="max_body_bytes"):
        LocalHttpGuard(application, McpServerConfig(), max_body_bytes=size)


@pytest.mark.parametrize("origin", ["https://client.example:", "http://client.example:0", "https://*.example",
                                   "https://client.example%2fother", "https://client.example\x7f"])
def test_ambiguous_origin_authorities_are_rejected(origin: str) -> None:
    with pytest.raises(ValueError):
        require_local_configuration(McpServerConfig(transport="streamable-http", cors_origins=(origin,)))


@pytest.mark.parametrize("body", [b'{"id":1,"id":2}', b'{"value":NaN}', b'{"value":1e999}',
                                 b'{"value":"\xff"}', b"[" * 100 + b"0" + b"]" * 100])
def test_mcp_json_framing_rejects_ambiguous_or_non_finite_documents(body: bytes) -> None:
    async def scenario() -> None:
        guard = LocalHttpGuard(application, McpServerConfig(transport="streamable-http"), strict_json=True)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guard), base_url="http://127.0.0.1:8000") as client:
            response = await client.post("/mcp", content=body)
            assert response.status_code == 400

    asyncio.run(scenario())


def test_http_admission_bounds_buffers_and_releases_slots_after_completion() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocked(scope: Any, receive: Any, send: Any) -> None:
            started.set()
            await release.wait()
            await application(scope, receive, send)

        guard = LocalHttpGuard(blocked, McpServerConfig(transport="streamable-http"), max_concurrent_requests=1)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=guard), base_url="http://127.0.0.1:8000") as client:
            first = asyncio.create_task(client.post("/mcp", content=b"{}"))
            await asyncio.wait_for(started.wait(), timeout=1)
            try:
                second = await client.post("/mcp", content=b"{}")
                assert second.status_code == 503
            finally:
                release.set()
                assert (await first).status_code == 200
            assert (await client.post("/mcp", content=b"{}")).status_code == 200

    asyncio.run(scenario())
