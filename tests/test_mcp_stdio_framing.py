"""Strict stdio framing using memory buffers; no external services."""

from __future__ import annotations

import asyncio
import io

import pytest

pytest.importorskip("anyio")

from orion.mcp.stdio import BoundedStdioInput, BoundedStdioOutput, StdioFrameError


def test_stdio_rejects_duplicate_keys_without_forwarding_private_payload() -> None:
    stream = io.BytesIO(b'{"id":1,"id":2,"secret":"synthetic-secret"}\n{"id":3}\n')

    async def scenario() -> None:
        reader = BoundedStdioInput(stream)
        assert await anext(reader) == "{"
        assert await anext(reader) == '{"id":3}'
        with pytest.raises(StopAsyncIteration):
            await anext(reader)

    asyncio.run(scenario())


@pytest.mark.parametrize("raw", [b'{"value":NaN}\n', b'{"value":1e999}\n', b'{"value":"\xff"}\n',
                                 b"[" * 100 + b"0" + b"]" * 100 + b"\n"])
def test_stdio_rejects_invalid_json_before_sdk_parsing(raw: bytes) -> None:
    async def scenario() -> None:
        assert await anext(BoundedStdioInput(io.BytesIO(raw))) == "{"

    asyncio.run(scenario())


def test_oversized_stdio_frame_stops_before_reading_its_tail() -> None:
    stream = io.BytesIO(b" " * 10000 + b'{"id":1}\n')

    async def scenario() -> None:
        with pytest.raises(StdioFrameError, match="connection closed"):
            await anext(BoundedStdioInput(stream, max_bytes=16))

    asyncio.run(scenario())
    assert stream.tell() == 18


def test_stdio_accepts_exactly_bounded_crlf_and_non_ascii_json() -> None:
    raw = '{"label":"á"}'.encode("utf-8")

    async def scenario() -> None:
        reader = BoundedStdioInput(io.BytesIO(raw + b"\r\n"), max_bytes=len(raw))
        assert await anext(reader) == raw.decode("utf-8")

    asyncio.run(scenario())


def test_stdio_output_enforces_bytes_before_any_partial_write() -> None:
    stream = io.BytesIO()

    async def scenario() -> None:
        output = BoundedStdioOutput(stream, max_bytes=8)
        with pytest.raises(StdioFrameError):
            await output.write("é" * 5)
        assert stream.getvalue() == b""
        assert await output.write("é\n") == 2
        await output.flush()
        assert stream.getvalue() == "é\n".encode("utf-8")

    asyncio.run(scenario())
