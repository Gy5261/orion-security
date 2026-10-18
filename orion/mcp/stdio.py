"""Bounded byte framing around the SDK's stdio transport and lifecycle.

Only I/O framing is adapted here; the SDK still owns JSON-RPC validation,
initialization, tools, resources, prompts and cancellation notifications.
"""

from __future__ import annotations

import sys
from typing import Any, BinaryIO

from orion.jsonio import loads_json
from orion.mcp.boundary import MAX_RESPONSE_BYTES
from orion.mcp.security import MAX_REQUEST_BYTES


class StdioFrameError(RuntimeError):
    """An oversized frame requires closing the stdio connection."""


class BoundedStdioInput:
    """Async iterator that never reads an unbounded line or forwards ambiguous JSON."""

    def __init__(self, stream: BinaryIO, max_bytes: int = MAX_REQUEST_BYTES) -> None:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
            raise ValueError("stdio frame limit must be between 1 byte and 16 MiB")
        self.stream = stream
        self.max_bytes = max_bytes

    def __aiter__(self) -> BoundedStdioInput:
        return self

    async def __anext__(self) -> str:
        import anyio

        raw = await anyio.to_thread.run_sync(self.stream.readline, self.max_bytes + 2)
        if not raw:
            raise StopAsyncIteration
        line = raw.removesuffix(b"\n").removesuffix(b"\r")
        if len(line) > self.max_bytes:
            # Do not reinterpret the tail of a rejected frame as a new request,
            # and do not drain an attacker-controlled endless line.
            raise StdioFrameError("stdio request exceeds the frame limit; connection closed")
        try:
            loads_json(line, max_bytes=self.max_bytes)
        except ValueError:
            # The SDK receives its normal parse-error path without logging the
            # rejected payload, duplicate values or invalid UTF-8 bytes.
            return "{"
        return line.decode("utf-8")


class BoundedStdioOutput:
    """Preserve UTF-8 and stdout protocol purity with a final encoded frame cap."""

    def __init__(self, stream: BinaryIO, max_bytes: int = MAX_RESPONSE_BYTES + 4096) -> None:
        self.stream = stream
        self.max_bytes = max_bytes

    async def write(self, value: str) -> int:
        import anyio

        if len(value) > self.max_bytes:
            raise StdioFrameError("stdio response exceeds the frame limit; connection closed")
        data = value.encode("utf-8")
        if len(data) > self.max_bytes:
            raise StdioFrameError("stdio response exceeds the frame limit; connection closed")
        await anyio.to_thread.run_sync(self.stream.write, data)
        return len(value)

    async def flush(self) -> None:
        import anyio

        await anyio.to_thread.run_sync(self.stream.flush)


def _frame_error(error: BaseException) -> StdioFrameError | None:
    if isinstance(error, StdioFrameError):
        return error
    for child in getattr(error, "exceptions", ()):
        found = _frame_error(child)
        if found is not None:
            return found
    return None


async def run_bounded_stdio(lowlevel_server: Any) -> None:
    """Run the existing SDK server over bounded adapters without owning stdio handles."""
    from mcp.server.stdio import stdio_server

    try:
        async with stdio_server(stdin=BoundedStdioInput(sys.stdin.buffer),  # type: ignore[arg-type]
                                stdout=BoundedStdioOutput(sys.stdout.buffer)) as (read, write):  # type: ignore[arg-type]
            await lowlevel_server.run(read, write, lowlevel_server.create_initialization_options())
    except Exception as exc:
        frame = _frame_error(exc)
        if frame is not None:
            raise frame from None
        raise
