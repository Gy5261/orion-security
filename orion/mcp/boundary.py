"""Transport-independent budgets for MCP callbacks and their public contracts.

The SDK remains responsible for protocol framing. ORION validates native JSON
before SDK coercion and runs synchronous work outside the protocol event loop.
"""

from __future__ import annotations

import copy
import json
import base64
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from orion.plugins.core import AuthorizationError, InputValidationError, PluginNotFoundError, ToolUnavailableError
from orion.plugins.execution import ExecutionCancellation, execution_scope

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_CALLBACK_WORKERS = 8
MAX_PENDING_CALLBACKS = 64
P = ParamSpec("P")
R = TypeVar("R")


class ResponseLimitError(ValueError):
    """The encoded result is larger than the documented response budget."""


class ServerBusyError(RuntimeError):
    """All bounded callback queue slots are occupied."""


class PublicMcpError(RuntimeError):
    """A fixed, actionable error which contains no raw paths or exception text."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def public_error(error: Exception) -> PublicMcpError:
    """Normalize expected errors even when the SDK wraps them in ToolError."""
    current: BaseException | None = error
    for _ in range(8):
        if isinstance(current, PublicMcpError):
            return current
        if isinstance(current, AuthorizationError):
            return PublicMcpError("operation_denied", "Operation denied by server policy; inspect orion_control_status and obtain independent operator review where required.")
        if isinstance(current, (FileNotFoundError, PermissionError)):
            return PublicMcpError("resource_unavailable", "Resource is unavailable or unpublished; use orion_resource_links to list permitted paths.")
        if isinstance(current, InputValidationError):
            return PublicMcpError("invalid_arguments", "Arguments do not match the advertised input schema; check required fields, native JSON types and limits.")
        if isinstance(current, PluginNotFoundError):
            return PublicMcpError("plugin_unavailable", "Plugin is not registered; use orion_list_plugins to choose an available contract.")
        if isinstance(current, ToolUnavailableError):
            return PublicMcpError("dependency_unavailable", "An optional tool is unavailable; inspect orion_doctor and install or configure the adapter on the server.")
        if isinstance(current, ResponseLimitError):
            return PublicMcpError("response_too_large", "Response exceeds the 8 MiB limit; request fewer results or publish a smaller resource.")
        if isinstance(current, ServerBusyError):
            return PublicMcpError("server_busy", "MCP callback queue is full; retry after active requests complete.")
        if current is None:
            break
        current = current.__cause__ or current.__context__
    if isinstance(error, (TypeError, ValueError)):
        return PublicMcpError("invalid_request", "Request could not be validated; inspect the tool schema and published resource list.")
    return PublicMcpError("operation_failed", "Operation failed; consult operator-controlled diagnostics.")


def tool_input_schema(name: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Expose the same native JSON and field budgets enforced before dispatch."""
    result = copy.deepcopy(schema)
    result["additionalProperties"] = False
    properties = result.get("properties", {})
    text_limits = {"plugin_id": 128, "client": 64, "command": 4096, "endpoint": 4096,
                   "authorization": 512, "actor": 128, "query": 512, "path": 4096}
    for key, maximum in text_limits.items():
        if key not in properties:
            continue
        field = properties[key]
        variants = field.get("anyOf", [field])
        for variant in variants:
            if variant.get("type") == "string":
                variant["maxLength"] = maximum
                if key not in {"authorization", "query", "client"}:
                    variant["minLength"] = 1
    if "query" in properties and name == "orion_search_resources":
        properties["query"]["minLength"] = 2
    if "limit" in properties:
        properties["limit"].update({"minimum": 1, "maximum": 100})
    if "transport" in properties:
        properties["transport"]["enum"] = ["stdio", "streamable-http", "sse"]
    if "timeout_seconds" in properties:
        for variant in properties["timeout_seconds"].get("anyOf", []):
            if variant.get("type") == "number":
                variant["exclusiveMinimum"] = 0
    return result


def bound_response(value: Any, maximum: int = MAX_RESPONSE_BYTES) -> None:
    """Reject an oversized result without constructing an additional JSON copy.

    CallToolResult and content models are serialized using their public Pydantic
    interface. SDK conversion may duplicate text in structuredContent; callers
    therefore check the converted result as well as the callback's raw value.
    """
    if isinstance(value, bytes):
        if len(value) > maximum:
            raise ResponseLimitError("MCP response exceeds the 8 MiB response limit")
        return

    def convert(item: Any) -> Any:
        dump = getattr(item, "model_dump", None)
        if callable(dump):
            return dump(mode="json", exclude_none=True)
        if is_dataclass(item) and not isinstance(item, type):
            return asdict(item)
        if isinstance(item, bytes):
            return base64.b64encode(item).decode("ascii")
        raise TypeError("MCP result is not JSON serializable")

    total = 0
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"), default=convert)
    for chunk in encoder.iterencode(value):
        total += len(chunk.encode("utf-8"))
        if total > maximum:
            raise ResponseLimitError("MCP response exceeds the 8 MiB response limit")


class CallbackRunner:
    """Bounded threads with cooperative cancellation and cleanup before release.

    A cancelled request signals the runtime's shared cancellation token. Its
    worker retains its slot until cleanup finishes. Arbitrary Python code cannot
    be forcibly terminated; only reviewed callbacks belong in this runner.
    """

    def __init__(self, workers: int = MAX_CALLBACK_WORKERS, pending: int = MAX_PENDING_CALLBACKS) -> None:
        import anyio

        if type(workers) is not int or workers < 1 or type(pending) is not int or pending < workers:
            raise ValueError("callback limits must be positive integers and pending must cover workers")
        self._admission = anyio.CapacityLimiter(workers)
        # Admission is held by the worker task, including during cancellation;
        # the thread bridge must not acquire the same limiter a second time.
        self._dispatch = anyio.CapacityLimiter(float("inf"))
        self._pending_limit = pending
        self._pending_count = 0

    async def call(self, function: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
        import anyio

        if self._pending_count >= self._pending_limit:
            raise ServerBusyError("MCP callback queue is full; retry after active requests complete")
        self._pending_count += 1
        cancellation = ExecutionCancellation()
        finished = anyio.Event()
        results: list[R] = []
        errors: list[Exception] = []

        def invoke() -> R:
            with execution_scope(cancellation=cancellation):
                result = function(*args, **kwargs)
                bound_response(result)
                return result

        async def worker() -> None:
            try:
                async with self._admission:
                    # A running thread cannot be abandoned safely: shield its
                    # cleanup while the parent signals cooperative cancellation.
                    with anyio.CancelScope(shield=True):
                        try:
                            results.append(await anyio.to_thread.run_sync(invoke, limiter=self._dispatch))
                        except Exception as exc:
                            errors.append(exc)
            finally:
                finished.set()

        try:
            async with anyio.create_task_group() as group:
                group.start_soon(worker)
                try:
                    await finished.wait()
                except BaseException:
                    cancellation.cancel()
                    raise
            if errors:
                raise errors[0]
            return results[0]
        finally:
            self._pending_count -= 1

    def wrap(self, function: Callable[P, R]) -> Callable[P, Any]:
        """Keep the callback's public signature and schema while making it async."""
        @wraps(function)
        async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return await self.call(function, *args, **kwargs)
            except Exception as exc:
                # SDK 1.x embeds callback exception strings in tool/resource
                # errors. Suppress the original context before it sees them.
                raise public_error(exc) from None

        return wrapped
