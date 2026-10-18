"""Cooperative deadlines shared by runtime, adapters, and trusted worker threads.

This is not an operating-system sandbox. Python code must reach a checkpoint;
subprocess adapters additionally enforce their deadline while waiting for a child.
"""

from __future__ import annotations

import math
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator


class ExecutionCancelledError(RuntimeError):
    """An operator or disconnected client cancelled this execution."""


class ExecutionCancellation:
    """Thread-safe cancellation token; cancellation remains set once requested."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Signal running work to stop at its next checkpoint."""
        self._event.set()

    @property
    def cancelled(self) -> bool:
        """Whether cancellation has been requested."""
        return self._event.is_set()


@dataclass(frozen=True, slots=True)
class _ExecutionBudget:
    deadline: float | None = None
    cancellations: tuple[ExecutionCancellation, ...] = ()


_CURRENT: ContextVar[_ExecutionBudget] = ContextVar("orion_execution_budget", default=_ExecutionBudget())


def _positive_timeout(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
        raise ValueError("timeout_seconds must be finite and positive")
    return float(value)


@contextmanager
def execution_scope(*, timeout_seconds: float | None = None,
                    cancellation: ExecutionCancellation | None = None) -> Iterator[None]:
    """Nest an execution budget without extending an inherited deadline.

    Enter this context in the worker thread that executes a synchronous runtime.
    The cancellation token itself may be signalled from any thread.
    """
    parent = _CURRENT.get()
    deadline = parent.deadline
    if timeout_seconds is not None:
        requested = time.monotonic() + _positive_timeout(timeout_seconds)
        deadline = requested if deadline is None else min(deadline, requested)
    cancellations = parent.cancellations
    if cancellation is not None:
        if not isinstance(cancellation, ExecutionCancellation):
            raise TypeError("cancellation must be an ExecutionCancellation token")
        cancellations += (cancellation,)
    token = _CURRENT.set(_ExecutionBudget(deadline, cancellations))
    try:
        check_execution()
        yield
    finally:
        _CURRENT.reset(token)


def check_execution() -> None:
    """Raise when the current execution has been cancelled or has expired."""
    current = _CURRENT.get()
    if any(token.cancelled for token in current.cancellations):
        raise ExecutionCancelledError("execution was cancelled")
    if current.deadline is not None and time.monotonic() >= current.deadline:
        raise TimeoutError("execution deadline exceeded")


def remaining_timeout(requested: float) -> float:
    """Limit a finite socket or process timeout to the shared time remaining."""
    timeout = _positive_timeout(requested)
    check_execution()
    deadline = _CURRENT.get().deadline
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("execution deadline exceeded")
    return min(timeout, remaining)
