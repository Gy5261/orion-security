"""Stable exception hierarchy for ORION plugin callers."""

class OrionPluginError(RuntimeError):
    """Base error for the ORION plugin runtime."""


class InputValidationError(OrionPluginError):
    """Raised when plugin input or output violates its contract."""


class AuthorizationError(OrionPluginError):
    """Raised when execution policy rejects a request."""


class PluginNotFoundError(OrionPluginError):
    """Raised when a plugin identifier is not registered."""


class PluginExecutionError(OrionPluginError):
    """Raised when plugin execution fails."""


class ToolUnavailableError(PluginExecutionError):
    """Raised when an optional third-party tool is not installed."""


