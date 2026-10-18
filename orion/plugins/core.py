"""Core contracts and execution runtime for ORION plugins."""
from __future__ import annotations

import importlib.metadata
import json
import math
import platform
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any, Iterable, Mapping, MutableMapping

from orion.controls import ControlDenied, audit_event, canonical_json, enforce_request, needs_network

from .errors import (
    AuthorizationError as AuthorizationError,
    InputValidationError as InputValidationError,
    OrionPluginError as OrionPluginError,
    PluginExecutionError as PluginExecutionError,
    PluginNotFoundError as PluginNotFoundError,
    ToolUnavailableError as ToolUnavailableError,
)
from .schema import validate_json_schema as validate_json_schema
from .execution import ExecutionCancelledError, check_execution, execution_scope
from .redaction import redact_data, redact_text

JsonObject = dict[str, Any]
_ADMITTED_REQUEST: ContextVar[tuple[int, int, int] | None] = ContextVar("orion_admitted_request", default=None)


@dataclass(frozen=True, slots=True)
class PluginHealth:
    """Availability report for a plugin and its optional dependencies."""
    available: bool
    status: str = "ready"
    message: str = ""
    details: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PluginMetadata:
    """Immutable, machine-readable contract for an ORION plugin."""
    plugin_id: str
    name: str
    version: str
    category: str
    description: str
    risk_level: str
    capabilities: tuple[str, ...]
    input_schema: JsonObject
    output_schema: JsonObject
    requires_authorization: bool = True
    network_access: bool = False
    side_effects: bool = False
    default_timeout_seconds: float = 30.0
    max_timeout_seconds: float = 300.0
    tags: tuple[str, ...] = ()
    homepage: str | None = None
    license: str | None = None
    integration: str = "native"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", self.plugin_id):
            raise ValueError(f"invalid plugin_id: {self.plugin_id!r}")
        if not self.name.strip():
            raise ValueError("name cannot be empty")
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", self.version):
            raise ValueError(f"invalid semantic version: {self.version!r}")
        if self.risk_level not in {"low", "medium", "high"}:
            raise ValueError("risk_level must be low, medium, or high")
        if not self.capabilities:
            raise ValueError("capabilities must contain at least one item")
        if any(type(value) is not bool for value in (self.requires_authorization, self.network_access, self.side_effects)):
            raise ValueError("plugin authorization and effect flags must be booleans")
        if type(self.default_timeout_seconds) not in {int, float} or not math.isfinite(self.default_timeout_seconds) or self.default_timeout_seconds <= 0:
            raise ValueError("default_timeout_seconds must be finite and positive")
        if type(self.max_timeout_seconds) not in {int, float} or not math.isfinite(self.max_timeout_seconds) or self.max_timeout_seconds < self.default_timeout_seconds:
            raise ValueError("max_timeout_seconds must be finite and cannot be lower than the default")
        if self.input_schema.get("type") != "object":
            raise ValueError("input_schema must declare type=object")
        if self.output_schema.get("type") not in {"object", "array"}:
            raise ValueError("output_schema must declare type=object or type=array")

    def to_dict(self) -> JsonObject:
        payload = asdict(self)
        payload["capabilities"] = list(self.capabilities)
        payload["tags"] = list(self.tags)
        return payload


@dataclass(frozen=True, slots=True)
class PluginContext:
    """Explicit execution context. Actor is an audit label, not an authenticated identity."""
    authorization: str | None = None
    allow_network: bool = False
    allow_side_effects: bool = False
    actor: str = "local-user"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.actor, str) or not 1 <= len(self.actor.strip()) <= 128:
            raise ValueError("actor must contain 1 to 128 characters")
        if any(ord(char) < 32 for char in self.actor):
            raise ValueError("actor must not contain control characters")
        if self.authorization is not None and (not isinstance(self.authorization, str) or len(self.authorization) > 512):
            raise ValueError("authorization must be a reference of at most 512 characters")
        if type(self.allow_network) is not bool or type(self.allow_side_effects) is not bool:
            raise ValueError("permission flags must be booleans")
        if not isinstance(self.environment, Mapping) or len(self.environment) > 32:
            raise ValueError("environment must be a mapping with at most 32 entries")
        for key, value in self.environment.items():
            if (not isinstance(key, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) is None
                    or not isinstance(value, str) or len(value) > 4096 or "\x00" in value):
                raise ValueError("environment entries must have valid names and bounded string values")
        # A frozen dataclass alone does not freeze a caller-owned dictionary.
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))
        try:
            uuid.UUID(self.request_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("request_id must be a valid UUID") from exc


@dataclass(frozen=True, slots=True)
class PluginResult:
    """Normalized result for CLI, MCP, agents, and pipelines."""
    plugin_id: str
    plugin_version: str
    request_id: str
    actor: str
    ok: bool
    duration_ms: int
    data: JsonObject | list[Any] | None = None
    warnings: tuple[str, ...] = ()
    error: JsonObject | None = None

    def to_dict(self) -> JsonObject:
        payload = asdict(self)
        payload["warnings"] = list(self.warnings)
        return payload


class BasePlugin(ABC):
    """Stable interface implemented by internal and explicitly trusted plugins."""
    metadata: PluginMetadata

    @abstractmethod
    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject | list[Any]:
        """Execute the plugin and return a JSON-serializable value."""

    def health(self) -> PluginHealth:
        return PluginHealth(available=True)

    def requests_side_effects(self, payload: JsonObject) -> bool:
        return self.metadata.side_effects and bool(payload.get("apply"))

    def authorize(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        """Apply the normal policy to direct calls as well as runtime calls.

        Official plugins call this before work. The runtime's exact object
        binding reuses an existing admission without consuming a lab approval
        twice. External Python plugins remain explicitly trusted code.
        """
        admitted = _ADMITTED_REQUEST.get() == (id(self), id(payload), id(context))
        if not admitted:
            try:
                payload = json.loads(canonical_json(payload))
            except ValueError as exc:
                raise InputValidationError(str(exc)) from exc
        validate_json_schema(payload, self.metadata.input_schema)
        if not admitted:
            ExecutionPolicy().validate(self, payload, context)
        check_execution()
        return payload


class ExecutionPolicy:
    """Centralized authorization with operator-provisioned controlled-lab approval."""

    def validate(self, plugin: BasePlugin, payload: JsonObject, context: PluginContext) -> None:
        metadata = plugin.metadata
        authorization = (context.authorization or "").strip()
        if metadata.requires_authorization and len(authorization) < 12:
            raise AuthorizationError("an explicit authorization reference is required")
        effects = plugin.requests_side_effects(payload)
        network = needs_network(metadata.plugin_id, payload, metadata.network_access, effects)
        if network and not context.allow_network:
            raise AuthorizationError(f"plugin {metadata.plugin_id} requires explicit network permission")
        if effects and not context.allow_side_effects:
            raise AuthorizationError(f"plugin {metadata.plugin_id} requires explicit side-effect permission")
        try:
            enforce_request(metadata.plugin_id, payload, authorization=authorization, actor=context.actor,
                            request_id=context.request_id, network=network, side_effects=effects)
        except ControlDenied as exc:
            raise AuthorizationError(str(exc)) from exc
        except (OSError, ValueError) as exc:
            raise AuthorizationError("controlled-operation configuration is invalid or inaccessible") from exc


class PluginRegistry:
    """Deterministic registry. Loading external Python code requires explicit opt-in."""
    ENTRY_POINT_GROUP = "orion.plugins"

    def __init__(self, *, load_external: bool = False) -> None:
        self._plugins: MutableMapping[str, BasePlugin] = {}
        self._discovery_errors: list[JsonObject] = []
        self._load_builtins()
        if load_external:
            self._load_entry_points()

    @property
    def discovery_errors(self) -> tuple[JsonObject, ...]:
        return tuple(self._discovery_errors)

    def _load_builtins(self) -> None:
        from .builtin import BUILTIN_PLUGINS
        from .osint import OSINT_PLUGINS
        for plugin_type in (*BUILTIN_PLUGINS, *OSINT_PLUGINS):
            self.register(plugin_type())

    def _load_entry_points(self) -> None:
        entry_points = importlib.metadata.entry_points()
        selected: Iterable[Any]
        if hasattr(entry_points, "select"):
            selected = entry_points.select(group=self.ENTRY_POINT_GROUP)
        else:  # pragma: no cover
            selected = entry_points.get(self.ENTRY_POINT_GROUP, [])
        for entry_point in selected:
            try:
                loaded = entry_point.load()
                plugin = loaded() if isinstance(loaded, type) else loaded
                if not isinstance(plugin, BasePlugin):
                    raise TypeError(f"entry point {entry_point.name!r} does not implement BasePlugin")
                if plugin.metadata.plugin_id in self._plugins:
                    continue
                self.register(plugin)
            except Exception as exc:  # noqa: BLE001
                self._discovery_errors.append({"entry_point": entry_point.name, "type": type(exc).__name__, "message": str(exc)})

    def register(self, plugin: BasePlugin) -> None:
        if not isinstance(plugin, BasePlugin):
            raise TypeError("plugin must implement BasePlugin")
        plugin_id = plugin.metadata.plugin_id
        if plugin_id in self._plugins:
            raise ValueError(f"duplicate plugin: {plugin_id}")
        self._plugins[plugin_id] = plugin

    def get(self, plugin_id: str) -> BasePlugin:
        try:
            return self._plugins[plugin_id]
        except KeyError as exc:
            available = ", ".join(sorted(self._plugins))
            raise PluginNotFoundError(f"plugin not found: {plugin_id}; available: {available}") from exc

    def list(self) -> tuple[BasePlugin, ...]:
        return tuple(self._plugins[key] for key in sorted(self._plugins))

    def health(self) -> JsonObject:
        return {plugin.metadata.plugin_id: plugin.health().to_dict() for plugin in self.list()}

    def manifest(self) -> JsonObject:
        from orion import __version__
        return {"manifest_version": "2.0", "runtime": {
            "name": "orion-hacking-etico", "version": __version__,
            "python_runtime": platform.python_version(), "minimum_python": "3.10",
            "entry_point_group": self.ENTRY_POINT_GROUP,
        }, "plugins": [plugin.metadata.to_dict() for plugin in self.list()]}


class OrionRuntime:
    """Uniform facade with cooperative deadlines and immutable request snapshots.

    Native Python plugins must cooperate with cancellation. External ToolRunner
    processes enforce the inherited deadline while the runtime rejects late data.
    """

    def __init__(self, registry: PluginRegistry | None = None, policy: ExecutionPolicy | None = None) -> None:
        self.registry = registry or PluginRegistry()
        self.policy = policy or ExecutionPolicy()

    def execute(self, plugin_id: str, payload: JsonObject, context: PluginContext, *,
                timeout_seconds: float | None = None, raise_errors: bool = False) -> PluginResult:
        plugin = self.registry.get(plugin_id)
        metadata = plugin.metadata
        timeout = timeout_seconds if timeout_seconds is not None else metadata.default_timeout_seconds
        if type(timeout) not in {int, float} or not math.isfinite(timeout) or timeout <= 0 or timeout > metadata.max_timeout_seconds:
            raise InputValidationError(f"timeout_seconds must be finite and between 0 and {metadata.max_timeout_seconds}")
        try:
            # The same detached JSON snapshot is validated, authorized, and run;
            # another thread cannot mutate the caller's dictionary after review.
            payload = json.loads(canonical_json(payload))
        except ValueError as exc:
            raise InputValidationError(str(exc)) from exc
        validate_json_schema(payload, metadata.input_schema)
        try:
            self.policy.validate(plugin, payload, context)
        except Exception:
            try:
                audit_event("denied", plugin_id, context.request_id, context.actor)
            except Exception:
                pass  # Never execute when the denial itself cannot be logged.
            raise
        audit_event("started", plugin_id, context.request_id, context.actor)
        started = time.perf_counter()
        try:
            with execution_scope(timeout_seconds=timeout):
                health = plugin.health()
                if not health.available:
                    raise ToolUnavailableError(health.message or f"plugin {plugin_id} is unavailable")
                check_execution()
                admission = _ADMITTED_REQUEST.set((id(plugin), id(payload), id(context)))
                try:
                    data = plugin.run(payload, context)
                finally:
                    _ADMITTED_REQUEST.reset(admission)
                check_execution()
                canonical_json(data)
                data = redact_data(data, context.environment)
                validate_json_schema(data, metadata.output_schema)
                check_execution()
            duration_ms = round((time.perf_counter() - started) * 1000)
            audit_event("succeeded", plugin_id, context.request_id, context.actor)
            return PluginResult(plugin_id=metadata.plugin_id, plugin_version=metadata.version,
                                request_id=context.request_id, actor=context.actor, ok=True,
                                duration_ms=duration_ms, data=data)
        except Exception as exc:  # noqa: BLE001
            duration_ms = round((time.perf_counter() - started) * 1000)
            try:
                event = "cancelled" if isinstance(exc, ExecutionCancelledError) else "failed"
                audit_event(event, plugin_id, context.request_id, context.actor)
            except Exception:
                pass
            if raise_errors:
                raise
            return PluginResult(plugin_id=metadata.plugin_id, plugin_version=metadata.version,
                                request_id=context.request_id, actor=context.actor, ok=False,
                                duration_ms=duration_ms,
                                error={"type": type(exc).__name__, "message": redact_text(str(exc), context.environment)[:2048]})
        except BaseException:
            try:
                audit_event("cancelled", plugin_id, context.request_id, context.actor)
            except Exception:
                pass
            raise


def dumps_json(payload: Any) -> str:
    """Serialize data using ORION's canonical pretty JSON representation."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False)
