"""Runtime isolation, schema correctness, and cooperative budget contracts."""

from __future__ import annotations

import math
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from orion.plugins.builtin import _parallel_map
from orion.plugins.core import (
    AuthorizationError,
    BasePlugin,
    ExecutionPolicy,
    InputValidationError,
    OrionRuntime,
    PluginContext,
    PluginMetadata,
    PluginRegistry,
    validate_json_schema,
)
from orion.plugins.execution import ExecutionCancellation, execution_scope, remaining_timeout


class LocalTestPlugin(BasePlugin):
    metadata = PluginMetadata(
        plugin_id="local_test_plugin", name="Local test", version="1.0.0", category="test",
        description="Offline synthetic fixture.", risk_level="low", capabilities=("offline-test",),
        input_schema={"type": "object"}, output_schema={"type": "object"},
        default_timeout_seconds=1, max_timeout_seconds=5,
    )

    def run(self, payload: dict[str, Any], context: PluginContext) -> dict[str, Any]:
        return payload


def runtime_with(plugin: BasePlugin, policy: ExecutionPolicy | None = None) -> OrionRuntime:
    registry = PluginRegistry()
    registry.register(plugin)
    return OrionRuntime(registry, policy)


def context(**kwargs: Any) -> PluginContext:
    return PluginContext(authorization="OFFLINE-TEST-REFERENCE", **kwargs)


@pytest.mark.parametrize("value", [
    {"unconstrained": {"x": math.nan}}, {"unconstrained": [math.inf]},
    {"unconstrained": object()}, {"unconstrained": b"bytes"}, {1: "not-json-object-key"},
])
def test_unconstrained_schema_nodes_still_require_json(value: Any) -> None:
    with pytest.raises(InputValidationError):
        validate_json_schema(value, {"type": "object"})


def test_cyclic_python_value_is_rejected_as_bounded_json() -> None:
    value: list[Any] = []
    value.append(value)
    with pytest.raises(InputValidationError):
        validate_json_schema(value, {})


@pytest.mark.parametrize("value", [[1, 1.0], [{"x": 1}, {"x": 1.0}], [[1], [1.0]]])
def test_unique_items_uses_json_numeric_equivalence(value: list[Any]) -> None:
    with pytest.raises(InputValidationError, match="duplicate"):
        validate_json_schema(value, {"type": "array", "uniqueItems": True})


def test_unique_items_keeps_booleans_separate_from_numbers() -> None:
    validate_json_schema([True, 1, False, 0], {"type": "array", "uniqueItems": True})


def test_additional_properties_schema_is_enforced() -> None:
    schema = {"type": "object", "properties": {"name": {"type": "string"}},
              "additionalProperties": {"type": "integer", "minimum": 0}}
    validate_json_schema({"name": "ok", "count": 2}, schema)
    with pytest.raises(InputValidationError):
        validate_json_schema({"name": "ok", "count": "injected"}, schema)


def test_false_items_schema_rejects_all_array_items() -> None:
    validate_json_schema([], {"type": "array", "items": False})
    with pytest.raises(InputValidationError):
        validate_json_schema([None], {"type": "array", "items": False})


@pytest.mark.parametrize("schema", [
    {"$ref": "#/unknown"}, {"not": {"$ref": "#/unknown"}},
    {"anyOf": [{"type": "string"}, {"$ref": "#/unknown"}]},
    {"properties": {"unused": {"$ref": "#/unknown"}}},
])
def test_unsupported_schema_assertions_never_silently_pass(schema: dict[str, Any]) -> None:
    with pytest.raises(InputValidationError, match="unsupported schema"):
        validate_json_schema("string", schema)


@pytest.mark.parametrize("schema", [
    {"oneOf": []}, {"type": ["string", "string"]}, {"type": 3}, {"required": "name"},
    {"properties": []}, {"minLength": True}, {"minimum": True}, {"pattern": "["}, {"uniqueItems": 1},
])
def test_malformed_schema_has_actionable_validation_error(schema: dict[str, Any]) -> None:
    with pytest.raises(InputValidationError):
        validate_json_schema("value", schema)


def test_allof_and_not_composition() -> None:
    schema = {"allOf": [{"type": "integer"}, {"minimum": 1}], "not": {"const": 2}}
    validate_json_schema(3, schema)
    with pytest.raises(InputValidationError):
        validate_json_schema(2, schema)


def test_context_snapshots_the_supplied_environment() -> None:
    supplied = {"API_TOKEN": "original"}
    execution_context = context(environment=supplied)
    supplied["API_TOKEN"] = "changed"
    assert execution_context.environment["API_TOKEN"] == "original"
    with pytest.raises(TypeError):
        execution_context.environment["API_TOKEN"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize("environment", [
    {"BAD NAME": "value"}, {"OK": "value\x00injected"}, {"OK": 5}, {"OK": "x" * 4097},
])
def test_context_rejects_malformed_environment(environment: Any) -> None:
    with pytest.raises(ValueError, match="environment"):
        context(environment=environment)


def test_runtime_executes_the_same_payload_snapshot_that_was_reviewed() -> None:
    payload: dict[str, Any] = {"target": {"value": "reviewed"}}

    class MutatingCallerPolicy(ExecutionPolicy):
        def validate(self, plugin: BasePlugin, reviewed: dict[str, Any], execution_context: PluginContext) -> None:
            super().validate(plugin, reviewed, execution_context)
            payload["target"]["value"] = "unreviewed"

    result = runtime_with(LocalTestPlugin(), MutatingCallerPolicy()).execute("local_test_plugin", payload, context())
    assert result.ok is True
    assert payload["target"]["value"] == "unreviewed"
    assert result.data == {"target": {"value": "reviewed"}}


def test_late_python_result_is_rejected_without_claiming_preemption() -> None:
    class SlowPlugin(LocalTestPlugin):
        def run(self, payload: dict[str, Any], execution_context: PluginContext) -> dict[str, Any]:
            time.sleep(0.04)
            return {"late": True}

    result = runtime_with(SlowPlugin()).execute("local_test_plugin", {}, context(), timeout_seconds=0.01)
    assert result.ok is False and result.data is None
    assert result.error and result.error["type"] == "TimeoutError"


def test_nested_execution_scope_cannot_extend_parent_deadline() -> None:
    with execution_scope(timeout_seconds=0.25):
        first = remaining_timeout(10)
        with execution_scope(timeout_seconds=20):
            nested = remaining_timeout(20)
    assert 0 < nested <= first <= 0.25


def test_runtime_cancellation_prevents_plugin_execution() -> None:
    class MustNotRun(LocalTestPlugin):
        def run(self, payload: dict[str, Any], execution_context: PluginContext) -> dict[str, Any]:
            pytest.fail("cancelled execution called plugin.run")

    cancellation = ExecutionCancellation()
    with execution_scope(cancellation=cancellation):
        cancellation.cancel()
        result = runtime_with(MustNotRun()).execute("local_test_plugin", {}, context())
    assert result.ok is False
    assert result.error and result.error["type"] == "ExecutionCancelledError"


def test_native_parallel_workers_receive_parent_budget() -> None:
    with execution_scope(timeout_seconds=1):
        results = _parallel_map(lambda _: {"remaining": remaining_timeout(20)}, ["one", "two"], workers=2)
    assert all(0 < result["remaining"] <= 1 for result in results)


def test_runtime_redacts_secrets_from_structured_output() -> None:
    result = runtime_with(LocalTestPlugin()).execute("local_test_plugin", {"value": "synthetic-api-secret"},
                                                     context(environment={"API_TOKEN": "synthetic-api-secret"}))
    assert result.ok is True
    assert result.data == {"value": "[REDACTED]"}


def test_runtime_redacts_and_bounds_plugin_failure_messages() -> None:
    class FailingPlugin(LocalTestPlugin):
        def run(self, payload: dict[str, Any], execution_context: PluginContext) -> dict[str, Any]:
            raise RuntimeError("synthetic-api-secret " + "x" * 10000)

    result = runtime_with(FailingPlugin()).execute("local_test_plugin", {},
                                                   context(environment={"API_TOKEN": "synthetic-api-secret"}))
    assert result.error
    assert "synthetic-api-secret" not in result.error["message"]
    assert len(result.error["message"]) <= 2048


def test_direct_tls_call_requires_operator_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    from orion.plugins.builtin import TlsPostureAuditPlugin
    from orion.scripts import tls_posture_audit

    monkeypatch.delenv("ORION_LAB_APPROVAL_FILE", raising=False)
    monkeypatch.delenv("ORION_AUDIT_DATABASE", raising=False)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("TLS engine ran without operator approval")

    monkeypatch.setattr(tls_posture_audit, "audit_target", forbidden)
    with pytest.raises(AuthorizationError, match="ORION_LAB_APPROVAL_FILE"):
        TlsPostureAuditPlugin().run({"targets": ["127.0.0.1:8443"], "workers": 1, "timeout": 0.5},
                                   context(allow_network=True))


def test_runtime_tls_consumes_exactly_one_approval_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from orion.controls import request_fingerprint
    from orion.scripts import tls_posture_audit

    payload = {"targets": ["127.0.0.1:8443"], "workers": 1, "timeout": 0.5}
    now = datetime.now(timezone.utc)
    document = {
        "schema_version": 1, "authorization": "OFFLINE-TEST-REFERENCE", "actor": "pytest",
        "asset_owner": "synthetic-owner", "approved_by": "synthetic-reviewer",
        "purpose": "offline TLS fixture", "legal_basis_reference": "SYNTHETIC-TEST-ONLY",
        "environment": "isolated-lab", "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(), "revoked": False,
        "request_sha256": request_fingerprint("tls_posture_audit", payload), "max_uses": 1,
    }
    permit = tmp_path / "synthetic-permit.json"
    permit.write_text(json.dumps(document), encoding="utf-8")
    permit.chmod(0o600)
    database = tmp_path / "audit.sqlite3"
    monkeypatch.setenv("ORION_LAB_APPROVAL_FILE", str(permit))
    monkeypatch.setenv("ORION_AUDIT_DATABASE", str(database))
    monkeypatch.setattr(tls_posture_audit, "audit_target", lambda target, timeout: {
        "target": target, "synthetic_fixture": True, "network_contacted": False,
    })
    result = OrionRuntime().execute("tls_posture_audit", payload, context(allow_network=True, actor="pytest"))
    assert result.ok is True, result.error
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM uses").fetchone()[0] == 1


def test_nested_plugin_cannot_reuse_parent_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    from orion.plugins.osint import SherlockPlugin

    nested = SherlockPlugin()

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("nested OSINT execution inherited another plugin's admission")

    monkeypatch.setattr(nested.runner, "run", forbidden)

    class ParentPlugin(LocalTestPlugin):
        def run(self, payload: dict[str, Any], execution_context: PluginContext) -> dict[str, Any]:
            self.authorize(payload, execution_context)
            return nested.run({"usernames": ["synthetic_user"]}, execution_context)

    with pytest.raises(AuthorizationError, match="not admitted"):
        runtime_with(ParentPlugin()).execute("local_test_plugin", {}, context(allow_network=True), raise_errors=True)
