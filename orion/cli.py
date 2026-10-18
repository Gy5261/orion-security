"""Command-line interface for the ORION runtime."""

from __future__ import annotations

# Python 3.15 defers this dependency when only interpreter diagnostics are requested.
# Earlier supported Python versions ignore __lazy_modules__ safely.
__lazy_modules__ = ["orion.plugins.core"]

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from orion import __version__
from orion.jsonio import canonical_json, read_json, read_json_file
from orion.plugins.core import (
    OrionPluginError,
    OrionRuntime,
    PluginContext,
    PluginRegistry,
    validate_json_schema,
)


def _read_json(path: str) -> dict[str, Any]:
    """Read no more than the control document budget, rejecting duplicate keys."""

    payload = read_json(sys.stdin.buffer) if path == "-" else read_json_file(path)
    if not isinstance(payload, dict):
        raise ValueError("plugin input must be a JSON object")
    return payload


def _write_json(payload: Any, output: str | None = None) -> None:
    canonical_json(payload, max_bytes=2 * 1024 * 1024)
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orion",
        description="Auditable plugin runtime for authorized defensive security.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    runtime_info = subparsers.add_parser("runtime-info", help="Inspect actual interpreter and Python 3.15 capabilities.")
    runtime_info.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    plugins = subparsers.add_parser("plugins", help="Inspect and execute plugins.")
    plugin_commands = plugins.add_subparsers(dest="plugin_command", required=True)

    list_parser = plugin_commands.add_parser("list", help="List registered plugins.")
    list_parser.add_argument("--json", action="store_true", help="Emit the complete manifest.")
    list_parser.add_argument("--health", action="store_true", help="Include dependency availability.")

    describe = plugin_commands.add_parser("describe", help="Show a plugin contract.")
    describe.add_argument("plugin_id")
    describe.add_argument("--health", action="store_true")

    run = plugin_commands.add_parser("run", help="Execute a plugin using JSON input.")
    run.add_argument("plugin_id")
    run.add_argument("--input", required=True, help="JSON file or '-' for stdin.")
    run.add_argument("--output", help="Output JSON path; defaults to stdout.")
    run.add_argument("--authorization", required=True, help="Ticket, ToR, or authorization reference.")
    run.add_argument("--actor", default="local-user")
    run.add_argument("--request-id", help="External UUID for correlation.")
    run.add_argument("--allow-network", action="store_true")
    run.add_argument("--allow-side-effects", action="store_true")
    run.add_argument("--timeout", type=float)

    export = plugin_commands.add_parser("export-manifest", help="Generate the runtime manifest.")
    export.add_argument("--output", required=True)

    doctor = plugin_commands.add_parser("doctor", help="Validate contracts and optional integrations.")
    doctor.add_argument(
        "--strict",
        action="store_true",
        help="Fail when an optional external tool is not installed.",
    )
    return parser


def _plugins_list(registry: PluginRegistry, as_json: bool, include_health: bool) -> int:
    if as_json:
        payload = registry.manifest()
        if include_health:
            payload["health"] = registry.health()
        _write_json(payload)
        return 0

    health = registry.health() if include_health else {}
    for plugin in registry.list():
        metadata = plugin.metadata
        permissions: list[str] = []
        if metadata.network_access:
            permissions.append("network")
        if metadata.side_effects:
            permissions.append("side-effects")
        suffix = f" [{', '.join(permissions)}]" if permissions else ""
        availability = ""
        if include_health:
            availability = f" {health[metadata.plugin_id]['status']}"
        print(f"{metadata.plugin_id:<24} {metadata.version:<10} {metadata.risk_level:<6}{suffix}{availability}")
    return 0


def _doctor(registry: PluginRegistry, strict: bool) -> int:
    checks: list[dict[str, Any]] = []
    unavailable = 0
    for plugin in registry.list():
        metadata = plugin.metadata
        validate_json_schema(
            metadata.to_dict(),
            {
                "type": "object",
                "required": ["plugin_id", "name", "version", "input_schema", "output_schema"],
            },
        )
        health = plugin.health()
        if not health.available:
            unavailable += 1
        checks.append(
            {
                "plugin_id": metadata.plugin_id,
                "version": metadata.version,
                "contract": "ok",
                "health": health.to_dict(),
            }
        )

    discovery_ok = not registry.discovery_errors
    ok = discovery_ok and (not strict or unavailable == 0)
    _write_json(
        {
            "ok": ok,
            "runtime_version": __version__,
            "plugin_count": len(checks),
            "available_plugins": len(checks) - unavailable,
            "optional_unavailable": unavailable,
            "strict": strict,
            "checks": checks,
            "discovery_errors": list(registry.discovery_errors),
        }
    )
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "runtime-info":
            from orion.runtime_info import interpreter_report

            _write_json(interpreter_report())
            return 0
        registry = PluginRegistry()
        if args.command == "plugins" and args.plugin_command == "list":
            return _plugins_list(registry, args.json, args.health)
        if args.command == "plugins" and args.plugin_command == "describe":
            plugin = registry.get(args.plugin_id)
            payload = plugin.metadata.to_dict()
            if args.health:
                payload["health"] = plugin.health().to_dict()
            _write_json(payload)
            return 0
        if args.command == "plugins" and args.plugin_command == "export-manifest":
            _write_json(registry.manifest(), args.output)
            return 0
        if args.command == "plugins" and args.plugin_command == "doctor":
            return _doctor(registry, args.strict)
        if args.command == "plugins" and args.plugin_command == "run":
            runtime = OrionRuntime(registry=registry)
            context_kwargs: dict[str, Any] = {
                "authorization": args.authorization,
                "actor": args.actor,
                "allow_network": args.allow_network,
                "allow_side_effects": args.allow_side_effects,
            }
            if args.request_id:
                context_kwargs["request_id"] = args.request_id
            result = runtime.execute(
                args.plugin_id,
                _read_json(args.input),
                PluginContext(**context_kwargs),
                timeout_seconds=args.timeout,
            )
            _write_json(result.to_dict(), args.output)
            return 0 if result.ok else 1
        parser.error("command not implemented")
    except (OrionPluginError, ValueError, OSError, json.JSONDecodeError) as exc:
        _write_json({"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
