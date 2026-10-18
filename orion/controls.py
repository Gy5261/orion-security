"""Fail-closed controls for trusted local operators and isolated TLS laboratories.

These controls are not legal advice, caller authentication, or an OS sandbox.
Approval files must be provisioned by an operator, never by an MCP argument.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from orion.fileio import is_link, open_regular
from orion.jsonio import MAX_DEPTH as MAX_DEPTH
from orion.jsonio import MAX_DOCUMENT_BYTES, canonical_json, loads_json

LAB_NETWORKS = tuple(ipaddress.ip_network(item) for item in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


class ControlDenied(PermissionError):
    """A controlled-operation prerequisite was not satisfied."""


def request_fingerprint(plugin_id: str, payload: Mapping[str, Any]) -> str:
    """Bind a review to an exact plugin and payload, including defaults as supplied."""
    document = {"plugin_id": plugin_id, "payload": dict(payload)}
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


def _private_path(raw: str, *, must_exist: bool) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise ControlDenied("control paths must be absolute and outside the repository")
    if any(is_link(part) for part in (path, *path.parents)):
        raise ControlDenied("control paths must not contain symbolic links")
    source_root = Path(__file__).resolve().parent
    if (source_root.parent / "pyproject.toml").is_file():
        source_root = source_root.parent
    if path.is_relative_to(source_root):
        raise ControlDenied("control paths must be outside the source or installed package")
    if os.name == "posix":
        for parent in path.parents:
            info = parent.stat()
            # Shared sticky directories such as /tmp cannot replace another
            # owner's private child. A plain group-writable parent can.
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise ControlDenied("control path parents must not be writable by other users")
    if must_exist and not path.is_file():
        raise ControlDenied("required control file is missing")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ControlDenied("control path must be a regular file")
        if info.st_nlink != 1:
            raise ControlDenied("control files must not have hard-link aliases")
        if os.name == "posix" and (info.st_mode & 0o077):
            raise ControlDenied("control files require owner-only permissions (chmod 600)")
        if os.name == "posix" and info.st_uid != os.getuid():
            raise ControlDenied("control files must be owned by the process user")
    return path


def load_private_json(raw: str) -> dict[str, Any]:
    """Read a bounded operator-owned JSON document; never follow a final symlink."""
    path = _private_path(raw, must_exist=True)
    with open_regular(path, single_link=True) as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ControlDenied("approval is not a regular file")
        if os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
            raise ControlDenied("approval permissions changed")
        raw_bytes = handle.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw_bytes) > MAX_DOCUMENT_BYTES:
        raise ControlDenied("approval exceeds 1 MiB")
    try:
        value = loads_json(raw_bytes)
        if not isinstance(value, dict):
            raise ValueError("approval must be an object")
        return value
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ControlDenied("approval is not valid bounded JSON") from exc


def needs_network(plugin_id: str, payload: Mapping[str, Any], declared: bool, effects: bool) -> bool:
    """Return the permission needed by a validated request, never by metadata alone.

    All IOC types are classified without DNS or network when external_sources is false.
    Callers MUST validate the input schema before consulting this function.
    """
    if effects:
        return True
    if plugin_id == "ioc_enricher" and payload.get("external_sources", False) is False:
        return False
    return declared


def lab_preflight(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Check exact IPv4 TLS peers without resolving DNS or opening a socket."""
    targets = payload.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 16:
        raise ControlDenied("laboratory TLS requests require 1 to 16 explicit targets")
    peers: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, str) or target != target.strip():
            raise ControlDenied("lab targets must be exact strings without surrounding whitespace")
        match = re.fullmatch(r"([0-9.]+)(?::([0-9]{1,5}))?", target)
        if match is None:
            raise ControlDenied("lab targets require literal IPv4 addresses; DNS and URLs are not allowed")
        try:
            address = ipaddress.IPv4Address(match.group(1))
        except ValueError as exc:
            raise ControlDenied("invalid IPv4 laboratory target") from exc
        port = int(match.group(2) or 443)
        if not 1 <= port <= 65535 or not any(address in network for network in LAB_NETWORKS):
            raise ControlDenied("target must be an approved loopback or RFC1918 laboratory peer")
        if address.packed[-1] in {0, 255}:
            raise ControlDenied("ambiguous network/broadcast-like laboratory address")
        peers.append({"address": str(address), "port": port})
    workers = payload.get("workers", 4)
    timeout = payload.get("timeout", 5.0)
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ControlDenied("lab workers must be between 1 and 4")
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0.1 <= timeout <= 10:
        raise ControlDenied("lab socket timeout must be between 0.1 and 10 seconds")
    return {"ok": True, "peers": peers, "workers": workers, "socket_timeout": timeout,
            "network_contacted": False, "isolation_verified": False}


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ControlDenied("approval timestamps must be ISO-8601 strings with a timezone")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError) as exc:
        raise ControlDenied("invalid approval timestamp") from exc
    if timestamp.utcoffset() is None:
        raise ControlDenied("approval timestamps require an explicit timezone")
    try:
        return timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ControlDenied("approval timestamp is outside the supported range") from exc


def review_approval(document: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Validate administrative completeness, not the authenticity of legal consent."""
    try:
        canonical_json(dict(document))
    except (ValueError, TypeError) as exc:
        raise ControlDenied("approval must be bounded JSON") from exc
    required = {"schema_version", "authorization", "actor", "asset_owner", "approved_by", "purpose",
                "legal_basis_reference", "environment", "not_before", "expires_at", "revoked",
                "request_sha256", "max_uses"}
    if set(document) != required:
        raise ControlDenied("approval must contain exactly the documented fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ControlDenied("unsupported approval schema version")
    for key in ("authorization", "actor", "asset_owner", "approved_by", "purpose", "legal_basis_reference"):
        value = document[key]
        if not isinstance(value, str) or not 3 <= len(value.strip()) <= 512:
            raise ControlDenied(f"approval field {key} must contain 3 to 512 characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ControlDenied(f"approval field {key} must not contain control characters")
    if len(document["authorization"].strip()) < 12:
        raise ControlDenied("authorization reference must contain at least 12 characters")
    if document["actor"].strip().casefold() == document["approved_by"].strip().casefold():
        raise ControlDenied("operator and reviewer labels must differ")
    if document["environment"] != "isolated-lab" or document["revoked"] is not False:
        raise ControlDenied("approval must be unrevoked and restricted to an isolated laboratory")
    if not isinstance(document["request_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", document["request_sha256"]):
        raise ControlDenied("approval must bind an exact SHA-256 request fingerprint")
    if type(document["max_uses"]) is not int or not 1 <= document["max_uses"] <= 100:
        raise ControlDenied("approval max_uses must be between 1 and 100")
    start, end = _timestamp(document["not_before"]), _timestamp(document["expires_at"])
    current = now or datetime.now(timezone.utc)
    if current.utcoffset() is None:
        raise ControlDenied("review clock requires a timezone")
    if not start <= current < end or not 0 < (end - start).total_seconds() <= 86400:
        raise ControlDenied("approval is not active or exceeds the 24-hour review window")
    return {"ok": True, "environment": "isolated-lab", "expires_at": end.isoformat(),
            "max_uses": document["max_uses"], "legal_validity_verified": False,
            "identity_verified": False, "isolation_verified": False}


def _audit_connection() -> sqlite3.Connection:
    raw = os.getenv("ORION_AUDIT_DATABASE", "")
    if not raw:
        raise ControlDenied("ORION_AUDIT_DATABASE is required for laboratory execution")
    path = _private_path(raw, must_exist=False)
    if not path.parent.is_dir():
        raise ControlDenied("create a private audit directory before execution")
    if not path.exists():
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except FileExistsError:
            pass
    _private_path(str(path), must_exist=True)
    connection = sqlite3.connect(str(path), timeout=5, isolation_level=None)
    try:
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("CREATE TABLE IF NOT EXISTS uses (approval TEXT NOT NULL, request_id TEXT PRIMARY KEY)")
        connection.execute("CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, event TEXT NOT NULL)")
        return connection
    except Exception:
        connection.close()
        raise


def audit_event(event: str, plugin_id: str, request_id: str, actor: str) -> None:
    """Append metadata only. Raw payloads, targets, credentials and errors are excluded."""
    if not os.getenv("ORION_AUDIT_DATABASE"):
        return
    record = canonical_json({"event": event, "plugin_id": plugin_id, "request_id": request_id,
                             "actor_label": actor, "time": datetime.now(timezone.utc).isoformat()})
    connection = _audit_connection()
    try:
        connection.execute("INSERT INTO events(event) VALUES (?)", (record,))
    finally:
        connection.close()


def enforce_request(plugin_id: str, payload: Mapping[str, Any], *, authorization: str,
                    actor: str, request_id: str, network: bool, side_effects: bool) -> None:
    """Default deny online activity; only reviewed, bounded TLS lab probes are admitted."""
    canonical_json(dict(payload))
    stop = os.getenv("ORION_EMERGENCY_STOP", "0").strip().casefold()
    if stop not in {"", "0", "false", "off", "no"}:
        raise ControlDenied("ORION emergency stop is active")
    if not network and not side_effects:
        return
    if side_effects:
        raise ControlDenied("writes are disabled in the controlled profile; export and review the plan instead")
    if plugin_id != "tls_posture_audit":
        raise ControlDenied("online OSINT and third-party adapters are not admitted to the controlled lab profile")
    lab_preflight(payload)
    raw = os.getenv("ORION_LAB_APPROVAL_FILE", "")
    if not raw:
        raise ControlDenied("ORION_LAB_APPROVAL_FILE must reference an operator-provisioned approval")
    document = load_private_json(raw)
    review_approval(document)
    if document["authorization"] != authorization or document["actor"] != actor:
        raise ControlDenied("request does not match the approved operator and authorization reference")
    if document["request_sha256"] != request_fingerprint(plugin_id, payload):
        raise ControlDenied("request differs from the reviewed payload")
    approval = hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
    connection = _audit_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        used = connection.execute("SELECT COUNT(*) FROM uses WHERE approval = ?", (approval,)).fetchone()[0]
        if used >= document["max_uses"]:
            raise ControlDenied("approval usage limit reached; obtain a new review")
        try:
            connection.execute("INSERT INTO uses(approval, request_id) VALUES (?, ?)", (approval, request_id))
        except sqlite3.IntegrityError as exc:
            raise ControlDenied("request identifier was already consumed") from exc
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def controls_status() -> dict[str, Any]:
    """Public status omits local paths, approval contents and operator identifiers."""
    return {"profile": "controlled", "default_network": "deny", "side_effects": "deny",
            "lab_plugin_allowlist": ["tls_posture_audit"],
            "approval_configured": bool(os.getenv("ORION_LAB_APPROVAL_FILE")),
            "audit_configured": bool(os.getenv("ORION_AUDIT_DATABASE")),
            "emergency_stop": os.getenv("ORION_EMERGENCY_STOP", "0").strip().casefold() not in {"", "0", "false", "off", "no"},
            "legal_compliance_certified": False, "os_sandbox": False,
            "actor_identity_authenticated": False}
