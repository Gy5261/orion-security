"""Bounded TLS certificate fingerprint inventory for exact, approved lab peers.

A successful handshake is not certificate trust verification. This module
discloses verification status explicitly and never fabricates certificate
subjects, issuer names, validity dates or expiry from an unverified socket.
CLI requests are dispatched through the ORION authorization runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orion.controls import lab_preflight
from orion.plugins.core import AuthorizationError, OrionRuntime, PluginContext


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect approved isolated-lab TLS peers.")
    parser.add_argument("--host", action="append", default=[], help="Literal private IPv4 or loopback with optional port.")
    parser.add_argument("--input", type=Path, help="Plain UTF-8 text file with one explicit lab IP per line.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Socket timeout 0.1..10 seconds.")
    parser.add_argument("--workers", type=int, default=2, help="At most four workers.")
    parser.add_argument("--authorization", required=True, help="Previously approved authorization reference.")
    parser.add_argument("--actor", default="local-user", help="Operator audit label, not identity proof.")
    parser.add_argument("--allow-network", action="store_true", help="Explicit consent to the approved local-lab probe.")
    parser.add_argument("--output", type=Path, help="Create new JSON output without overwriting existing files.")
    return parser.parse_args(argv)


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.host)
    if args.input:
        with args.input.open("rb") as handle:
            raw = handle.read(8193)
        if len(raw) > 8192:
            raise ValueError("TLS target file exceeds 8 KiB")
        targets.extend(raw.decode("utf-8").splitlines())
    unique = list(dict.fromkeys(target.strip() for target in targets if target.strip()))
    if not 1 <= len(unique) <= 16:
        raise ValueError("TLS assessment requires 1 to 16 laboratory IP targets")
    return unique


def split_host_port(target: str) -> tuple[str, int]:
    peer = lab_preflight({"targets": [target], "workers": 1, "timeout": 5})["peers"][0]
    return peer["address"], peer["port"]


def cert_to_json(cert: dict[str, Any]) -> dict[str, Any]:
    """Parse only an actual populated certificate mapping; missing is unknown."""
    if not cert:
        return {"available": False, "verification": "not_performed",
                "subject": None, "issuer": None, "subject_alt_names": None, "days_until_expiry": None}

    def flatten(items: Any) -> list[dict[str, str]]:
        return [{str(key): str(value) for key, value in entry} for entry in items]

    subject = flatten(cert.get("subject", []))
    issuer = flatten(cert.get("issuer", []))
    expiry = cert.get("notAfter")
    days = None
    if expiry:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc)
        days = (expires_at - datetime.now(timezone.utc)).days
    return {
        "available": True, "verification": "provided_by_caller",
        "subject": subject, "issuer": issuer,
        "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
        "serial_number": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"), "not_after": expiry,
        "days_until_expiry": days,
    }


def audit_target(target: str, timeout: float) -> dict[str, Any]:
    """Inspect bounded TLS metadata without claiming certificate validation."""
    from orion.plugins.execution import check_execution, remaining_timeout

    check_execution()
    peer = lab_preflight({"targets": [target], "workers": 1, "timeout": timeout})["peers"][0]
    host, port = peer["address"], peer["port"]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=remaining_timeout(timeout)) as sock:
        # TCP connect and TLS handshake share the runtime's remaining budget.
        sock.settimeout(remaining_timeout(timeout))
        with context.wrap_socket(sock, server_hostname=None) as tls_sock:
            tls_sock.settimeout(remaining_timeout(timeout))
            certificate = tls_sock.getpeercert(binary_form=True)
            cipher = tls_sock.cipher()
            check_execution()
            return {
                "target": target, "peer_ip": tls_sock.getpeername()[0],
                "version": tls_sock.version(),
                "cipher": {"name": cipher[0] if cipher else None,
                           "protocol": cipher[1] if cipher else None,
                           "bits": cipher[2] if cipher else None},
                "certificate": {
                    "available": bool(certificate),
                    "der_sha256": hashlib.sha256(certificate).hexdigest() if certificate else None,
                    "trust_verified": False, "hostname_verified": False,
                    "subject": None, "issuer": None, "days_until_expiry": None,
                },
                "assessment": "TLS handshake and certificate fingerprint only, NOT trust verification",
            }


def write_output(payload: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if output:
        with output.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        targets = load_targets(args)
        payload = {"targets": targets, "workers": args.workers, "timeout": args.timeout}
        context = PluginContext(authorization=args.authorization, actor=args.actor,
                                allow_network=args.allow_network)
        try:
            result = OrionRuntime().execute("tls_posture_audit", payload, context)
        except AuthorizationError as exc:
            write_output({"ok": False, "error": {"type": "AuthorizationError", "message": str(exc)},
                          "targets_succeeded": 0, "targets_failed": 0}, args.output)
            return 1
        report = result.to_dict()
        items = report.get("data", {}).get("items", []) if report.get("ok") else []
        report["targets_succeeded"] = sum("error" not in item for item in items)
        report["targets_failed"] = sum("error" in item for item in items)
        write_output(report, args.output)
        return 0 if result.ok and report["targets_failed"] == 0 else 1
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
