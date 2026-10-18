#!/usr/bin/env python3
"""
ioc_enricher.py - Enriquecimiento seguro de IOCs con servicios opcionales.

Entradas:
- --ioc VALUE (repetible)
- --input FILE.json con lista de IOCs

Servicios opcionales por variables de entorno:
- VT_API_KEY
- ABUSEIPDB_API_KEY
- SHODAN_API_KEY
- OTX_API_KEY

Salida:
- JSON normalizado con clasificacion local, resolucion DNS y enriquecimiento externo opcional
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from orion.jsonio import read_json, read_json_file


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_SERVICE_HOSTS = frozenset({"www.virustotal.com", "api.abuseipdb.com", "api.shodan.io", "otx.alienvault.com"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enriquece IOCs de forma segura.")
    parser.add_argument("--ioc", action="append", default=[], help="IOC individual.")
    parser.add_argument("--input", help="Archivo JSON con lista de IOCs.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout de red.")
    parser.add_argument("--output", help="Archivo JSON de salida. Por defecto stdout.")
    return parser.parse_args()


def load_iocs(args: argparse.Namespace) -> List[str]:
    values = list(args.ioc)
    if args.input:
        data = read_json_file(args.input)
        if isinstance(data, list) and all(isinstance(item, str) for item in data):
            values.extend(data)
        else:
            raise ValueError("El archivo de entrada debe contener una lista JSON.")
    deduped = []
    seen = set()
    for value in values:
        cleaned = value.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)
    if not deduped:
        raise ValueError("No se recibieron IOCs.")
    if len(deduped) > 500 or any(len(ioc) > 2048 for ioc in deduped):
        raise ValueError("IOC count or item length exceeds the configured limit")
    return deduped


def classify_ioc(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash"
    if DOMAIN_RE.match(value):
        return "domain"
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    return "unknown"


def dns_lookup(value: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"resolved_ips": [], "reverse_dns": None}
    try:
        _, _, addrs = socket.gethostbyname_ex(value)
        result["resolved_ips"] = sorted(set(addrs))
    except OSError as exc:
        result["dns_error"] = str(exc)
    if result["resolved_ips"]:
        try:
            result["reverse_dns"] = socket.gethostbyaddr(result["resolved_ips"][0])[0]
        except OSError:
            pass
    return result


def fetch_json(url: str, headers: Dict[str, str], timeout: float) -> Dict[str, Any]:
    """Trusted integration helper: fixed HTTPS services, bounded JSON, no redirects.

    CLI/MCP never expose this helper and the controlled policy denies external
    enrichment. A custom Python integration must authorize it before calling.
    """
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in _SERVICE_HOSTS
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or parsed.port not in {None, 443}
            or any(ord(char) < 33 or ord(char) == 127 for char in url)):
        raise ValueError("external enrichment requires an approved HTTPS service URL")
    if type(timeout) not in {float, int} or not 0.1 <= timeout <= 30:
        raise ValueError("external enrichment timeout must be finite and between 0.1 and 30 seconds")
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        payload = read_json(response)
    if not isinstance(payload, dict):
        raise ValueError("external enrichment response must be a JSON object")
    return payload


def safe_fetch(label: str, fn) -> Dict[str, Any]:
    try:
        data = fn()
        return {"ok": True, "source": label, "data": data}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "source": label, "error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        # Transport exception text can contain a complete URL, including API keys.
        return {"ok": False, "source": label, "error": type(exc).__name__}


def enrich_external(ioc_type: str, value: str, timeout: float) -> Dict[str, Any]:
    integrations: Dict[str, Any] = {}

    vt_key = os.getenv("VT_API_KEY")
    if vt_key:
        encoded = urllib.parse.quote(value, safe="")
        url = f"https://www.virustotal.com/api/v3/search?query={encoded}"
        integrations["virustotal"] = safe_fetch(
            "virustotal",
            lambda: fetch_json(url, {"x-apikey": vt_key}, timeout),
        )

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    if abuse_key and ioc_type == "ip":
        query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
        url = f"https://api.abuseipdb.com/api/v2/check?{query}"
        integrations["abuseipdb"] = safe_fetch(
            "abuseipdb",
            lambda: fetch_json(url, {"Key": abuse_key, "Accept": "application/json"}, timeout),
        )

    shodan_key = os.getenv("SHODAN_API_KEY")
    if shodan_key and ioc_type == "ip":
        url = f"https://api.shodan.io/shodan/host/{value}?key={shodan_key}"
        integrations["shodan"] = safe_fetch(
            "shodan",
            lambda: fetch_json(url, {}, timeout),
        )

    otx_key = os.getenv("OTX_API_KEY")
    if otx_key and ioc_type in {"domain", "ip", "hash"}:
        section = {"domain": "domain", "ip": "IPv4", "hash": "file"}[ioc_type]
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general"
        integrations["alienvault_otx"] = safe_fetch(
            "alienvault_otx",
            lambda: fetch_json(url, {"X-OTX-API-KEY": otx_key}, timeout),
        )

    return integrations


def build_record(value: str, timeout: float, *, allow_network: bool = False) -> Dict[str, Any]:
    """Classify an IOC offline by default. Online enrichment requires explicit opt-in.

    The direct CLI does not expose online mode in the controlled profile.
    All external-source operations remain subject to the higher-level policy.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("IOC must be a string of 1 to 2048 characters")
    if type(allow_network) is not bool:
        raise ValueError("allow_network must be a boolean")
    ioc_type = classify_ioc(value)
    record: Dict[str, Any] = {
        "value": value,
        "type": ioc_type,
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "local": {},
        "external": {},
    }
    if ioc_type == "ip":
        ip = ipaddress.ip_address(value)
        record["local"] = {
            "version": ip.version,
            "is_private": ip.is_private,
            "is_global": ip.is_global,
            "is_multicast": ip.is_multicast,
            "is_reserved": ip.is_reserved,
        }
    elif ioc_type == "domain":
        record["local"] = {"normalized": value.casefold(), "dns_performed": False}
    elif ioc_type == "url":
        parsed = urllib.parse.urlparse(value)
        record["local"] = {
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "path": parsed.path,
        }
        record["local"]["dns_performed"] = False
    elif ioc_type == "hash":
        record["local"] = {"algorithm_guess": {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))}
    record["local"].setdefault("dns_performed", False)
    if allow_network:
        if not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 30:
            raise ValueError("online timeout must be between 0.1 and 30 seconds")
        if ioc_type in {"domain", "url"}:
            hostname = value if ioc_type == "domain" else urllib.parse.urlsplit(value).hostname
            if hostname:
                record["local"]["dns"] = dns_lookup(hostname)
                record["local"]["dns_performed"] = True
        record["external"] = enrich_external(ioc_type, value, timeout)
    record["classification_only"] = not allow_network
    return record


def write_output(payload: Dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    if output:
        with open(output, "x", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    else:
        print(rendered)


def main() -> int:
    try:
        args = parse_args()
        iocs = load_iocs(args)
        payload = {
            "tool": "ioc_enricher",
            "count": len(iocs),
            "items": [build_record(ioc, args.timeout) for ioc in iocs],
        }
        write_output(payload, args.output)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[ioc_enricher] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
