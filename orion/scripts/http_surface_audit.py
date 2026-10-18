"""Inspect HTTP response headers from fixtures or explicit loopback laboratories.

This tool reports configuration observations, NOT confirmed exploitable flaws.
External and private-network targets are denied: use offline exported headers
for non-loopback assets and the approved ORION runtime for authorized probes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping

from orion.jsonio import read_json_file

MAX_BODY_BYTES = 1024 * 1024
MAX_TARGETS = 16
DEFAULT_TIMEOUT = 5.0
USER_AGENT = "ORION-controlled-http-review/2.0"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow Location headers to unreviewed network destinations."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _loopback_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    if (parsed.scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None
            or not parsed.hostname or parsed.fragment or any(ord(c) < 32 for c in raw)):
        raise ValueError("only literal HTTP(S) loopback URLs without credentials or fragments are allowed")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        if not address.is_loopback:
            raise ValueError("only loopback IP literals are allowed; export remote headers for offline review")
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("port out of range")
    except ValueError as exc:
        raise ValueError("target must use a loopback IP literal, for example 127.0.0.1") from exc
    return raw


def fetch_with_retry(url: str, max_retries: int = 2, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Perform bounded, no-proxy, no-redirect GET against loopback only."""
    url = _loopback_url(url)
    if not 1 <= max_retries <= 3 or not math.isfinite(timeout) or not 0.1 <= timeout <= 10:
        raise ValueError("invalid retry count or timeout")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for attempt in range(max_retries):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}, method="HEAD")
        try:
            with opener.open(request, timeout=timeout) as response:
                return {"url": url, "status": response.status,
                        "headers": {key.casefold(): value for key, value in response.headers.items()},
                        "error": None, "network_contacted": True}
        except urllib.error.HTTPError as exc:
            # Includes denied redirects: record only headers; never follow Location.
            return {"url": url, "status": exc.code,
                    "headers": {key.casefold(): value for key, value in exc.headers.items()},
                    "error": None, "network_contacted": True,
                    "redirect_followed": False}
        except (TimeoutError, OSError, urllib.error.URLError) as exc:
            if attempt == max_retries - 1:
                return {"url": url, "status": None, "headers": {}, "error": str(exc),
                        "network_contacted": True}
            time.sleep(min(0.1 * (2 ** attempt), 0.4))
    raise AssertionError("unreachable retry state")


def _normalize_headers(raw: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("header names and values must be strings without invalid name controls")
        if len(name) > 256 or len(value) > 4096:
            raise ValueError("header exceeds size limit")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("invalid HTTP header name")
        if any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in value):
            raise ValueError("invalid HTTP header value")
        if name.casefold() in result:
            raise ValueError("duplicate HTTP header name")
        result[name.casefold()] = value
    return result


def analyze_headers(headers: Mapping[str, str], scheme: str = "https") -> tuple[list[dict[str, Any]], float]:
    """Return independently reviewable observations and a NON-CVSS heuristic."""
    headers = _normalize_headers(headers)
    observations: list[dict[str, Any]] = []

    def note(header: str, state: str, severity: str, description: str, weight: float = 0.0) -> None:
        observations.append({"header": header, "status": state, "severity": severity,
                             "description": description, "confirmed_vulnerability": False, "weight": weight})

    if scheme == "https":
        hsts = headers.get("strict-transport-security")
        if hsts is None:
            note("strict-transport-security", "absent", "review", "HSTS not advertised on this response", 1)
        else:
            match = None
            for directive in hsts.split(";"):
                if directive.strip().casefold().startswith("max-age"):
                    match = directive.strip().partition("=")[2].strip()
                    break
            if match is None or not match.isdigit() or int(match) == 0:
                note("strict-transport-security", "invalid", "review", "HSTS max-age is absent or not positive", 1)
    csp = headers.get("content-security-policy", "")
    if not csp:
        note("content-security-policy", "absent", "review", "Content Security Policy absent; inspect application", 1)
    elif "unsafe-eval" in csp.casefold():
        note("content-security-policy", "potentially-weak", "review", "CSP permits unsafe-eval", 1)
    if not csp or "frame-ancestors" not in csp.casefold():
        if headers.get("x-frame-options", "").casefold() not in {"deny", "sameorigin"}:
            note("frame-embedding", "not-restricted", "review",
                 "No supported frame-ancestors or X-Frame-Options policy detected", 1)
    if headers.get("x-content-type-options", "").casefold() != "nosniff":
        note("x-content-type-options", "not-nosniff", "review", "MIME sniffing policy not set to nosniff", 1)
    if not headers.get("referrer-policy"):
        note("referrer-policy", "absent", "informational", "Referrer policy not advertised")
    if not headers.get("permissions-policy"):
        note("permissions-policy", "absent", "informational", "Permissions policy not advertised")
    if headers.get("server"):
        note("server", "present", "informational", "Server header present; no vulnerability inferred")
    score = min(10.0, sum(item["weight"] for item in observations))
    return observations, score


def classify_risk_level(score: float) -> str:
    """Historical compatibility label; not a security severity or CVSS score."""
    return "needs-review" if score else "no-config-observations"


def _read_offline(path: Path) -> list[dict[str, Any]]:
    data = read_json_file(path, max_bytes=MAX_BODY_BYTES)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_TARGETS:
        raise ValueError("offline input must be one response or an array of 1..16 responses")
    snapshots: list[dict[str, Any]] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict) or not isinstance(item.get("headers"), dict):
            raise ValueError(f"snapshot[{index}] requires a headers object")
        url = item.get("url", "offline://saved-response")
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError(f"snapshot[{index}] requires a bounded URL string")
        status = item.get("status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError(f"snapshot[{index}] has invalid HTTP status")
        scheme = urllib.parse.urlsplit(url).scheme
        if scheme not in {"http", "https", "offline"}:
            raise ValueError(f"snapshot[{index}] has unsupported URL scheme")
        snapshots.append({"url": url, "status": item.get("status"),
                          "headers": _normalize_headers(item["headers"]), "error": None,
                          "network_contacted": False})
    return snapshots


def _render_result(response: Mapping[str, Any]) -> dict[str, Any]:
    if response.get("error"):
        return {**dict(response), "findings": [], "risk_score": None,
                "risk_score_method": "not-evaluated", "risk_level": "not-evaluated"}
    scheme = urllib.parse.urlsplit(str(response["url"])).scheme
    observations, heuristic = analyze_headers(response["headers"], scheme=scheme)
    return {
        "url": response["url"], "status": response["status"], "error": None,
        "security_headers": dict(response["headers"]), "findings": observations,
        "risk_score": heuristic, "risk_score_method": "configuration-heuristic-not-cvss",
        "risk_level": classify_risk_level(heuristic),
        "confirmed_vulnerabilities": 0, "network_contacted": response["network_contacted"],
    }


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if not values:
        print("Uso: http_surface_audit.py --input saved-headers.json | --allow-loopback http://127.0.0.1:PORT")
        return 1
    parser = argparse.ArgumentParser(description="Review saved HTTP headers or explicitly permitted loopback responses.")
    parser.add_argument("urls", nargs="*", help="Only literal loopback IP HTTP(S) URLs.")
    parser.add_argument("--input", type=Path, help="Offline JSON response(s) with headers, status and URL.")
    parser.add_argument("--allow-loopback", action="store_true", help="Explicitly permit local laboratory HEAD requests.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(values)
    try:
        if args.input is not None:
            if args.urls or args.allow_loopback:
                raise ValueError("--input cannot be combined with live URL requests")
            snapshots = _read_offline(args.input)
        else:
            if not args.urls or not args.allow_loopback:
                raise ValueError("live requests require --allow-loopback and at least one loopback URL")
            if not 1 <= len(args.urls) <= MAX_TARGETS:
                raise ValueError("allowed target count is 1..16")
            if not 1 <= args.workers <= 4:
                raise ValueError("workers must be 1..4")
            validated = [_loopback_url(url) for url in args.urls]
            with ThreadPoolExecutor(max_workers=min(args.workers, len(validated))) as pool:
                snapshots = list(pool.map(lambda url: fetch_with_retry(url, timeout=args.timeout), validated))
        results = [_render_result(response) for response in snapshots]
        failed = sum(bool(item["error"]) for item in results)
        summary = {
            "urls_scanned": len(results), "successful_scans": len(results) - failed,
            "failed_scans": failed, "confirmed_vulnerabilities": 0,
            "configuration_observations": sum(len(item["findings"]) for item in results),
            "network_contacted": any(item["network_contacted"] for item in results),
            "assessment_scope": "header configuration review; no exploit verification",
        }
        print(json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False, allow_nan=False))
        return 1 if failed else 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
