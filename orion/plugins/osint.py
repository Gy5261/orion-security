"""Safe adapters for established OSINT tools.

Third-party projects remain separate installations. ORION invokes trusted local
executables or a configured SpiderFoot service with bounded, structured input.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Mapping

from .adapters import (
    TemporaryToolDirectory,
    ToolRunner,
    ToolSpec,
    collect_artifacts,
    parse_json_output,
)
from .core import BasePlugin, JsonObject, PluginContext, PluginHealth, PluginMetadata
from .execution import check_execution, execution_scope, remaining_timeout

_GENERIC_OUTPUT_SCHEMA: JsonObject = {
    "type": "object",
    "required": ["tool", "result"],
    "properties": {
        "tool": {"type": "string"},
        "result": {},
        "execution": {"type": "object"},
        "artifacts": {"type": "object"},
    },
}


def _timeout(payload: Mapping[str, Any], default: float = 120.0) -> float:
    return float(payload.get("timeout_seconds", default))


def _argument_value(value: str, label: str) -> str:
    """Reject data that an external argparse/Cobra parser may interpret as flags."""
    if (not value or value != value.strip() or value.startswith("-")
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"{label} must be nonempty data without option prefixes or control characters")
    return value


def _domain(value: str) -> str:
    _argument_value(value, "domain")
    labels = value.removesuffix(".").split(".")
    if any(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None for label in labels):
        raise ValueError("domain must contain valid DNS labels")
    return value


def _web_url(value: str) -> str:
    _argument_value(value, "url")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or any(char.isspace() for char in value)):
        raise ValueError("url must be an HTTP(S) URL without embedded credentials or whitespace")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("url port must be between 1 and 65535")
    return value


def _execution_result(tool_id: str, execution: JsonObject, artifacts: JsonObject | None = None) -> JsonObject:
    parsed = parse_json_output(str(execution.get("stdout", "")))
    result: JsonObject = {
        "tool": tool_id,
        "result": parsed if parsed is not None else execution.get("stdout", ""),
        "execution": {
            "return_code": execution["return_code"],
            "duration_ms": execution["duration_ms"],
            "stderr": execution.get("stderr", ""),
            "stdout_truncated": execution.get("stdout_truncated", False),
            "stderr_truncated": execution.get("stderr_truncated", False),
        },
    }
    if artifacts:
        result["artifacts"] = artifacts
    return result


class ExternalCommandPlugin(BasePlugin):
    """Base class for allow-listed third-party command adapters."""

    tool_spec: ToolSpec

    def __init__(self) -> None:
        self.runner = ToolRunner(self.tool_spec)

    def health(self) -> PluginHealth:
        return self.runner.health()


class SpiderFootPlugin(BasePlugin):
    metadata = PluginMetadata(
        plugin_id="spiderfoot",
        name="SpiderFoot",
        version="1.0.0",
        category="osint-automation",
        description="Controls an authorized SpiderFoot service and returns normalized scan data.",
        risk_level="medium",
        capabilities=("scan-start", "scan-list", "scan-results"),
        requires_authorization=True,
        network_access=True,
        side_effects=True,
        default_timeout_seconds=60,
        max_timeout_seconds=600,
        tags=("osint", "spiderfoot", "service-adapter", "read-mostly"),
        homepage="https://github.com/smicallef/spiderfoot",
        license="MIT",
        integration="http-api",
        input_schema={
            "type": "object",
            "required": ["operation"],
            "additionalProperties": False,
            "properties": {
                "operation": {"type": "string", "enum": ["start", "list", "results", "summary"]},
                "server_url": {"type": "string", "pattern": r"^https?://", "maxLength": 2048},
                "target": {"type": "string", "minLength": 1, "maxLength": 2048},
                "scan_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "use_case": {"type": "string", "maxLength": 128},
                "modules": {
                    "type": "array",
                    "maxItems": 250,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                },
                "types": {
                    "type": "array",
                    "maxItems": 250,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                },
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 600},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def requests_side_effects(self, payload: JsonObject) -> bool:
        return payload.get("operation") == "start"

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        operation = str(payload["operation"])
        server = str(payload.get("server_url", "http://127.0.0.1:5001")).rstrip("/")
        self._validate_local_service(server)
        parsed_server = urllib.parse.urlsplit(server)
        if parsed_server.hostname == "localhost":
            port = f":{parsed_server.port}" if parsed_server.port is not None else ""
            # An OS hosts/DNS configuration must never redirect localhost to a
            # remote service. HTTPS still performs normal certificate checks.
            server = f"{parsed_server.scheme}://127.0.0.1{port}"
        timeout = _timeout(payload, 60)

        if operation == "start":
            target = str(payload.get("target", "")).strip()
            if not target:
                raise ValueError("target is required for SpiderFoot start")
            fields = {
                "scanname": str(payload.get("name", f"ORION-{target}")),
                "scantarget": target,
                "modulelist": ",".join(payload.get("modules", [])),
                "typelist": ",".join(payload.get("types", [])),
                "usecase": str(payload.get("use_case", "all")),
            }
            result = self._request(f"{server}/startscan", timeout, fields)
        elif operation == "list":
            result = self._request(f"{server}/scanlist", timeout)
        else:
            scan_id = str(payload.get("scan_id", "")).strip()
            if not scan_id:
                raise ValueError(f"scan_id is required for SpiderFoot {operation}")
            endpoint = "scansummary" if operation == "summary" else "scanexportjsonmulti"
            parameters = {"id": scan_id, "by": "type"} if operation == "summary" else {"ids": scan_id}
            query = urllib.parse.urlencode(parameters)
            result = self._request(f"{server}/{endpoint}?{query}", timeout)
        return {"tool": "spiderfoot", "result": result}

    @staticmethod
    def _validate_local_service(server: str) -> None:
        """Only an explicit local SpiderFoot service; never a remote target URL."""
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in server):
            raise ValueError("SpiderFoot server_url must not contain whitespace or control characters")
        parsed = urllib.parse.urlsplit(server)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or "%" in parsed.hostname):
            raise ValueError("SpiderFoot server_url must be a plain local HTTP(S) origin")
        if parsed.hostname != "localhost":
            try:
                if not ip_address(parsed.hostname).is_loopback:
                    raise ValueError("SpiderFoot service must be loopback-only")
            except ValueError as exc:
                raise ValueError("SpiderFoot server must use localhost or a loopback IP literal") from exc
        try:
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("invalid port")
        except ValueError as exc:
            raise ValueError("invalid SpiderFoot local port") from exc

    @staticmethod
    def _request(url: str, timeout: float, fields: Mapping[str, str] | None = None) -> Any:
        parsed_url = urllib.parse.urlsplit(url)
        SpiderFootPlugin._validate_local_service(f"{parsed_url.scheme}://{parsed_url.netloc}")
        if parsed_url.hostname == "localhost":
            raise ValueError("SpiderFoot requests require a pinned loopback IP literal")
        data = urllib.parse.urlencode(fields).encode("utf-8") if fields else None
        request = urllib.request.Request(url, data=data, method="POST" if fields else "GET")
        request.add_header("Accept", "application/json")
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                                 headers: Any, newurl: str) -> None:
                return None

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with execution_scope(timeout_seconds=timeout), opener.open(request, timeout=remaining_timeout(timeout)) as response:
                raw_bytes = bytearray()
                read_chunk = getattr(response, "read1", response.read)
                while True:
                    check_execution()
                    chunk = read_chunk(min(65536, 1024 * 1024 + 1 - len(raw_bytes)))
                    if not chunk:
                        break
                    raw_bytes.extend(chunk)
                    if len(raw_bytes) > 1024 * 1024:
                        raise ValueError("SpiderFoot response exceeds the 1 MiB limit")
                check_execution()
                raw = raw_bytes.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"SpiderFoot HTTP {exc.code}; check the local service configuration") from None
        parsed = parse_json_output(raw)
        return parsed if parsed is not None else raw


class TheHarvesterPlugin(ExternalCommandPlugin):
    tool_spec = ToolSpec(
        tool_id="theharvester",
        candidates=("theHarvester", "theharvester"),
        environment_variable="ORION_THEHARVESTER_EXECUTABLE",
        homepage="https://github.com/laramies/theHarvester",
        license="GPL-2.0-only",
    )
    metadata = PluginMetadata(
        plugin_id="theharvester",
        name="theHarvester",
        version="1.0.0",
        category="osint-reconnaissance",
        description="Collects public emails, hosts, and subdomains for an authorized domain.",
        risk_level="medium",
        capabilities=("email-discovery", "subdomain-discovery", "host-discovery"),
        network_access=True,
        tags=("osint", "domain", "external-adapter"),
        homepage=tool_spec.homepage,
        license=tool_spec.license,
        integration="subprocess",
        default_timeout_seconds=180,
        max_timeout_seconds=900,
        input_schema={
            "type": "object",
            "required": ["domain"],
            "additionalProperties": False,
            "properties": {
                "domain": {"type": "string", "pattern": r"^[A-Za-z0-9.-]+$", "maxLength": 253},
                "sources": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "uniqueItems": True,
                    "items": {"type": "string", "pattern": r"^[A-Za-z0-9_-]+$", "maxLength": 64},
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 5000},
                "dns_lookup": {"type": "boolean"},
                "quiet": {"type": "boolean"},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 900},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        domain = _domain(payload["domain"])
        sources = payload.get("sources", ["crtsh", "duckduckgo"])
        for source in sources:
            _argument_value(source, "source")
        with TemporaryToolDirectory("orion-theharvester-") as output:
            prefix = output / "results"
            arguments = [
                "-d",
                domain,
                "-b",
                ",".join(sources),
                "-l",
                str(payload.get("limit", 500)),
                "-f",
                str(prefix),
            ]
            if payload.get("dns_lookup"):
                arguments.append("-n")
            if payload.get("quiet", True):
                arguments.append("-q")
            execution = self.runner.run(
                arguments,
                timeout_seconds=_timeout(payload, 180),
                environment=context.environment,
                working_directory=output,
            )
            return _execution_result("theharvester", execution, collect_artifacts(output))


class SherlockPlugin(ExternalCommandPlugin):
    tool_spec = ToolSpec(
        tool_id="sherlock",
        candidates=("sherlock",),
        environment_variable="ORION_SHERLOCK_EXECUTABLE",
        homepage="https://github.com/sherlock-project/sherlock",
        license="MIT",
    )
    metadata = PluginMetadata(
        plugin_id="sherlock",
        name="Sherlock",
        version="1.0.0",
        category="osint-identity",
        description="Checks public username presence across configured public services.",
        risk_level="medium",
        capabilities=("username-enumeration", "public-profile-discovery"),
        network_access=True,
        tags=("osint", "username", "external-adapter"),
        homepage=tool_spec.homepage,
        license=tool_spec.license,
        integration="subprocess",
        default_timeout_seconds=180,
        max_timeout_seconds=900,
        input_schema={
            "type": "object",
            "required": ["usernames"],
            "additionalProperties": False,
            "properties": {
                "usernames": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 64},
                },
                "sites": {
                    "type": "array",
                    "maxItems": 300,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                },
                "request_timeout": {"type": "number", "minimum": 1, "maximum": 60},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 900},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        usernames = [_argument_value(item, "username") for item in payload["usernames"]]
        sites = [_argument_value(item, "site") for item in payload.get("sites", [])]
        with TemporaryToolDirectory("orion-sherlock-") as output:
            arguments = [
                *usernames,
                "--print-found",
                "--no-color",
                "--folderoutput",
                str(output),
                "--timeout",
                str(payload.get("request_timeout", 10)),
            ]
            for site in sites:
                arguments.extend(["--site", str(site)])
            execution = self.runner.run(
                arguments,
                timeout_seconds=_timeout(payload, 180),
                environment=context.environment,
            )
            return _execution_result("sherlock", execution, collect_artifacts(output))


class OsintSpyPlugin(ExternalCommandPlugin):
    tool_spec = ToolSpec(
        tool_id="osint-spy",
        candidates=("osint-spy.py", "osint-spy"),
        environment_variable="ORION_OSINT_SPY_EXECUTABLE",
        homepage="https://github.com/SharadKumar97/OSINT-SPY",
        license="GPL-3.0",
    )
    metadata = PluginMetadata(
        plugin_id="osint_spy",
        name="OSINT-SPY",
        version="1.0.0",
        category="osint-aggregation",
        description="Runs the legacy OSINT-SPY public-data modes through a constrained adapter.",
        risk_level="medium",
        capabilities=("domain-lookup", "email-lookup", "ip-lookup", "device-lookup"),
        network_access=True,
        tags=("osint", "legacy", "external-adapter"),
        homepage=tool_spec.homepage,
        license=tool_spec.license,
        integration="subprocess",
        default_timeout_seconds=120,
        max_timeout_seconds=600,
        input_schema={
            "type": "object",
            "required": ["target_type", "value"],
            "additionalProperties": False,
            "properties": {
                "target_type": {"type": "string", "enum": ["domain", "email", "ip", "device"]},
                "value": {"type": "string", "minLength": 1, "maxLength": 512},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 600},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        value = _argument_value(payload["value"], "value")
        if payload["target_type"] == "domain":
            _domain(value)
        elif payload["target_type"] == "ip":
            ip_address(value)
        resolved = self.runner.resolve()
        working_directory = Path(resolved.path).parent if resolved else None
        execution = self.runner.run(
            [f"--{payload['target_type']}", value, "--json"],
            timeout_seconds=_timeout(payload, 120),
            environment=context.environment,
            working_directory=working_directory,
        )
        return _execution_result("osint_spy", execution)


class PhoneInfogaPlugin(ExternalCommandPlugin):
    tool_spec = ToolSpec(
        tool_id="phoneinfoga",
        candidates=("phoneinfoga",),
        environment_variable="ORION_PHONEINFOGA_EXECUTABLE",
        homepage="https://github.com/sundowndev/phoneinfoga",
        license="GPL-3.0",
    )
    metadata = PluginMetadata(
        plugin_id="phoneinfoga",
        name="PhoneInfoga",
        version="1.0.0",
        category="osint-phone",
        description="Normalizes authorized PhoneInfoga scans of international telephone numbers.",
        risk_level="medium",
        capabilities=("phone-validation", "country-inference", "public-number-recon"),
        network_access=True,
        tags=("osint", "phone", "external-adapter"),
        homepage=tool_spec.homepage,
        license=tool_spec.license,
        integration="subprocess",
        default_timeout_seconds=120,
        max_timeout_seconds=600,
        input_schema={
            "type": "object",
            "required": ["number"],
            "additionalProperties": False,
            "properties": {
                "number": {"type": "string", "pattern": r"^\+?[0-9 ()-]{6,32}$"},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 600},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        number = _argument_value(payload["number"], "number")
        execution = self.runner.run(
            ["scan", "-n", number],
            timeout_seconds=_timeout(payload, 120),
            environment=context.environment,
        )
        return _execution_result("phoneinfoga", execution)


class PhotonPlugin(ExternalCommandPlugin):
    tool_spec = ToolSpec(
        tool_id="photon",
        candidates=("photon", "photon.py"),
        environment_variable="ORION_PHOTON_EXECUTABLE",
        homepage="https://github.com/s0md3v/Photon",
        license="GPL-3.0",
    )
    metadata = PluginMetadata(
        plugin_id="photon",
        name="Photon",
        version="1.0.0",
        category="osint-web",
        description="Crawls an authorized web target and normalizes public URLs, emails, files, and profiles.",
        risk_level="medium",
        capabilities=("web-crawling", "url-extraction", "email-extraction", "file-discovery"),
        network_access=True,
        tags=("osint", "crawler", "web", "external-adapter"),
        homepage=tool_spec.homepage,
        license=tool_spec.license,
        integration="subprocess",
        default_timeout_seconds=180,
        max_timeout_seconds=900,
        input_schema={
            "type": "object",
            "required": ["url"],
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "pattern": r"^https?://", "maxLength": 2048},
                "depth": {"type": "integer", "minimum": 1, "maximum": 5},
                "threads": {"type": "integer", "minimum": 1, "maximum": 20},
                "delay": {"type": "number", "minimum": 0, "maximum": 30},
                "request_timeout": {"type": "number", "minimum": 1, "maximum": 60},
                "only_urls": {"type": "boolean"},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 900},
            },
        },
        output_schema=_GENERIC_OUTPUT_SCHEMA,
    )

    def run(self, payload: JsonObject, context: PluginContext) -> JsonObject:
        payload = self.authorize(payload, context)
        url = _web_url(payload["url"])
        resolved = self.runner.resolve()
        working_directory = Path(resolved.path).parent if resolved else None
        with TemporaryToolDirectory("orion-photon-") as output:
            arguments = [
                "-u",
                url,
                "-l",
                str(payload.get("depth", 2)),
                "-t",
                str(payload.get("threads", 4)),
                "-d",
                str(payload.get("delay", 0)),
                "--timeout",
                str(payload.get("request_timeout", 6)),
                "-o",
                str(output),
                "-e",
                "json",
            ]
            if payload.get("only_urls"):
                arguments.append("--only-urls")
            execution = self.runner.run(
                arguments,
                timeout_seconds=_timeout(payload, 180),
                environment=context.environment,
                working_directory=working_directory,
            )
            return _execution_result("photon", execution, collect_artifacts(output))


OSINT_PLUGINS: tuple[type[BasePlugin], ...] = (
    SpiderFootPlugin,
    TheHarvesterPlugin,
    SherlockPlugin,
    OsintSpyPlugin,
    PhoneInfogaPlugin,
    PhotonPlugin,
)
