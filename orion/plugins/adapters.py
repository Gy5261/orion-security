"""Hardened adapters for optional third-party command-line tools."""

from __future__ import annotations

import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

from orion.jsonio import loads_json

from .core import JsonObject, PluginHealth, ToolUnavailableError
from .execution import check_execution, execution_scope, remaining_timeout
from .processes import ProcessGroup, stop_process
from .redaction import redact_text

_MAX_STREAM_BYTES = 2 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_ARTIFACT_FILES = 256
_MAX_ARTIFACT_ENTRIES = 4096
_MAX_ARTIFACT_DEPTH = 16
_MAX_ARGUMENT_BYTES = 128 * 1024
_CLEANUP_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Resolution contract for an optional executable."""

    tool_id: str
    candidates: tuple[str, ...]
    environment_variable: str
    homepage: str
    license: str
    version_arguments: tuple[str, ...] = ("--version",)


@dataclass(frozen=True, slots=True)
class ResolvedTool:
    """Resolved executable prefix."""

    path: str
    command_prefix: tuple[str, ...]
    source: str


class ToolRunner:
    """Resolve and execute allow-listed tools without invoking a shell."""

    def __init__(self, spec: ToolSpec) -> None:
        self.spec = spec

    def resolve(self) -> ResolvedTool | None:
        override = os.getenv(self.spec.environment_variable)
        if override:
            path = Path(override).expanduser()
            if path.is_file() and (path.suffix.lower() == ".py" or os.access(path, os.X_OK)):
                return self._resolved(str(path.resolve()), "environment")
            # An explicitly configured but invalid path must not select an
            # unrelated executable from PATH instead.
            return None

        for candidate in self.spec.candidates:
            discovered = shutil.which(candidate)
            if discovered:
                return self._resolved(str(Path(discovered).resolve()), "path")
        return None

    @staticmethod
    def _resolved(path: str, source: str) -> ResolvedTool:
        if Path(path).suffix.lower() in {".bat", ".cmd"}:
            raise ValueError("batch command wrappers are not supported; configure a native executable or .py file")
        prefix = (sys.executable, path) if path.lower().endswith(".py") else (path,)
        return ResolvedTool(path=path, command_prefix=prefix, source=source)

    def health(self) -> PluginHealth:
        try:
            resolved = self.resolve()
        except (OSError, ValueError):
            return PluginHealth(available=False, status="invalid_configuration",
                                message=f"{self.spec.environment_variable} must select a usable native executable or .py file")
        if resolved is None:
            candidates = ", ".join(self.spec.candidates)
            return PluginHealth(
                available=False,
                status="optional_dependency_missing",
                message=(
                    f"{self.spec.tool_id} is not installed; set {self.spec.environment_variable} "
                    f"or install one of: {candidates}"
                ),
                details={
                    "tool": self.spec.tool_id,
                    "homepage": self.spec.homepage,
                    "license": self.spec.license,
                    "environment_variable": self.spec.environment_variable,
                },
            )
        return PluginHealth(
            available=True,
            details={
                "tool": self.spec.tool_id,
                "path": resolved.path,
                "source": resolved.source,
                "homepage": self.spec.homepage,
                "license": self.spec.license,
            },
        )

    @staticmethod
    def _drain(pipe: BinaryIO, buffer: bytearray, overflow: list[bool]) -> None:
        """Always drain pipes; retain only bounded output in memory."""
        try:
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                available = max(0, _MAX_STREAM_BYTES - len(buffer))
                buffer.extend(chunk[:available])
                if len(chunk) > available:
                    overflow[0] = True
        finally:
            pipe.close()

    @staticmethod
    def _stop_process(process: subprocess.Popen[bytes]) -> None:
        """Compatibility helper for a dedicated POSIX group or one child."""
        stop_process(process)

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float,
        environment: Mapping[str, str] | None = None,
        working_directory: str | Path | None = None,
    ) -> JsonObject:
        if type(timeout_seconds) not in {int, float} or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        if isinstance(arguments, (str, bytes)) or len(arguments) > 1024:
            raise ValueError("tool arguments must be a bounded sequence of strings")
        if any(not isinstance(argument, str) or any(ord(char) < 32 for char in argument) for argument in arguments):
            raise ValueError("tool arguments must be strings without control characters or NUL bytes")
        if sum(len(argument.encode("utf-8")) + 1 for argument in arguments) > _MAX_ARGUMENT_BYTES:
            raise ValueError("tool arguments exceed the 128 KiB limit")
        env = self._environment(environment)
        resolved = self.resolve()
        if resolved is None:
            raise ToolUnavailableError(self.health().message)
        command = [*resolved.command_prefix, *arguments]
        started = time.perf_counter_ns()
        stdout_bytes, stderr_bytes = bytearray(), bytearray()
        stdout_overflow, stderr_overflow = [False], [False]
        # HOME and temporary paths are private to this invocation. A trusted
        # adapter may select its installed resources as cwd, but no caller may
        # inject another home/config directory through environment overrides.
        with tempfile.TemporaryDirectory(prefix="orion-exec-") as private_home, execution_scope(timeout_seconds=timeout_seconds):
            for key in ("HOME", "USERPROFILE", "TMP", "TEMP", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
                env[key] = private_home
            process = subprocess.Popen(
                command,
                cwd=str(working_directory) if working_directory is not None else private_home,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=os.name == "posix",
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
            )
            group: ProcessGroup | None = None
            readers: list[threading.Thread] = []
            try:
                group = ProcessGroup(process)
                if process.stdout is None or process.stderr is None:
                    raise RuntimeError("tool output pipes could not be initialized")
                for label, pipe, buffer, overflow in (
                    ("stdout", process.stdout, stdout_bytes, stdout_overflow),
                    ("stderr", process.stderr, stderr_bytes, stderr_overflow),
                ):
                    reader = threading.Thread(target=self._drain, args=(pipe, buffer, overflow),
                                              name=f"orion-tool-{label}", daemon=True)
                    reader.start()
                    readers.append(reader)
                while True:
                    check_execution()
                    try:
                        return_code = process.wait(timeout=remaining_timeout(0.05))
                        break
                    except subprocess.TimeoutExpired:
                        continue
            finally:
                # Also runs for cancellation, KeyboardInterrupt, reader setup
                # errors, and successful parents that left children behind.
                if group is not None:
                    group.stop()
                else:
                    self._stop_process(process)
                cleanup_deadline = time.monotonic() + _CLEANUP_SECONDS
                try:
                    process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    self._stop_process(process)
                for reader in readers:
                    reader.join(timeout=max(0, cleanup_deadline - time.monotonic()))
                if not readers:
                    for stream in (process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
            if any(reader.is_alive() for reader in readers):
                raise RuntimeError(f"{self.spec.tool_id} retained open subprocess output handles after cleanup")
            check_execution()
        duration_ms = round((time.perf_counter_ns() - started) / 1_000_000)

        stdout = redact_text(self._decode(bytes(stdout_bytes)), environment)
        stderr = redact_text(self._decode(bytes(stderr_bytes)), environment)
        if stdout_overflow[0]:
            stdout += "\n[ORION STDOUT TRUNCATED AT 2 MiB]"
        if stderr_overflow[0]:
            stderr += "\n[ORION STDERR TRUNCATED AT 2 MiB]"
        result: JsonObject = {
            "tool": self.spec.tool_id,
            "return_code": return_code,
            "duration_ms": duration_ms,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_overflow[0],
            "stderr_truncated": stderr_overflow[0],
        }
        if return_code != 0:
            raise RuntimeError(
                f"{self.spec.tool_id} exited with code {return_code}: {(stderr or stdout)[:2048]}"
            )
        return result

    @staticmethod
    def _environment(extra: Mapping[str, str] | None) -> dict[str, str]:
        allowed = {
            "PATH",
            "LANG",
            "LC_ALL",
            "SYSTEMROOT",
            "WINDIR",
        }
        env = {key.upper(): value for key, value in os.environ.items() if key.upper() in allowed}
        env.setdefault("PYTHONUNBUFFERED", "1")
        if extra:
            if len(extra) > 32:
                raise ValueError("too many tool environment overrides")
            blocked = allowed | {
                "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TMP", "TEMP", "TMPDIR",
                "COMSPEC", "PATHEXT", "BASH_ENV", "BASHOPTS", "ENV", "IFS", "SHELLOPTS", "CDPATH",
                "NODE_OPTIONS", "NODE_PATH", "RUBYOPT", "RUBYLIB", "PERL5OPT", "PERL5LIB", "PERLLIB",
                "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
                "GCONV_PATH", "LOCPATH", "SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR",
                "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "GODEBUG", "R_PROFILE", "R_PROFILE_USER", "R_ENVIRON", "R_ENVIRON_USER",
            }
            names: set[str] = set()
            for key, value in extra.items():
                if not isinstance(key, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key) is None:
                    raise ValueError(f"invalid environment variable name: {key!r}")
                normalized = key.upper()
                protected_prefixes = (
                    "DYLD_", "LD_", "PYTHON", "XDG_", "GIT_", "SSH_", "ORION_", "OPENSSL_", "NODE_",
                    "DOTNET_", "CORECLR_", "COR_", "LUA_", "TCL_", "TK_", "QT_", "GTK_", "GIO_", "GI_",
                )
                if normalized in blocked or (normalized.startswith(protected_prefixes) and not normalized.startswith("ORION_TOOL_")):
                    raise ValueError(f"protected environment variable cannot be overridden: {key!r}")
                if normalized in names:
                    raise ValueError("duplicate case-insensitive environment variable name")
                if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                    raise ValueError(f"invalid environment variable value for {key!r}")
                names.add(normalized)
                env[key] = value
        return env

    @staticmethod
    def _decode(value: bytes | str | None) -> str:
        if value is None:
            return ""
        raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
        if len(raw) > _MAX_STREAM_BYTES:
            raw = raw[:_MAX_STREAM_BYTES] + b"\n[ORION OUTPUT TRUNCATED]"
        return raw.decode("utf-8", errors="replace").strip()


def parse_json_output(text: str) -> Any | None:
    """Parse bounded strict JSON, or one of the last 256 tool output lines."""

    if len(text) > _MAX_STREAM_BYTES or len(text.encode("utf-8")) > _MAX_STREAM_BYTES:
        # A truncated byte stream is evidence, not a complete JSON document.
        return None
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return loads_json(stripped, max_bytes=_MAX_STREAM_BYTES)
    except ValueError:
        pass
    for line in reversed(stripped.rsplit("\n", 256)[-256:]):
        candidate = line.strip()
        if candidate.startswith(("{", "[")):
            try:
                return loads_json(candidate, max_bytes=_MAX_STREAM_BYTES)
            except ValueError:
                continue
    return None


def collect_artifacts(root: str | Path) -> JsonObject:
    """Read bounded regular artifacts without traversing links or special files.

    POSIX traversal opens each directory relative to its parent descriptor with
    O_NOFOLLOW. Windows rejects reparse points and checks the opened file identity.
    This bounds collection, not disk consumption by the external executable.
    """
    supplied = Path(root)
    if supplied.is_symlink() or getattr(supplied.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("artifact root must not be a symbolic link or reparse point")
    base = supplied.resolve(strict=True)
    if not base.is_dir():
        raise ValueError("artifact root must be a directory")
    files: JsonObject = {}
    consumed = 0
    visited = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor_walk = os.open in os.supports_dir_fd and os.scandir in os.supports_fd

    def regular_artifact(descriptor: int, relative: Path, expected: os.stat_result) -> None:
        nonlocal consumed
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino)):
                return
            if len(files) >= _MAX_ARTIFACT_FILES:
                raise ValueError("artifact file count exceeds the 256-file limit")
            remaining = _MAX_ARTIFACT_BYTES - consumed
            name = str(relative)
            if info.st_size > remaining:
                files[name] = {"truncated": True, "size_bytes": info.st_size}
                return
            raw = handle.read(remaining + 1)
            if len(raw) > remaining:
                files[name] = {"truncated": True, "size_bytes": max(info.st_size, len(raw))}
                return
            consumed += len(raw)
        if relative.suffix.lower() == ".json":
            try:
                files[name] = loads_json(raw, max_bytes=_MAX_ARTIFACT_BYTES)
                return
            except ValueError:
                pass
        files[name] = raw.decode("utf-8", errors="replace")

    def walk(directory: int | Path, relative: Path, depth: int) -> None:
        nonlocal visited
        entries: list[os.DirEntry[str]] = []
        with os.scandir(directory) as scan:
            for entry in scan:
                visited += 1
                if visited > _MAX_ARTIFACT_ENTRIES:
                    raise ValueError("artifact directory entry budget exceeded")
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            check_execution()
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                continue  # Includes Windows junctions and other reparse points.
            child = relative / entry.name
            if stat.S_ISDIR(info.st_mode):
                if depth >= _MAX_ARTIFACT_DEPTH:
                    raise ValueError("artifact directory nesting exceeds 16 levels")
                if isinstance(directory, int):
                    try:
                        child_fd = os.open(entry.name, flags | os.O_DIRECTORY, dir_fd=directory)
                    except FileNotFoundError:
                        continue
                    try:
                        walk(child_fd, child, depth + 1)
                    finally:
                        os.close(child_fd)
                else:
                    walk(directory / entry.name, child, depth + 1)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                try:
                    descriptor = (os.open(entry.name, flags, dir_fd=directory) if isinstance(directory, int)
                                  else os.open(directory / entry.name, flags))
                except FileNotFoundError:
                    continue
                regular_artifact(descriptor, child, info)

    if descriptor_walk:
        root_fd = os.open(base, flags | os.O_DIRECTORY)
        try:
            walk(root_fd, Path(), 0)
        finally:
            os.close(root_fd)
    else:
        walk(base, Path(), 0)
    return {name: files[name] for name in sorted(files)}


class TemporaryToolDirectory:
    """Context manager exposing a private temporary directory to adapters."""

    def __init__(self, prefix: str) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix=prefix)
        self.path = Path(self._temporary.name)

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._temporary.cleanup()
