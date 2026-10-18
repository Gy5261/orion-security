"""Process and OSINT regressions using temporary fake tools and mock HTTP only."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator

import pytest

from orion.plugins import adapters
from orion.plugins.adapters import ToolRunner, ToolSpec, collect_artifacts, parse_json_output
from orion.plugins.core import AuthorizationError, PluginContext
from orion.plugins.execution import ExecutionCancellation, ExecutionCancelledError, execution_scope
from orion.plugins.osint import PhoneInfogaPlugin, PhotonPlugin, SherlockPlugin, SpiderFootPlugin, TheHarvesterPlugin


def fake_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str) -> ToolRunner:
    executable = tmp_path / "fake_tool.py"
    executable.write_text(source, encoding="utf-8")
    monkeypatch.setenv("ORION_TEST_TOOL", str(executable))
    return ToolRunner(ToolSpec("test-tool", ("missing-test-tool",), "ORION_TEST_TOOL",
                               "https://example.invalid", "MIT"))


def offline_fixture(plugin: Any) -> Any:
    """Only used when its network/process boundary has been replaced with a fake."""
    plugin.metadata = replace(plugin.metadata, network_access=False, side_effects=False)
    return plugin


def offline_context() -> PluginContext:
    return PluginContext(authorization="SYNTHETIC-OFFLINE-FIXTURE")


@pytest.mark.parametrize("key", [
    "NODE_OPTIONS", "BASH_ENV", "ENV", "RUBYOPT", "PERL5OPT", "JAVA_TOOL_OPTIONS",
    "GIT_CONFIG_COUNT", "SSH_ASKPASS", "SSLKEYLOGFILE", "HTTP_PROXY", "REQUESTS_CA_BUNDLE",
    "HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "TMPDIR", "ComSpec", "PATHEXT",
    "ORION_PHOTON_EXECUTABLE",
    "OPENSSL_CONF", "OPENSSL_MODULES", "NODE_EXTRA_CA_CERTS", "DOTNET_STARTUP_HOOKS", "LUA_CPATH",
])
def test_environment_rejects_execution_and_routing_hooks(key: str) -> None:
    with pytest.raises(ValueError, match="protected"):
        ToolRunner._environment({key: "injected"})


def test_environment_rejects_case_collisions() -> None:
    with pytest.raises(ValueError, match="case-insensitive"):
        ToolRunner._environment({"API_TOKEN": "one", "api_token": "two"})


def test_invalid_override_never_falls_back_to_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "print('safe')\n")
    monkeypatch.setenv("ORION_TEST_TOOL", str(tmp_path / "missing.py"))
    monkeypatch.setattr(adapters.shutil, "which", lambda _: str(tmp_path / "fake_tool.py"))
    assert runner.resolve() is None
    assert runner.health().available is False


def test_batch_wrappers_are_not_executable_adapters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "print('safe')\n")
    command = tmp_path / "unsafe.cmd"
    command.write_text("echo should-not-run", encoding="utf-8")
    command.chmod(0o700)
    monkeypatch.setenv("ORION_TEST_TOOL", str(command))
    assert runner.health().status == "invalid_configuration"
    with pytest.raises(ValueError, match="batch"):
        runner.run([], timeout_seconds=1)


@pytest.mark.parametrize("arguments", [["safe\x00unsafe"], ["a\nb"], [1], "--target example.org"])
def test_runner_rejects_malformed_argument_vectors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arguments: Any) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "raise AssertionError('must not execute')\n")
    with pytest.raises(ValueError, match="arguments"):
        runner.run(arguments, timeout_seconds=1)


def test_tool_has_private_home_and_does_not_inherit_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch,
                         "import json, os\nprint(json.dumps({'cwd': os.getcwd(), 'home': os.environ['HOME'], "
                         "'token': os.environ.get('GLOBAL_CLOUD_TOKEN'), 'tmp': os.environ['TMP']}))\n")
    monkeypatch.setenv("GLOBAL_CLOUD_TOKEN", "parent-secret")
    result = json.loads(runner.run([], timeout_seconds=5)["stdout"])
    assert result["token"] is None
    assert result["home"] == result["tmp"]
    assert Path(result["cwd"]).resolve() == Path(result["home"]).resolve()
    assert not Path(result["home"]).exists()


def test_stdout_and_stderr_redact_known_secret_encodings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch,
                         "import json, os, sys\nfrom urllib.parse import quote\n"
                         "value = os.environ['API_TOKEN']\nprint(json.dumps({'token': value}))\n"
                         "print(quote(value, safe=''), file=sys.stderr)\n")
    secret = 'synthetic-"quoted"-secret'
    result = runner.run([], timeout_seconds=5, environment={"API_TOKEN": secret})
    assert json.loads(result["stdout"])["token"] == "[REDACTED]"
    assert result["stderr"] == "[REDACTED]"
    assert secret not in str(result)


def test_failed_tool_does_not_leak_environment_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch,
                         "import os, sys\nprint(os.environ['API_TOKEN'], file=sys.stderr)\nsys.exit(3)\n")
    with pytest.raises(RuntimeError) as caught:
        runner.run([], timeout_seconds=5, environment={"API_TOKEN": "synthetic-failed-token"})
    assert "synthetic-failed-token" not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


def test_parent_deadline_limits_external_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "import time\ntime.sleep(30)\n")
    started = time.monotonic()
    with execution_scope(timeout_seconds=0.15), pytest.raises(TimeoutError, match="deadline"):
        runner.run([], timeout_seconds=10)
    assert time.monotonic() - started < 3


def test_cancellation_stops_running_external_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "started.txt"
    runner = fake_runner(tmp_path, monkeypatch,
                         "import os, pathlib, time\n"
                         "pathlib.Path(os.environ['ORION_TOOL_MARKER']).write_text(str(os.getpid()))\n"
                         "time.sleep(30)\n")
    cancellation = ExecutionCancellation()

    def execute() -> None:
        with execution_scope(cancellation=cancellation):
            runner.run([], timeout_seconds=10, environment={"ORION_TOOL_MARKER": str(marker)})

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(execute)
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "fake child did not start"
        started = time.monotonic()
        cancellation.cancel()
        with pytest.raises(ExecutionCancelledError):
            future.result(timeout=3)
        assert time.monotonic() - started < 3
    if os.name == "posix":
        with pytest.raises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)


def test_keyboard_interrupt_always_reaps_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "import time\ntime.sleep(30)\n")
    original_popen = subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def interrupted_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = original_popen(*args, **kwargs)
        original_wait = process.wait
        calls = 0

        def wait(*wait_args: Any, **wait_kwargs: Any) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt()
            return original_wait(*wait_args, **wait_kwargs)

        monkeypatch.setattr(process, "wait", wait)
        processes.append(process)
        return process

    monkeypatch.setattr(adapters.subprocess, "Popen", interrupted_popen)
    with pytest.raises(KeyboardInterrupt):
        runner.run([], timeout_seconds=5)
    assert len(processes) == 1 and processes[0].poll() is not None


def test_successful_parent_cannot_leave_descendant_output_handles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch,
                         "import subprocess, sys, time\n"
                         "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
                         "print(child.pid, flush=True)\ntime.sleep(0.2)\n")
    started = time.monotonic()
    result = runner.run([], timeout_seconds=5)
    assert result["return_code"] == 0
    assert time.monotonic() - started < 3
    if sys.platform == "linux":
        status = Path(f"/proc/{int(result['stdout'])}/stat")
        assert not status.exists() or status.read_text().split()[2] == "Z"


def test_artifacts_skip_links_and_special_files(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    private = tmp_path / "private.txt"
    private.write_text("unrelated-private-content", encoding="utf-8")
    (output / "safe.json").write_text('{"ok":true}', encoding="utf-8")
    if os.name == "posix":
        (output / "link.txt").symlink_to(private)
        (output / "directory").symlink_to(tmp_path, target_is_directory=True)
        os.link(private, output / "hardlink.txt")
        os.mkfifo(output / "named-pipe")
    assert collect_artifacts(output) == {"safe.json": {"ok": True}}


def test_artifact_path_walk_uses_full_windows_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows directory enumeration omits identity and hardlink metadata."""
    output = tmp_path / "output"
    output.mkdir()
    (output / "safe.json").write_text('{"ok":true}', encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("private-hardlinked-data", encoding="utf-8")
    os.link(outside, output / "linked.txt")
    original_scandir = os.scandir

    class IncompleteDirEntry:
        def __init__(self, entry: os.DirEntry[str]) -> None:
            self._entry = entry
            self.name = entry.name

        def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
            fields = list(self._entry.stat(follow_symlinks=follow_symlinks))
            fields[1] = fields[2] = fields[3] = 0  # st_ino, st_dev, st_nlink
            return os.stat_result(fields)

    @contextmanager
    def windows_scandir(path: Path) -> Iterator[Iterator[IncompleteDirEntry]]:
        with original_scandir(path) as entries:
            yield (IncompleteDirEntry(entry) for entry in entries)

    monkeypatch.setattr(adapters.os, "supports_fd", set())
    monkeypatch.setattr(adapters.os, "scandir", windows_scandir)
    assert collect_artifacts(output) == {"safe.json": {"ok": True}}


def test_artifact_reads_remain_bounded_after_stat_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "growing.txt").write_bytes(b"x" * 2048)
    monkeypatch.setattr(adapters, "_MAX_ARTIFACT_BYTES", 1024)
    original_fstat = os.fstat

    def stale_fstat(descriptor: int) -> os.stat_result:
        info = original_fstat(descriptor)
        fields = list(info)
        fields[6] = 1  # Pretend the regular file was smaller at preflight.
        return os.stat_result(fields)

    monkeypatch.setattr(adapters.os, "fstat", stale_fstat)
    assert collect_artifacts(tmp_path)["growing.txt"]["truncated"] is True


def test_growing_artifacts_share_one_actual_read_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for index in range(3):
        (tmp_path / f"growing-{index}.txt").write_bytes(b"x" * 2048)
    monkeypatch.setattr(adapters, "_MAX_ARTIFACT_BYTES", 1024)
    original_fstat = os.fstat
    original_fdopen = os.fdopen
    actual_reads: list[int] = []

    def stale_fstat(descriptor: int) -> os.stat_result:
        fields = list(original_fstat(descriptor))
        fields[6] = 0  # Every file claims to fit, including after exhaustion.
        return os.stat_result(fields)

    class CountingReader:
        def __init__(self, descriptor: int, mode: str) -> None:
            self._handle = original_fdopen(descriptor, mode)

        def __enter__(self) -> CountingReader:
            return self

        def __exit__(self, *args: Any) -> None:
            self._handle.close()

        def fileno(self) -> int:
            return self._handle.fileno()

        def read(self, size: int) -> bytes:
            data = self._handle.read(size)
            actual_reads.append(len(data))
            return data

    monkeypatch.setattr(adapters.os, "fstat", stale_fstat)
    monkeypatch.setattr(adapters.os, "fdopen", CountingReader)
    result = collect_artifacts(tmp_path)
    assert len(result) == 3
    assert all(item["truncated"] for item in result.values())
    assert sum(actual_reads) == 1024 + 1
    assert len(actual_reads) == 1


@pytest.mark.parametrize("budget, value", [("_MAX_ARTIFACT_ENTRIES", 2), ("_MAX_ARTIFACT_FILES", 2)])
def test_artifact_collection_has_entry_and_file_budgets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                      budget: str, value: int) -> None:
    for index in range(3):
        (tmp_path / f"{index}.txt").write_text("data", encoding="utf-8")
    monkeypatch.setattr(adapters, budget, value)
    with pytest.raises(ValueError, match="(budget|file count)"):
        collect_artifacts(tmp_path)


def test_artifact_collection_rejects_excessive_nesting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "one" / "two").mkdir(parents=True)
    monkeypatch.setattr(adapters, "_MAX_ARTIFACT_DEPTH", 1)
    with pytest.raises(ValueError, match="nesting"):
        collect_artifacts(tmp_path)


@pytest.mark.parametrize("text", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'])
def test_tool_json_is_strict(text: str) -> None:
    assert parse_json_output(text) is None


def test_json_parser_accepts_last_structured_line_after_progress() -> None:
    assert parse_json_output("starting\nprogress\n{\"ok\":true}\n") == {"ok": True}


@pytest.mark.parametrize("plugin_type,payload", [
    (SherlockPlugin, {"usernames": ["--help"]}),
    (SherlockPlugin, {"usernames": ["valid"], "sites": ["--json"]}),
    (SherlockPlugin, {"usernames": ["user\n--help"]}),
    (TheHarvesterPlugin, {"domain": "--help"}),
    (TheHarvesterPlugin, {"domain": "example.org", "sources": ["--help"]}),
    (PhoneInfogaPlugin, {"number": "-1234567"}),
    (PhotonPlugin, {"url": "https://user:secret@example.org"}),
    (PhotonPlugin, {"url": "https://example.org\n"}),
])
def test_adapters_reject_option_or_credential_injection(plugin_type: Any, payload: dict[str, Any],
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = offline_fixture(plugin_type())

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("unsafe input reached an external command")

    monkeypatch.setattr(plugin.runner, "run", forbidden)
    with pytest.raises(ValueError):
        plugin.run(payload, offline_context())


def test_sherlock_builds_only_declared_arguments_for_fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = fake_runner(tmp_path, monkeypatch, "import json, sys\nprint(json.dumps({'args':sys.argv[1:]}))\n")
    plugin = offline_fixture(SherlockPlugin())
    plugin.runner = runner
    result = plugin.run({"usernames": ["ordinary_user"], "sites": ["Example"]}, offline_context())
    arguments = result["result"]["args"]
    assert arguments[0] == "ordinary_user"
    assert arguments[-2:] == ["--site", "Example"]
    assert "--no-color" in arguments


@pytest.mark.parametrize("origin", [
    "http://localhost:0", "http://127.0.0.1\n", "http://[::1%lo]:5001", "\thttp://127.0.0.1",
])
def test_spiderfoot_rejects_ambiguous_local_origins(origin: str) -> None:
    with pytest.raises(ValueError):
        SpiderFootPlugin._validate_local_service(origin)


def test_spiderfoot_pins_localhost_to_literal_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = offline_fixture(SpiderFootPlugin())
    urls: list[str] = []

    def request(url: str, timeout: float) -> dict[str, bool]:
        urls.append(url)
        return {"ok": True}

    monkeypatch.setattr(plugin, "_request", request)
    plugin.run({"operation": "list", "server_url": "http://localhost:5001"}, offline_context())
    assert urls == ["http://127.0.0.1:5001/scanlist"]


def test_spiderfoot_http_error_never_echoes_service_body(monkeypatch: pytest.MonkeyPatch) -> None:
    body = io.BytesIO(b"database_password=synthetic-secret")

    class FailingOpener:
        def open(self, request: Any, timeout: float) -> Any:
            raise urllib.error.HTTPError(request.full_url, 500, "error", {}, body)  # type: ignore[arg-type]

    monkeypatch.setattr("orion.plugins.osint.urllib.request.build_opener", lambda *args: FailingOpener())
    with pytest.raises(RuntimeError) as caught:
        SpiderFootPlugin._request("http://127.0.0.1:5001/scanlist", 1)
    assert "synthetic-secret" not in str(caught.value)
    assert body.closed


def test_spiderfoot_response_read_checks_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    cancellation = ExecutionCancellation()

    class Response(io.BytesIO):
        def read1(self, size: int = -1) -> bytes:
            cancellation.cancel()
            return super().read1(size)

    response = Response(b'{"ok":true}')

    class Opener:
        def open(self, request: Any, timeout: float) -> Response:
            return response

    monkeypatch.setattr("orion.plugins.osint.urllib.request.build_opener", lambda *args: Opener())
    with execution_scope(cancellation=cancellation), pytest.raises(ExecutionCancelledError):
        SpiderFootPlugin._request("http://127.0.0.1:5001/scanlist", 1)
    assert response.closed


@pytest.mark.parametrize("plugin_type,payload", [
    (SherlockPlugin, {"usernames": ["synthetic_user"]}),
    (TheHarvesterPlugin, {"domain": "example.invalid"}),
    (PhoneInfogaPlugin, {"number": "+123456789"}),
    (PhotonPlugin, {"url": "https://example.invalid"}),
    (SpiderFootPlugin, {"operation": "list"}),
])
def test_direct_plugin_run_cannot_bypass_controlled_policy(plugin_type: Any, payload: dict[str, Any]) -> None:
    plugin = plugin_type()
    context = PluginContext(authorization="EXPLICIT-TEST-REFERENCE", allow_network=True, allow_side_effects=True)
    with pytest.raises(AuthorizationError, match="not admitted"):
        plugin.run(payload, context)
