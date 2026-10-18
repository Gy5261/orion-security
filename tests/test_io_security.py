"""Adversarial JSON, filesystem and offline input regressions. No network."""
from __future__ import annotations

import io
import json
import os
import tracemalloc
from pathlib import Path
from typing import Any

import pytest

from orion.cli import main
from orion.controls import ControlDenied, load_private_json
from orion.jsonio import canonical_json, loads_json, read_json, read_json_file
from orion.resources import ResourceCatalog
from orion.scripts import http_surface_audit, ioc_enricher, log_triage


@pytest.mark.parametrize("raw", [
    '{"a":1,"a":2}', '{"a":{"secret":1,"secret":2}}',
    '{"value":NaN}', '{"value":1e999}',
    '{"value":"\\ud800"}', '{"\\udfff":1}',
    '[' * 1200 + '0' + ']' * 1200, '1' * 1025,
])
def test_every_json_boundary_rejects_ambiguous_or_unbounded_data(raw: str, tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text(raw, encoding="utf-8")
    for read in (lambda: loads_json(raw), lambda: read_json(io.BytesIO(raw.encode())),
                 lambda: read_json_file(path)):
        with pytest.raises(ValueError):
            read()


def test_repeated_strings_are_rejected_before_large_serialization() -> None:
    value = ["x" * 8192] * 2000
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="byte limit"):
            canonical_json(value)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024  # The encoded attack would exceed 15 MiB.


def test_cyclic_python_values_are_rejected_without_recursion_error() -> None:
    value: list[Any] = []
    value.append(value)
    with pytest.raises(ValueError, match="nesting"):
        canonical_json(value)


def test_json_keys_share_the_document_budget() -> None:
    with pytest.raises(ValueError):
        canonical_json({"a" * 600_000: 1, "b" * 600_000: 2})


def test_json_reader_never_requests_unbounded_read() -> None:
    class GuardedStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 17
            return super().read(size)
    with pytest.raises(ValueError, match="exceeds"):
        read_json(GuardedStream(b" " * 20), max_bytes=16)


def test_deep_cli_json_returns_error_instead_of_traceback(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "deep.json"
    path.write_text('{"iocs":' + '[' * 1200 + '0' + ']' * 1200 + '}', encoding="utf-8")
    assert main(["plugins", "run", "ioc_enricher", "--input", str(path),
                 "--authorization", "OFFLINE-JSON-TEST"]) == 2
    assert json.loads(capsys.readouterr().out)["ok"] is False


@pytest.mark.parametrize("path", ["./data.md", "a//data.md", "a/../data.md", "data.md/",
                                  "C:secret.md", "data.md\x7f", "a\\data.md"])
def test_resource_paths_have_one_canonical_meaning(tmp_path: Path, path: str) -> None:
    with pytest.raises(ValueError):
        ResourceCatalog(tmp_path).read(path)


def test_resource_links_encode_reserved_uri_characters(tmp_path: Path) -> None:
    name = "how to #1%?.md"
    if os.name == "nt":
        name = "how to #1%.md"
    (tmp_path / name).write_text("public", encoding="utf-8")
    descriptor = ResourceCatalog(tmp_path).descriptor(name)
    assert " " not in descriptor.uri and "#" not in descriptor.uri
    assert "%25" in descriptor.uri
    assert ResourceCatalog(tmp_path).read(descriptor.path) == "public"


def test_resource_hardlink_cannot_publish_private_control_file(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir()
    secret = private / "approval.json"
    secret.write_text('{"secret":"do not publish"}', encoding="utf-8")
    alias = tmp_path / "readme.json"
    try:
        os.link(secret, alias)
    except OSError:
        pytest.skip("hard links are unavailable")
    assert ResourceCatalog(tmp_path).list() == ()
    with pytest.raises(ValueError, match="hard-link"):
        ResourceCatalog(tmp_path).read(alias.name)


def test_private_control_hardlink_is_refused(tmp_path: Path) -> None:
    secret = tmp_path / "permit.json"
    secret.write_text("{}", encoding="utf-8")
    secret.chmod(0o600)
    try:
        os.link(secret, tmp_path / "alias.json")
    except OSError:
        pytest.skip("hard links are unavailable")
    with pytest.raises(ControlDenied, match="hard-link"):
        load_private_json(str(secret))


def test_resource_traversal_counts_excluded_entries(tmp_path: Path, monkeypatch: Any) -> None:
    for number in range(8):
        (tmp_path / f"ignored{number}.unknown").touch()
    monkeypatch.setattr("orion.resources._MAX_TRAVERSAL_ENTRIES", 4)
    with pytest.raises(ValueError, match="traversal"):
        ResourceCatalog(tmp_path).list()


def test_resource_search_budgets_actual_bytes_after_files_grow(tmp_path: Path, monkeypatch: Any) -> None:
    from contextlib import contextmanager
    from orion import resources
    names = [f"file-{number}.md" for number in range(10)]
    for name in names:
        (tmp_path / name).write_text("x", encoding="utf-8")
    catalog = ResourceCatalog(tmp_path)
    descriptors = catalog.list()
    monkeypatch.setattr(catalog, "list", lambda: descriptors)
    monkeypatch.setattr("orion.resources._MAX_SEARCH_BYTES", 16)
    for name in names:
        (tmp_path / name).write_text("keyword 1234", encoding="utf-8")
    actual_bytes = 0
    original_open = resources.open_regular

    @contextmanager
    def counted_open(*args: Any, **kwargs: Any) -> Any:
        with original_open(*args, **kwargs) as original:
            class CountedReader:
                def read(self, size: int) -> bytes:
                    nonlocal actual_bytes
                    data = original.read(size)
                    actual_bytes += len(data)
                    return data
            yield CountedReader()

    monkeypatch.setattr(resources, "open_regular", counted_open)
    # Ten stale bytes grow to 120. Failed reads must also consume the budget.
    found = catalog.search("keyword")
    assert [item["path"] for item in found] == ["file-0.md"]
    assert actual_bytes == 16


def test_resource_parent_swap_to_symlink_fails_closed(tmp_path: Path, monkeypatch: Any) -> None:
    root = tmp_path / "public"
    root.mkdir()
    folder = root / "docs"
    folder.mkdir()
    (folder / "readme.md").write_text("public", encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir()
    (private / "readme.md").write_text("private secret", encoding="utf-8")
    catalog = ResourceCatalog(root)
    descriptor = catalog.descriptor("docs/readme.md")
    original_resolve = catalog._resolve
    def resolve_then_swap(path: str) -> Path:
        resolved = original_resolve(path)
        folder.rename(root / "old-docs")
        try:
            folder.symlink_to(private, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are unavailable")
        return resolved
    monkeypatch.setattr(catalog, "descriptor", lambda _: descriptor)
    monkeypatch.setattr(catalog, "_resolve", resolve_then_swap)
    with pytest.raises((OSError, ValueError)):
        catalog.read_bytes(descriptor.path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_json_fifo_is_rejected_without_waiting_for_a_writer(tmp_path: Path) -> None:
    path = tmp_path / "fifo.json"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular"):
        read_json_file(path)


@pytest.mark.parametrize("headers", [{"X-Test": "ok\r\nInjected: yes"}, {"bad name": "value"},
                                    {"X-Test": "one", "x-test": "two"}])
def test_offline_http_headers_reject_injection_and_duplicates(headers: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        http_surface_audit.analyze_headers(headers)


def test_ioc_file_does_not_coerce_objects_into_indicators(tmp_path: Path) -> None:
    import argparse
    path = tmp_path / "indicators.json"
    path.write_text('[{"not":"an indicator"}]', encoding="utf-8")
    with pytest.raises(ValueError):
        ioc_enricher.load_iocs(argparse.Namespace(ioc=[], input=str(path)))


def test_log_triage_handles_null_type(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    path = tmp_path / "events.json"
    path.write_text('[{"type":null}]', encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["log_triage.py", str(path)])
    assert log_triage.main() == 0
    assert json.loads(capsys.readouterr().out)["total_events"] == 1


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://www.virustotal.com/api/v3/search",
                                 "https://127.0.0.1/secrets", "https://www.virustotal.com@attacker.invalid/",
                                 "https://api.shodan.io:444/", "https://api.shodan.io/#fragment"])
def test_external_json_helper_cannot_fetch_arbitrary_destinations(url: str, monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("rejected service URL contacted the network")
    monkeypatch.setattr(ioc_enricher.urllib.request, "build_opener", forbidden)
    with pytest.raises(ValueError):
        ioc_enricher.fetch_json(url, {}, 1.0)


def test_external_errors_do_not_disclose_api_key_urls() -> None:
    def failed() -> Any:
        raise OSError("https://api.shodan.io/?key=private-test-token")
    result = ioc_enricher.safe_fetch("shodan", failed)
    assert result["ok"] is False
    assert "private-test-token" not in json.dumps(result)


def test_evidence_growth_never_causes_an_unbounded_read(tmp_path: Path, monkeypatch: Any) -> None:
    from contextlib import contextmanager
    from orion.scripts import evidence_manifest
    path = tmp_path / "growing.bin"
    path.write_bytes(b"initial")

    @contextmanager
    def growing_file(*args: Any, **kwargs: Any) -> Any:
        with path.open("rb") as original:
            class GrowingReader:
                def fileno(self) -> int:
                    return original.fileno()
                def read(self, size: int) -> bytes:
                    # A malicious writer grows on every read, including EOF.
                    with path.open("ab") as writer:
                        writer.write(b"another block")
                    assert size <= len(b"initial")
                    return original.read(size)
            yield GrowingReader()

    monkeypatch.setattr(evidence_manifest, "open_regular", growing_file)
    with pytest.raises(ValueError, match="changed"):
        evidence_manifest.sha256_file(path)
