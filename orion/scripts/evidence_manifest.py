"""Generate a bounded, read-only SHA-256 file inventory.

A manifest documents bytes observed at a point in time. It is NOT a legally
certified chain of custody, signature, timestamp authority or tamper-proof log.
Symlinks, unusual file types and files changing during hashing are refused.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from orion.fileio import is_link, open_regular

_CHUNK_SIZE = 1024 * 1024
_MAX_FILES = 10_000
_MAX_TAG_LENGTH = 128
_IGNORED_DIRS = {".git", ".venv", "__pycache__", "node_modules"}
_MAX_TRAVERSAL_ENTRIES = 100_000
_MAX_TRAVERSAL_DEPTH = 64


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Produce a verified SHA-256 file manifest; no network access.")
    parser.add_argument("paths", nargs="+", help="Files or directories to inventory.")
    parser.add_argument("--output", help="Optional JSON output; must not already exist.")
    parser.add_argument("--tag", action="append", default=[], help="Non-sensitive operator label, max 128 chars.")
    parser.add_argument("--max-files", type=int, default=_MAX_FILES)
    return parser.parse_args()


def iter_files(paths: Iterable[str], *, max_files: int = _MAX_FILES) -> list[Path]:
    """Collect stable, explicit paths without following symbolic links."""
    if type(max_files) is not int or not 1 <= max_files <= _MAX_FILES:
        raise ValueError("max_files must be between 1 and 10000")
    discovered: dict[str, Path] = {}
    visited = 0
    for item in paths:
        root = Path(item).expanduser()
        if any(is_link(part) for part in (root, *root.parents)):
            raise ValueError("symbolic links are not valid manifest inputs")
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = []
            pending = [(root, 0)]
            while pending:
                current, depth = pending.pop()
                with os.scandir(current) as scan:
                    for entry in scan:
                        visited += 1
                        if visited > _MAX_TRAVERSAL_ENTRIES:
                            raise ValueError("manifest traversal entry budget exceeded")
                        path = Path(entry.path)
                        if is_link(path):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in _IGNORED_DIRS:
                                if depth >= _MAX_TRAVERSAL_DEPTH:
                                    raise ValueError("manifest traversal depth budget exceeded")
                                pending.append((path, depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            candidates.append(path)
                            if len(candidates) + len(discovered) > max_files:
                                raise ValueError(f"manifest limit exceeded: {max_files} files")
        else:
            raise FileNotFoundError(f"not a regular file or directory: {root}")
        for path in candidates:
            if is_link(path):
                continue
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                continue
            discovered[str(path.absolute())] = path
            if len(discovered) > max_files:
                raise ValueError(f"manifest limit exceeded: {max_files} files")
    if not discovered:
        raise ValueError("No regular files were provided.")
    return [discovered[name] for name in sorted(discovered)]


def _snapshot(path: Path) -> tuple[str, os.stat_result, int]:
    """Hash one regular file using a descriptor; fail if it changes during reading."""
    with open_regular(path) as handle:
        initial = os.fstat(handle.fileno())
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError(f"not a regular file: {path.name}")
        digest = hashlib.sha256()
        actual = 0
        remaining = initial.st_size
        while remaining:
            block = handle.read(min(_CHUNK_SIZE, remaining))
            if not block:
                break
            digest.update(block)
            actual += len(block)
            remaining -= len(block)
        # A continuously growing file must not keep this read running forever.
        if handle.read(1):
            raise ValueError(f"file changed during hashing: {path.name}")
        final = os.fstat(handle.fileno())
        if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns, initial.st_ino) != (
                final.st_size, final.st_mtime_ns, final.st_ctime_ns, final.st_ino
        ) or actual != final.st_size:
            raise ValueError(f"file changed during hashing: {path.name}")
    return digest.hexdigest(), final, actual


def sha256_file(path: Path) -> str:
    """Return SHA-256 of unchanged file contents."""
    return _snapshot(Path(path))[0]


def file_record(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    digest, info, size = _snapshot(path)
    base = root or Path.cwd()
    try:
        relative = path.absolute().relative_to(base.absolute()).as_posix()
    except ValueError:
        relative = path.name
    return {
        "path": relative,
        "size_bytes": size,
        "sha256": digest,
        "modified_at_utc": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
        "content_stable_while_read": True,
    }


def write_output(payload: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if output:
        path = Path(output)
        with path.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)


def main() -> int:
    try:
        args = parse_args()
        if any(not isinstance(tag, str) or not tag.strip() or len(tag) > _MAX_TAG_LENGTH for tag in args.tag):
            raise ValueError("tags must be non-empty strings of at most 128 characters")
        paths = iter_files(args.paths, max_files=args.max_files)
        if args.output is not None:
            output_path = Path(args.output).absolute()
            if any(path.absolute() == output_path for path in paths):
                raise ValueError("output must not overwrite an inventoried file")
        common = Path(os.path.commonpath([str(path.absolute()) for path in paths]))
        if len(paths) == 1:
            common = paths[0].absolute().parent
        payload = {
            "tool": "evidence_manifest", "schema_version": 2,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "hash_algorithm": "sha256", "legal_chain_of_custody_verified": False,
            "network_contacted": False, "tags": args.tag, "count": len(paths),
            "items": [file_record(path, root=common) for path in paths],
        }
        write_output(payload, args.output)
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
