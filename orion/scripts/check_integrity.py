"""Validate explicit local Markdown links with deterministic, offline checks.

Inline-code snippets may be examples, not links; only Markdown link syntax is
verified. External URLs are never fetched.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
SKIP_DIRS = {".git", ".github", ".venv", "node_modules", "__pycache__", "dist", "build"}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\((?P<dest><[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")
SCHEMES = {"http", "https", "mailto", "tel", "data", "ftp", "file", "orion"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def categorize_file(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel.startswith("orion/references/"):
        return "reference"
    if rel.startswith("orion/playbooks/"):
        return "playbook"
    if rel.startswith("orion/scripts/"):
        return "script"
    return "core" if rel.startswith("orion/") else rel.split("/", 1)[0]


def _markdown_files() -> list[Path]:
    return sorted(path for path in REPO_ROOT.rglob("*.md") if path.is_file()
                  and not any(part in SKIP_DIRS or part.startswith(".") for part in path.relative_to(REPO_ROOT).parts)
                  and not path.is_symlink())


def _link_targets(document: str) -> list[str]:
    fenced = False
    marker = ""
    links: list[str] = []
    for line in document.splitlines():
        stripped = line.lstrip()
        if stripped.startswith((chr(96) * 3, "~~~")):
            token = stripped[:3]
            if not fenced:
                fenced, marker = True, token
            elif token == marker:
                fenced = False
            continue
        if fenced:
            continue
        for match in LINK_RE.finditer(line):
            links.append(match.group("dest").strip("<>"))
    return links


def resolve_reference(doc_path: Path, ref: str) -> Path | None:
    """Resolve a local link, returning None for URLs and anchors only."""
    if not ref or ref.startswith("#") or ref.startswith("//"):
        return None
    parsed = urlsplit(ref)
    if parsed.scheme or parsed.netloc:
        return None
    raw_path = unquote(parsed.path)
    if not raw_path:
        return None
    candidate = Path(raw_path)
    if candidate.is_absolute() or "\\" in raw_path or "\x00" in raw_path:
        return REPO_ROOT / "__unsafe_absolute_link__"
    target = (doc_path.parent / candidate).resolve()
    if target.exists():
        return target
    if candidate.parts and candidate.parts[0] in {
            "orion", "docs", "skills", "samples", "tests", "tools", "schemas", "evals", "eval-results"
    }:
        root_target = (REPO_ROOT / candidate).resolve()
        if root_target.exists():
            return root_target
    return target


def main() -> int:
    checked = 0
    failures: list[dict[str, str]] = []
    categories: Counter[str] = Counter()
    existing_files: set[Path] = set()
    documents = _markdown_files()
    root = REPO_ROOT.resolve()
    for path in documents:
        categories[categorize_file(path)] += 1
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("Markdown exceeds 2 MiB inspection limit")
            document = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError) as exc:
            failures.append({"file": path.relative_to(root).as_posix(), "ref": "", "reason": str(exc)})
            continue
        for link in _link_targets(document):
            target = resolve_reference(path, link)
            if target is None:
                continue
            checked += 1
            try:
                target.relative_to(root)
            except ValueError:
                failures.append({"file": path.relative_to(root).as_posix(), "ref": link,
                                 "reason": "destination escapes repository"})
                continue
            if not target.is_file():
                failures.append({"file": path.relative_to(root).as_posix(), "ref": link,
                                 "reason": "local file not found"})
            else:
                existing_files.add(target)
    counts: Counter[str] = Counter(item["file"] for item in failures)
    broken_by_type: Counter[str] = Counter(Path(item["ref"].split("#", 1)[0]).suffix for item in failures)
    result = {
        "summary": {
            "total_files": len(documents), "docs_checked": len(documents), "checked_refs": checked,
            "missing_refs": len(failures), "files_with_broken_refs": len(counts),
            "broken_by_type": dict(broken_by_type),
            "verification_scope": "explicit local Markdown links only; not arbitrary inline code",
        },
        "details": {"files_with_broken_refs": [{"file": file, "broken_count": count}
                    for file, count in sorted(counts.items())],
                    "categories": dict(categories), "linked_files": len(existing_files)},
        "missing_refs": failures[:50],
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
