#!/usr/bin/env python3
"""
build_singlefile_site.py - Constructor de sitio HTML monolítico con dataset embebido.

Genera página HTML única autónoma que contiene:
- Toda la base de conocimientos ORION-HACKING
- CSS y JavaScript integrados (sin dependencias externas)
- Dataset JSON embebido para scraping por IA
- Búsqueda y filtrado en el cliente
- Diseño responsivo y accesible
- Metadatos legibles por máquina

Características:
- Escanea recursivamente archivos .md, .py, .ps1, .sh, .json
- Extrae títulos automáticamente de documentos
- Clasifica contenido por categoría
- Genera tabla de contenidos navegable
- Proporciona búsqueda de texto completo en el cliente
- Exporta JSON embebido para parseo por agentes IA

Uso:
    python3 build_singlefile_site.py

Salida:
    orion/ORION-HACKING-singlefile.html
"""

import html
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from collections import defaultdict


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_PATHS = [
    REPO_ROOT / "orion" / "ORION-HACKING-singlefile.html",
]
INCLUDE_EXTS = {".md", ".json", ".py", ".ps1", ".sh"}
SKIP_PARTS = {"__pycache__", ".git", ".github", "node_modules", ".venv",
              "evidence", "private", "audit", "engagements", "build", "dist"}
SKIP_NAMES = {"credentials.json", "secrets.json", "approval.json", "lab-approval.json"}
PUBLISHED_ROOTS = {"README.md", "AGENTS.md", "orion", "docs", "samples", "schemas",
                   "skills", "evals", "eval-results", "tools"}
MAX_SINGLE_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024


def slugify(value: str) -> str:
    """Convierte texto a identificador HTML válido."""
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def classify(path: pathlib.Path) -> str:
    """Clasifica archivo por su directorio."""
    rel = path.relative_to(REPO_ROOT).as_posix()

    if rel == "README.md":
        return "root"
    if rel.startswith("orion/references/"):
        return "reference"
    if rel.startswith("orion/playbooks/"):
        return "playbook"
    if rel.startswith("orion/scripts/"):
        return "script"
    if rel.startswith("orion/"):
        return "core"
    if rel.startswith("evals/"):
        return "eval"
    if rel.startswith("eval-results/"):
        return "result"
    if rel.startswith("samples/"):
        return "sample"

    return "other"


def title_from_path(path: pathlib.Path) -> str:
    """Extrae título de un archivo (primero encabezado H1 para .md)."""
    path.relative_to(REPO_ROOT)  # Require a path in the published source tree.

    if path.suffix == ".md":
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if line.startswith("# "):
                    title = line[2:].strip()
                    if title:
                        return title
        except Exception:
            pass

    # Fallback: nombre del archivo limpio
    return path.stem.replace("-", " ").replace("_", " ").title()


def get_file_size(path: pathlib.Path) -> int:
    """Retorna tamaño del archivo en bytes."""
    try:
        return path.stat().st_size
    except OSError:
        return 0


def extract_summary(path: pathlib.Path, max_length: int = 200) -> str:
    """Extrae resumen de primeras líneas del archivo."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Omite encabezados markdown
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        summary = " ".join(lines[:3])  # Primeras 3 líneas no vacías
        return summary[:max_length] + ("..." if len(summary) > max_length else "")
    except Exception:
        return ""


def files_to_include() -> List[pathlib.Path]:
    """Publish only documented project locations, never arbitrary local files."""
    files: List[pathlib.Path] = []
    total_bytes = 0
    root = REPO_ROOT.resolve()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not rel.parts or rel.parts[0] not in PUBLISHED_ROOTS:
            continue
        if path.is_symlink() or not path.is_file() or any(part.startswith(".") or part in SKIP_PARTS
                                                        for part in rel.parts):
            continue
        if path.name.casefold() in SKIP_NAMES or path.suffix.casefold() not in INCLUDE_EXTS:
            continue
        file_bytes = path.stat().st_size
        if file_bytes > MAX_SINGLE_FILE_BYTES:
            continue
        total_bytes += file_bytes
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("publication exceeds 16 MiB; select smaller documentation inputs")
        files.append(path)
    return files


def build_sections(files: List[pathlib.Path]) -> Tuple[str, str, List[Dict], Dict]:
    """
    Construye secciones de navegación, cuerpo y dataset.

    Retorna: (nav_html, body_html, data_array, statistics)
    """
    nav_parts = []
    body_parts = []
    data = []
    stats = defaultdict(int)

    for path in files:
        rel = path.relative_to(REPO_ROOT).as_posix()
        category = classify(path)
        title = title_from_path(path)
        anchor = slugify(rel)
        file_size = get_file_size(path)
        summary = extract_summary(path)

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            text = "[Error reading file]"

        # Stats
        stats[category] += 1
        stats["total_size"] += file_size

        # Navegación
        nav_parts.append(
            f'<a class="toc-link" href="#{anchor}" data-category="{category}" '
            f'data-size="{file_size}" title="{html.escape(title)}">'
            f'<span class="toc-title">{html.escape(title)}</span>'
            f'<code class="toc-path">{html.escape(rel)}</code>'
            f'<span class="toc-size">{file_size:,} bytes</span>'
            f'</a>'
        )

        # Cuerpo del documento
        body_parts.append(
            f'''<article id="{anchor}" class="doc-card" data-category="{category}"
                    data-path="{html.escape(rel)}" data-title="{html.escape(title)}"
                    data-size="{file_size}" data-index="{len(data)}">
  <header class="doc-header">
    <div class="doc-meta">
      <span class="pill">{html.escape(category)}</span>
      <code class="doc-size">{file_size:,} bytes</code>
      <span class="doc-extension">{html.escape(path.suffix)}</span>
    </div>
    <h2>{html.escape(title)}</h2>
    <p class="doc-path">{html.escape(rel)}</p>
    {f'<p class="doc-summary">{html.escape(summary)}</p>' if summary else ''}
  </header>
  <section class="doc-content" data-consultable="{html.escape(text[:500].lower())}">
    <pre><code>{html.escape(text)}</code></pre>
  </section>
</article>'''
        )

        # Dataset JSON
        data.append({
            "path": rel,
            "category": category,
            "title": title,
            "extension": path.suffix,
            "size_bytes": file_size,
            "summary": summary,
            "content": text,
            "anchor": anchor,
            "last_modified": datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]) if "SOURCE_DATE_EPOCH" in os.environ else path.stat().st_mtime, timezone.utc).isoformat(),
        })

    return "\n".join(nav_parts), "\n".join(body_parts), data, dict(stats)


def build_html() -> str:
    """Construye página HTML completa."""
    print("📦 Escaneando archivos...", file=sys.stderr)
    files = files_to_include()
    print(f"   ✓ {len(files)} archivos encontrados", file=sys.stderr)

    print("🔨 Construyendo secciones...", file=sys.stderr)
    nav_html, body_html, data, raw_stats = build_sections(files)

    # Procesa estadísticas
    counts = {
        cat: raw_stats.get(cat, 0)
        for cat in ["root", "core", "reference", "playbook", "script", "eval", "result", "sample", "other"]
    }
    counts = {k: v for k, v in counts.items() if v > 0}

    total_docs = len(data)
    total_size = raw_stats.get("total_size", 0)

    # Genera HTML de estadísticas
    stats_html = ""
    for key in ["root", "core", "reference", "playbook", "script", "eval", "result", "sample"]:
        if key in counts:
            stats_html += f'''<div class="stat">
  <strong>{counts[key]}</strong>
  <span>{html.escape(key)}</span>
</div>
'''

    # Dataset JSON embebido
    dataset = {
        "name": "ORION-HACKING",
        "format": "singlefile-html",
        "version": "1.0",
        "scrapeable": True,
        "generated": datetime.fromtimestamp(int(os.environ.get("SOURCE_DATE_EPOCH", str(int(datetime.now(timezone.utc).timestamp())))), timezone.utc).isoformat(),
        "stats": {
            "total_documents": total_docs,
            "total_size_bytes": total_size,
            "categories": counts,
        },
        "entries": data,
    }

    dataset_json = json.dumps(
        dataset,
        ensure_ascii=False,
        indent=2,
    ).replace("<", "\\u003c").replace(">", "\\u003e")  # Escape all HTML parser delimiters

    print(f"✓ {total_docs} documentos, {total_size:,} bytes totales", file=sys.stderr)

    # Construye HTML final
    html_content = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=5">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>ORION-HACKING Singlefile - Knowledge Base</title>
  <meta name="description" content="ORION-HACKING: Single-file knowledge base with embedded JSON for authorized cybersecurity workflows and AI-driven safe automation.">
  <meta name="keywords" content="cybersecurity,pentesting,offensive security,red team,blue team,security automation">
  <meta name="theme-color" content="#b34b2e">
  <meta name="robots" content="noindex,nofollow">

  <style>
    :root {{
      --bg: #efe8dc;
      --bg-deep: #e5dac8;
      --panel: rgba(255, 251, 244, 0.9);
      --panel-strong: #fffdf9;
      --ink: #181511;
      --muted: #675f54;
      --line: rgba(87, 64, 41, 0.16);
      --line-strong: rgba(87, 64, 41, 0.28);
      --accent: #b34b2e;
      --accent-deep: #7b2c18;
      --accent-soft: rgba(179, 75, 46, 0.1);
      --accent-glow: rgba(179, 75, 46, 0.2);
      --code: #f6efe2;
      --chip: #f4ead7;
      --shadow: 0 20px 50px rgba(45, 29, 16, 0.09);
      --shadow-soft: 0 12px 24px rgba(45, 29, 16, 0.05);
      --radius-xl: 28px;
      --radius-lg: 22px;
      --radius-md: 16px;
    }}

    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}

    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "IBM Plex Serif", Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, var(--accent-glow), transparent 26rem),
        radial-gradient(circle at right 10% top 10%, rgba(36, 115, 122, 0.1), transparent 24rem),
        linear-gradient(180deg, #faf6ef 0%, var(--bg) 55%, var(--bg-deep) 100%);
      background-attachment: fixed;
      line-height: 1.6;
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(122, 86, 51, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(122, 86, 51, 0.04) 1px, transparent 1px);
      background-size: 28px 28px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.16), transparent 75%);
      z-index: 0;
    }}

    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ background: var(--chip); padding: 0.2em 0.4em; border-radius: 4px; font-family: "Cascadia Code", Consolas, monospace; }}
    h1, h2, h3 {{ line-height: 1.2; }}

    .shell {{
      display: grid;
      grid-template-columns: 24rem minmax(0, 1fr);
      min-height: 100vh;
      position: relative;
      z-index: 1;
    }}

    .sidebar {{
      position: sticky;
      top: 0;
      height: 100vh;
      overflow: auto;
      border-right: 1px solid var(--line);
      background: rgba(252, 247, 239, 0.85);
      backdrop-filter: blur(12px);
      padding: 1.2rem;
    }}

    .sidebar-shell {{
      display: grid;
      gap: 1.2rem;
    }}

    .brand {{
      padding: 1.2rem;
      border-radius: var(--radius-lg);
      border: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.85), rgba(246,236,220,0.8));
      box-shadow: var(--shadow-soft);
    }}

    .brand h1 {{
      margin: 0;
      font-size: 1.7rem;
      line-height: 0.95;
      letter-spacing: 0.02em;
    }}

    .brand p {{
      margin: 0.55rem 0 0;
      color: var(--muted);
      font-size: 0.92rem;
    }}

    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      margin-bottom: 0.7rem;
      padding: 0.32rem 0.55rem;
      border-radius: 999px;
      border: 1px solid rgba(179, 75, 46, 0.2);
      background: var(--accent-soft);
      color: var(--accent-deep);
      font-size: 0.68rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-weight: 600;
    }}

    .sidebar-block {{
      padding: 1rem;
      border-radius: var(--radius-lg);
      border: 1px solid var(--line);
      background: var(--panel);
      box-shadow: var(--shadow-soft);
    }}

    .sidebar-block h3 {{
      margin: 0 0 0.8rem 0;
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}

    .search {{
      width: 100%;
      padding: 0.8rem 1rem;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel-strong);
      color: var(--ink);
      font: inherit;
      margin: 0;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.65);
      transition: all 160ms ease;
    }}

    .search:focus {{
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(179, 75, 46, 0.1);
    }}

    .filters {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-top: 0.8rem;
    }}

    .filter {{
      border: 1px solid var(--line);
      background: var(--panel-strong);
      color: var(--muted);
      border-radius: 999px;
      padding: 0.4rem 0.7rem;
      font: inherit;
      cursor: pointer;
      transition: 160ms ease;
      font-size: 0.85rem;
    }}

    .filter:hover {{
      transform: translateY(-1px);
      border-color: var(--accent);
    }}

    .filter.active {{
      color: white;
      background: linear-gradient(180deg, var(--accent), var(--accent-deep));
      border-color: transparent;
      box-shadow: 0 8px 16px rgba(179, 75, 46, 0.2);
    }}

    .toc {{
      display: grid;
      gap: 0.5rem;
      max-height: calc(100vh - 500px);
      overflow-y: auto;
    }}

    .toc-link {{
      display: grid;
      gap: 0.15rem;
      text-decoration: none;
      color: var(--ink);
      padding: 0.7rem 0.8rem;
      border-radius: 0.8rem;
      background: rgba(255,255,255,0.35);
      border: 1px solid transparent;
      transition: 160ms ease;
      font-size: 0.85rem;
    }}

    .toc-link:hover {{
      background: var(--accent-soft);
      border-color: rgba(179, 75, 46, 0.2);
      transform: translateX(2px);
    }}

    .toc-title {{
      font-weight: 500;
      color: var(--ink);
    }}

    .toc-path {{
      color: var(--muted);
      font-size: 0.75rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    .toc-size {{
      color: var(--muted);
      font-size: 0.7rem;
    }}

    .main {{
      padding: 1.5rem 1.6rem 3rem;
      overflow-y: auto;
    }}

    .main-shell {{
      max-width: 1280px;
      margin: 0 auto;
      display: grid;
      gap: 1.5rem;
    }}

    .masthead {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
      padding: 0.5rem 0;
      flex-wrap: wrap;
    }}

    .masthead-copy h2 {{
      margin: 0;
      font-size: 0.9rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}

    .masthead-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.6rem 0.9rem;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.5);
      box-shadow: var(--shadow-soft);
      font-size: 0.8rem;
      color: var(--muted);
    }}

    .hero {{
      background: linear-gradient(180deg, rgba(255,255,255,0.9), rgba(252,245,235,0.88));
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      border-radius: var(--radius-xl);
      padding: 2rem;
    }}

    .hero h2 {{
      margin: 0 0 1rem 0;
      font-size: clamp(1.8rem, 4vw, 3rem);
      line-height: 1;
    }}

    .hero p {{
      margin: 0.5rem 0 0;
      color: var(--muted);
      max-width: 65ch;
      font-size: 1rem;
    }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 0.8rem;
    }}

    .stat {{
      display: grid;
      gap: 0.2rem;
      align-content: center;
      padding: 1rem;
      border-radius: var(--radius-lg);
      background: linear-gradient(180deg, rgba(255,255,255,0.85), rgba(246,235,217,0.8));
      border: 1px solid var(--line);
      box-shadow: var(--shadow-soft);
      text-align: center;
    }}

    .stat strong {{
      font-size: 1.8rem;
      line-height: 1;
      color: var(--accent-deep);
    }}

    .stat span {{
      color: var(--muted);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}

    .control-bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem 1.2rem;
      border-radius: var(--radius-lg);
      border: 1px solid var(--line);
      background: rgba(255, 251, 244, 0.8);
      box-shadow: var(--shadow-soft);
      flex-wrap: wrap;
    }}

    .control-title strong {{
      font-size: 0.95rem;
    }}

    .control-state {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }}

    .state-chip {{
      padding: 0.4rem 0.7rem;
      border-radius: 999px;
      background: var(--chip);
      border: 1px solid var(--line);
      font-size: 0.8rem;
      color: var(--muted);
    }}

    .docs {{
      display: grid;
      gap: 1.2rem;
    }}

    .doc-card {{
      position: relative;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      border-radius: var(--radius-lg);
      overflow: hidden;
      transition: transform 160ms ease, box-shadow 160ms ease;
    }}

    .doc-card:hover {{
      transform: translateY(-2px);
      box-shadow: 0 24px 60px rgba(45, 29, 16, 0.12);
    }}

    .doc-card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: linear-gradient(180deg, var(--accent), rgba(36, 115, 122, 0.6));
    }}

    .doc-header {{
      padding: 1.2rem 1.3rem 0.8rem 1.4rem;
      border-bottom: 1px solid var(--line);
    }}

    .doc-meta {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-bottom: 0.6rem;
    }}

    .pill {{
      background: var(--accent-soft);
      color: var(--accent-deep);
      border: 1px solid rgba(179,75,46,0.15);
      border-radius: 999px;
      padding: 0.25rem 0.55rem;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 600;
    }}

    .doc-extension, .doc-size {{
      color: var(--muted);
      font-size: 0.78rem;
    }}

    .doc-header h2 {{
      margin: 0 0 0.3rem 0;
      font-size: 1.15rem;
      line-height: 1.25;
    }}

    .doc-path {{
      margin: 0;
      color: var(--muted);
      font-size: 0.8rem;
      font-family: monospace;
    }}

    .doc-summary {{
      margin: 0.4rem 0 0 0;
      color: var(--muted);
      font-size: 0.88rem;
      line-height: 1.4;
    }}

    .doc-content {{
      padding: 0;
    }}

    .doc-content pre {{
      margin: 0;
      padding: 1rem 1.3rem 1.2rem 1.4rem;
      overflow: auto;
      max-height: 400px;
      white-space: pre-wrap;
      word-break: break-word;
      background: linear-gradient(180deg, rgba(248,243,232,0.6), rgba(255,253,248,0.9));
      font-family: "Cascadia Code", "IBM Plex Mono", Consolas, monospace;
      font-size: 0.8rem;
      line-height: 1.6;
    }}

    .doc-content code {{
      background: transparent;
      padding: 0;
    }}

    .hidden {{
      display: none !important;
    }}

    ::selection {{
      background: rgba(179, 75, 46, 0.2);
      color: var(--ink);
    }}

    .info-box {{
      padding: 1rem;
      border-left: 4px solid var(--accent);
      background: var(--accent-soft);
      border-radius: 0.4rem;
      margin: 1rem 0;
      font-size: 0.9rem;
    }}

    @media (max-width: 1024px) {{
      .shell {{
        grid-template-columns: 1fr;
      }}

      .sidebar {{
        position: static;
        height: auto;
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }}
    }}

    @media (max-width: 640px) {{
      .masthead {{
        flex-direction: column;
        align-items: flex-start;
      }}

      .main {{
        padding: 1rem;
      }}

      .sidebar {{
        padding: 1rem;
      }}

      .hero {{
        padding: 1.5rem;
      }}

      .doc-card pre {{
        max-height: 250px;
        font-size: 0.75rem;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="sidebar-shell">
        <div class="brand">
          <div class="eyebrow">singlefile knowledge</div>
          <h1>ORION-HACKING</h1>
          <p>Base de conocimientos integrada para flujos de ciberseguridad autorizada y automatización segura.</p>
        </div>

        <div class="sidebar-block">
          <input id="search" class="search" type="search" placeholder="Buscar documentos...">
          <div class="filters" id="filters">
            <button class="filter active" data-filter="all">Todos</button>
            <button class="filter" data-filter="root">Raíz</button>
            <button class="filter" data-filter="core">Núcleo</button>
            <button class="filter" data-filter="reference">Referencias</button>
            <button class="filter" data-filter="playbook">Playbooks</button>
            <button class="filter" data-filter="script">Scripts</button>
          </div>
        </div>

        <div class="sidebar-block">
          <h3>Documentos</h3>
          <nav class="toc" id="toc">
            {nav_html}
          </nav>
        </div>
      </div>
    </aside>

    <main class="main">
      <div class="main-shell">
        <section class="masthead">
          <div class="masthead-copy">
            <h2>Base de conocimientos integrada</h2>
          </div>
          <div class="masthead-badge">JSON embebido · Sin dependencias externas</div>
        </section>

        <section class="hero">
          <h2>ORION-HACKING Singlefile</h2>
          <p>Página HTML autónoma que contiene la base de conocimientos completa con búsqueda en el cliente, filtrado interactivo y dataset JSON embebido para scraping por agentes IA. No requiere conexión de red ni servidor externo.</p>
          <div class="info-box">
            <strong>Características:</strong> Texto completo consultable, navegación por categoría, responsivo, accesible, datos legibles por máquina.
          </div>
        </section>

        <section class="stats" aria-label="Estadísticas del dataset">
          <div class="stat">
            <strong>{total_docs}</strong>
            <span>Documentos</span>
          </div>
          {stats_html}
        </section>

        <section class="control-bar">
          <strong>Estado Vivo:</strong>
          <div class="control-state">
            <span class="state-chip" id="visible-count">0 visibles</span>
            <span class="state-chip" id="active-filter">filtro: todos</span>
          </div>
        </section>

        <section class="docs" id="docs">
          {body_html}
        </section>
      </div>
    </main>
  </div>

  <script id="orion-dataset" type="application/json">
{dataset_json}
  </script>

  <script>
    (function() {{
      'use strict';

      const search = document.getElementById('search') || null;
      const filters = Array.from(document.querySelectorAll('.filter'));
      const cards = Array.from(document.querySelectorAll('.doc-card'));
      const tocLinks = Array.from(document.querySelectorAll('.toc-link'));
      const visibleCount = document.getElementById('visible-count');
      const consultable = new Map(cards.map(card => [card, [
        card.dataset.title || '', card.dataset.path || '', card.textContent || ''
      ].join('\\n').toLowerCase()]));
      const activeFilterLabel = document.getElementById('active-filter');
      let activeFilter = 'all';

      function applyFilters() {{
        const query = (search?.value || '').trim().toLowerCase();
        let shown = 0;

        cards.forEach(card => {{
          const cardHaystack = consultable.get(card) || '';

          const categoryOk = activeFilter === 'all' || card.dataset.category === activeFilter;
          const queryOk = !query || cardHaystack.includes(query);
          const show = categoryOk && queryOk;

          card.classList.toggle('hidden', !show);
          if (show) shown += 1;
        }});

        tocLinks.forEach(link => {{
          const target = document.querySelector(link.getAttribute('href'));
          const shouldHideToc = !target || target.classList.contains('hidden');
          link.classList.toggle('hidden', shouldHideToc);
        }});

        if (visibleCount) {{
          visibleCount.textContent = `${{shown}} visible${{shown !== 1 ? 's' : ''}}`;
        }}
        if (activeFilterLabel) {{
          activeFilterLabel.textContent = `filtro: ${{activeFilter}}`;
        }}
      }}

      filters.forEach(btn => {{
        btn.addEventListener('click', () => {{
          activeFilter = btn.dataset.filter;
          filters.forEach(item => {{
            item.classList.toggle('active', item === btn);
          }});
          applyFilters();
        }});
      }});

      if (search) {{
        let pending = false;
        search.addEventListener('input', () => {{
          if (!pending) {{
            pending = true;
            requestAnimationFrame(() => {{
              pending = false;
              applyFilters();
            }});
          }}
        }});
      }}

      applyFilters();
    }})();
  </script>
</body>
</html>
"""

    return html_content


def main() -> int:
    """Construye y escribe archivos HTML."""
    print("🏗️  ORION-HACKING Single-File Builder", file=sys.stderr)
    print("=" * 50, file=sys.stderr)

    try:
        html_content = build_html()

        print("📝 Escribiendo archivos de salida...", file=sys.stderr)
        for out_path in OUT_PATHS:
            out_path.write_text(html_content, encoding="utf-8")
            size_mb = out_path.stat().st_size / (1024 * 1024)
            print(f"   ✓ {out_path.name} ({size_mb:.2f} MB)", file=sys.stderr)

        print("=" * 50, file=sys.stderr)
        print("✅ Build completado exitosamente", file=sys.stderr)
        return 0

    except Exception as e:
        print(f"❌ Error durante build: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

