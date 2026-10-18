#!/usr/bin/env python3
"""
findings_ticket_sync.py - Convierte hallazgos normalizados en tickets Jira o ServiceNow.

Entradas:
- JSON normalizado con lista de findings

Modos:
- plan: solo genera payloads
- jira: genera o crea issues Jira si se usa --apply
- servicenow: genera o crea incidents si se usa --apply
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Iterable, List

from orion.jsonio import read_json_file


SEVERITY_TO_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sincroniza hallazgos con plataformas de tickets.")
    parser.add_argument("input", help="Archivo JSON de hallazgos.")
    parser.add_argument("--mode", choices=["plan", "jira", "servicenow"], default="plan")
    parser.add_argument("--apply", action="store_true", help="Envia tickets al backend.")
    parser.add_argument("--output", help="Archivo de salida JSON.")
    return parser.parse_args()


def load_findings(path: str) -> List[Dict[str, Any]]:
    data = read_json_file(path)
    if isinstance(data, dict):
        for key in ("findings", "items", "results"):
            if isinstance(data.get(key), list):
                return _validate_findings(data[key])
    if isinstance(data, list):
        return _validate_findings(data)
    raise ValueError("Formato de hallazgos no soportado.")


def _validate_findings(rows: List[Any]) -> List[Dict[str, Any]]:
    if not 1 <= len(rows) <= 1000 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("findings must contain between 1 and 1000 JSON objects")
    return rows


def normalize_severity(finding: Dict[str, Any]) -> str:
    value = str(
        finding.get("severity")
        or finding.get("risk")
        or finding.get("priority")
        or "medium"
    ).strip().lower()
    if value not in SEVERITY_TO_PRIORITY:
        raise ValueError(f"unsupported severity: {value[:48]}")
    return value


def summary_for(finding: Dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("name") or finding.get("finding")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("every ticket plan requires an explicit finding title")
    return title.strip()


def description_for(finding: Dict[str, Any]) -> str:
    parts = [
        f"Resumen: {summary_for(finding)}",
        f"Severidad: {normalize_severity(finding)}",
        f"Activo: {finding.get('asset') or finding.get('target') or 'n/d'}",
        f"CWE/CVE: {finding.get('cwe') or finding.get('cve') or 'n/d'}",
        f"Evidencia: {finding.get('evidence') or finding.get('details') or 'n/d'}",
        f"Remediacion: {finding.get('remediation') or finding.get('recommendation') or 'n/d'}",
    ]
    return "\n".join(parts)


def build_plan(findings: Iterable[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    if mode not in {"plan", "jira", "servicenow"}:
        raise ValueError("unsupported ticket plan mode")
    plan = []
    for finding in findings:
        severity = normalize_severity(finding)
        payload = {
            "summary": summary_for(finding),
            "description": description_for(finding),
            "labels": ["orion-hacking", severity],
            "priority": SEVERITY_TO_PRIORITY[severity],
            "source_asset": finding.get("asset") or finding.get("target"),
        }
        if mode == "jira":
            payload["jira_fields"] = {
                "project": {"key": os.getenv("JIRA_PROJECT_KEY", "SEC")},
                "issuetype": {"name": "Task"},
                "summary": payload["summary"],
                "description": payload["description"],
                "labels": payload["labels"],
            }
        if mode == "servicenow":
            payload["servicenow_fields"] = {
                "short_description": payload["summary"],
                "description": payload["description"],
                "severity": severity,
                "category": "security",
                "subcategory": "vulnerability",
            }
        plan.append(payload)
    return plan


def apply_jira(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Public compatibility API: external writes are deliberately disabled."""
    raise PermissionError("Jira writes are disabled by the controlled ORION profile")


def apply_servicenow(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Public compatibility API: external writes are deliberately disabled."""
    raise PermissionError("ServiceNow writes are disabled by the controlled ORION profile")


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
        if args.apply:
            raise PermissionError("ticket creation is disabled; export a reviewable plan instead")
        findings = load_findings(args.input)
        plan = build_plan(findings, args.mode)
        payload: Dict[str, Any] = {"mode": args.mode, "count": len(plan), "items": plan}
        write_output(payload, args.output)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[findings_ticket_sync] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
