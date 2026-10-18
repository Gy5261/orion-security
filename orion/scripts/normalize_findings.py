"""Normaliza hallazgos aportados por el operador; no inventa vulnerabilidades.

Sólo transforma valores suministrados. Los cálculos heurísticos son marcados como
estimaciones; CVSS es un valor declarado, no una evaluación técnica verificada.
Entrada: una lista JSON o un objeto JSON. Salida: estadísticas y hallazgos.
"""
from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from typing import Any

from orion.jsonio import read_json

MAX_INPUT_BYTES = 1024 * 1024
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ALIASES = {
    "critical": "critical", "urgent": "critical", "blocker": "critical",
    "high": "high", "major": "high", "important": "high",
    "medium": "medium", "moderate": "medium", "normal": "medium",
    "low": "low", "minor": "low", "trivial": "low",
    "info": "info", "informational": "info", "information": "info",
}
STATUS_ALIASES = {
    "open": "open", "new": "open",
    "closed": "closed", "fixed": "closed", "resolved": "closed", "remediated": "closed",
    "mitigated": "mitigated", "partial": "mitigated",
    "accepted": "accepted", "risk_accepted": "accepted",
}
SEVERITY_ESTIMATES = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
EFFORT_ESTIMATES = {"critical": 9, "high": 7, "medium": 5, "low": 2, "info": 1}


def normalize_severity(value: Any) -> str:
    if value is None or value == "":
        return "info"
    severity = str(value).strip().casefold()
    if severity not in SEVERITY_ALIASES:
        raise ValueError(f"unrecognized severity: {severity[:64]}")
    return SEVERITY_ALIASES[severity]


def normalize_status(value: Any) -> str:
    if value is None or value == "":
        return "open"
    status = str(value).strip().casefold()
    if status not in STATUS_ALIASES:
        raise ValueError(f"unrecognized finding status: {status[:64]}")
    return STATUS_ALIASES[status]


def _text(value: Any, key: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    return value.strip() or None


def _cvss(value: Any) -> float | None:
    if value is None:
        return None
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError("CVSS must be a finite number from 0 to 10; it cannot be silently clamped")
    return float(value)


def _cwe(value: Any) -> str | None:
    text = _text(value, "cwe")
    if text is None:
        return None
    identifier = text.upper().replace("CWE-", "")
    if not re.fullmatch(r"[1-9][0-9]{0,6}", identifier):
        raise ValueError("cwe must contain a numeric CWE identifier")
    return f"CWE-{identifier}"


def calculate_remediation_effort(finding: dict[str, Any]) -> int:
    """Heuristic estimate, NOT a verified schedule or engineering commitment."""
    severity = normalize_severity(finding.get("severity"))
    effort = EFFORT_ESTIMATES[severity]
    recommendation = str(finding.get("recommendation") or "").casefold()
    if "architecture" in recommendation or "redesign" in recommendation:
        effort += 2
    elif "install" in recommendation or "patch" in recommendation:
        effort -= 1
    return max(1, min(effort, 10))


def calculate_risk_score(finding: dict[str, Any]) -> float:
    """Preserve a supplied CVSS value; otherwise return a labeled heuristic."""
    cvss = _cvss(finding.get("cvss"))
    return cvss if cvss is not None else SEVERITY_ESTIMATES[normalize_severity(finding.get("severity"))]


def normalize_finding(raw_finding: Any) -> dict[str, Any] | None:
    if not isinstance(raw_finding, dict):
        return None
    title = _text(raw_finding.get("title"), "title")
    if title is None:
        return None
    severity = normalize_severity(raw_finding.get("severity"))
    cvss = _cvss(raw_finding.get("cvss"))
    normalized: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "asset": _text(raw_finding.get("asset"), "asset"),
        "evidence": _text(raw_finding.get("evidence"), "evidence"),
        "recommendation": _text(raw_finding.get("recommendation"), "recommendation"),
        "cvss": cvss,
        "cwe": _cwe(raw_finding.get("cwe")),
        "status": normalize_status(raw_finding.get("status")),
        "risk_score_method": "supplied_cvss_unverified" if cvss is not None else "severity_heuristic",
        "remediation_effort_method": "severity_heuristic_not_validated",
    }
    normalized["remediation_effort"] = calculate_remediation_effort(normalized)
    normalized["risk_score"] = calculate_risk_score(normalized)
    return normalized


def main() -> int:
    try:
        data = read_json(sys.stdin.buffer, max_bytes=MAX_INPUT_BYTES)
        if not isinstance(data, (dict, list)):
            raise ValueError("input must be an object or a list of objects")
        rows = data if isinstance(data, list) else [data]
        normalized: list[dict[str, Any]] = []
        skipped = 0
        for i, item in enumerate(rows):
            try:
                finding = normalize_finding(item)
            except ValueError as exc:
                raise ValueError(f"finding[{i}]: {exc}") from exc
            if finding is None:
                skipped += 1
            else:
                normalized.append(finding)
        normalized.sort(key=lambda finding: (SEVERITY_ORDER[finding["severity"]], -finding["risk_score"]))
        severities = Counter(finding["severity"] for finding in normalized)
        summary = {
            "total_findings": len(normalized),
            "skipped_entries": skipped,
            "by_severity": {key: severities.get(key, 0) for key in SEVERITY_ORDER},
            "open_findings": sum(finding["status"] == "open" for finding in normalized),
            "risk_scores_estimated": sum(finding["cvss"] is None for finding in normalized),
            "avg_risk_score": sum(finding["risk_score"] for finding in normalized) / len(normalized)
                              if normalized else None,
            "risk_score_warning": "Average mixes supplied CVSS and heuristic estimates; not a verified risk metric",
        }
        print(json.dumps({"summary": summary, "findings": normalized}, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
