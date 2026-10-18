#!/usr/bin/env python3
"""
log_triage.py - Análisis y clasificación automática de eventos de seguridad.

Procesa archivos JSON de eventos y genera resumen ejecutivo con:
- Estadísticas globales (total eventos, distribución temporal)
- Usuarios únicos y análisis de comportamiento
- Clasificación por tipo de evento
- Timeline de eventos críticos
- Detección de anomalías simples

Uso:
    python3 log_triage.py <events.json>

Formato JSON esperado:
    [
        {
            "timestamp": "2024-01-01T12:00:00Z",
            "user": "admin",
            "source": "192.168.1.1",
            "type": "auth_failed|auth_success|access|config_change|...",
            "severity": "critical|high|medium|low|info",
            "message": "descripción del evento"
        },
        ...
    ]
"""

import json
import sys
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import Dict, Any

from orion.jsonio import read_json_file


def parse_timestamp(ts_str: str) -> datetime | None:
    """Return comparable UTC instants; legacy timestamps without offsets use UTC."""
    if not isinstance(ts_str, str):
        return None
    try:
        parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(ts_str, "%d/%m/%Y %H:%M:%S")
        except ValueError:
            return None
    if parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def classify_severity(event: Dict[str, Any]) -> str:
    """Clasifica severity de un evento basado en tipo y contenido."""
    severity = str(event.get("severity") or "info").lower()
    event_type = str(event.get("type") or "").lower()

    # Prioridades predefinidas
    critical_patterns = ["failed_login_attempts", "privilege_escalation", "malware", "breach"]
    high_patterns = ["auth_failed", "unauthorized_access", "config_change", "policy_violation"]

    message = str(event.get("message", "")).lower()

    for pattern in critical_patterns:
        if pattern in message or pattern in event_type:
            return "critical"

    for pattern in high_patterns:
        if pattern in message or pattern == event_type:
            return "high"

    return severity


def main() -> int:
    """Procesa archivo de eventos y genera reporte."""
    if len(sys.argv) != 2:
        print("Uso: log_triage.py <events.json>")
        return 1

    try:
        events = read_json_file(sys.argv[1])
    except (OSError, ValueError) as e:
        print(json.dumps({"error": f"Failed to load bounded event JSON: {e}"}))
        return 1

    if not isinstance(events, list):
        print(json.dumps({"error": "Events must be a JSON array"}))
        return 1
    if len(events) > 5000:
        print(json.dumps({"error": "Events exceed the 5000-row limit"}))
        return 1
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            print(json.dumps({"error": f"Event {index} must be a JSON object"}))
            return 1
        for field in ("user", "source", "type", "severity", "timestamp"):
            if event.get(field) is not None and not isinstance(event[field], str):
                print(json.dumps({"error": f"Event {index} field {field} must be a string"}))
                return 1

    # Inicializa contadores y estructuras
    summary = {
        "total_events": len(events),
        "users": [],
        "sources": [],
        "event_types": {},
        "severity_distribution": defaultdict(int),
        "auth_failures": 0,
        "auth_successes": 0,
        "timeline": {
            "first_event": None,
            "last_event": None,
            "events_per_hour": defaultdict(int),
            "invalid_timestamps": 0
        },
        "top_users": [],
        "top_sources": [],
        "anomalies": [],
        "statistics": {}
    }

    user_counter = Counter()
    source_counter = Counter()
    type_counter = Counter()
    time_buckets = defaultdict(int)
    observed_timestamps: list[tuple[datetime, str]] = []

    # Procesa eventos
    for event in events:
        user = event.get("user")
        source = event.get("source")
        event_type = (event.get("type") or "unknown").lower()
        severity = classify_severity(event)

        if user:
            user_counter[user] += 1
        if source:
            source_counter[source] += 1

        type_counter[event_type] += 1
        summary["severity_distribution"][severity] += 1

        # Clasifica auth eventos
        if event_type == "auth_failed":
            summary["auth_failures"] += 1
        elif event_type == "auth_success":
            summary["auth_successes"] += 1

        # Timeline
        ts = event.get("timestamp")
        if ts:
            parsed_ts = parse_timestamp(ts)
            if parsed_ts:
                hour_bucket = parsed_ts.strftime("%Y-%m-%d %H:00")
                time_buckets[hour_bucket] += 1

                observed_timestamps.append((parsed_ts, ts))
            else:
                summary["timeline"]["invalid_timestamps"] += 1

    if observed_timestamps:
        summary["timeline"]["first_event"] = min(observed_timestamps, key=lambda item: item[0])[1]
        summary["timeline"]["last_event"] = max(observed_timestamps, key=lambda item: item[0])[1]

    # Compila resultados
    summary["users"] = sorted({e.get("user") for e in events if e.get("user")})
    summary["sources"] = sorted({e.get("source") for e in events if e.get("source")})
    summary["event_types"] = dict(type_counter.most_common(10))
    summary["severity_distribution"] = dict(summary["severity_distribution"])
    summary["top_users"] = [{"user": u, "count": c} for u, c in user_counter.most_common(10)]
    summary["top_sources"] = [{"source": s, "count": c} for s, c in source_counter.most_common(5)]
    summary["timeline"]["events_per_hour"] = dict(sorted(time_buckets.items()))

    # Detección simple de anomalías
    if summary["auth_failures"] > len(events) * 0.3:
        summary["anomalies"].append({
            "type": "high_auth_failure_rate",
            "description": f"Tasa de fallos de autenticación alta: {summary['auth_failures']/len(events)*100:.1f}%"
        })

    # Si hay un usuario con muchos eventos, podría ser sospechoso
    if summary["top_users"] and summary["top_users"][0]["count"] > len(events) * 0.2:
        summary["anomalies"].append({
            "type": "concentrated_activity",
            "description": f"Usuario {summary['top_users'][0]['user']} genera {summary['top_users'][0]['count']/len(events)*100:.1f}% de eventos"
        })

    summary["statistics"] = {
        "avg_events_per_user": len(events) / max(len(summary["users"]), 1),
        "avg_events_per_source": len(events) / max(len(summary["sources"]), 1),
        "unique_user_count": len(summary["users"]),
        "unique_source_count": len(summary["sources"]),
        "unique_event_types": len(summary["event_types"])
    }

    # Salida
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
