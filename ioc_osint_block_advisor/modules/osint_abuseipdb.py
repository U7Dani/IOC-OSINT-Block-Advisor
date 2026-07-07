from __future__ import annotations

import os

import requests
from dotenv import load_dotenv


def query(ip: str) -> dict:
    """Consulta AbuseIPDB para reputación de IP. Degrada de forma segura
    (skipped) si no hay API key configurada; nunca inventa un score."""
    load_dotenv()
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return {"source": "abuseipdb", "status": "skipped", "score_delta": 0, "evidence": "ABUSEIPDB_API_KEY no configurada"}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        if score >= 75:
            status, delta = "hit", 45
        elif score >= 40:
            status, delta = "suspicious", 20
        else:
            status, delta = "not_found", 0
        evidence = f"AbuseIPDB: confidence={score}%, reports={reports}"
        return {"source": "abuseipdb", "status": status, "score_delta": delta, "evidence": evidence, "raw": data}
    except Exception as exc:
        return {"source": "abuseipdb", "status": "error", "score_delta": 0, "evidence": str(exc)}
