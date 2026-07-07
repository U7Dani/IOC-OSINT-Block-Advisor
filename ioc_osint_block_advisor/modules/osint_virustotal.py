from __future__ import annotations

import base64
import os

import requests
from dotenv import load_dotenv


def query(value: str, ioc_type: str) -> dict:
    """Consulta VirusTotal v3. Nunca inventa resultado: si falta API key o
    la fuente falla, se marca como skipped/error, no como clean."""
    load_dotenv()
    key = os.getenv("VT_API_KEY", "").strip()
    if not key:
        return {"source": "virustotal", "status": "skipped", "score_delta": 0, "evidence": "VT_API_KEY no configurada"}

    endpoint_map = {
        "domain": f"https://www.virustotal.com/api/v3/domains/{value}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{value}",
        "hash": f"https://www.virustotal.com/api/v3/files/{value}",
        "url": None,  # requiere id derivado; ver más abajo
    }
    if ioc_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {"source": "virustotal", "status": "skipped", "score_delta": 0, "evidence": f"Tipo {ioc_type} no soportado por este módulo"}

    try:
        response = requests.get(endpoint, headers={"x-apikey": key}, timeout=10)
        if response.status_code == 404:
            return {"source": "virustotal", "status": "not_found", "score_delta": 0, "evidence": "Sin registro en VirusTotal"}
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(stats.values()) or 1
        if malicious >= 3:
            status, score_delta = "hit", 50
        elif malicious >= 1 or suspicious >= 3:
            status, score_delta = "suspicious", 20
        else:
            status, score_delta = "not_found", 0
        evidence = f"VirusTotal: {malicious}/{total} motores maliciosos, {suspicious} sospechosos"
        return {"source": "virustotal", "status": status, "score_delta": score_delta, "evidence": evidence, "raw": stats}
    except Exception as exc:
        return {"source": "virustotal", "status": "error", "score_delta": 0, "evidence": str(exc)}
