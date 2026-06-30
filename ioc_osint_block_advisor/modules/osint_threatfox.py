from __future__ import annotations

import requests


def query(value: str) -> dict:
    try:
        response = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": value}, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") == "ok":
            return {"source": "threatfox", "status": "hit", "score_delta": 50, "evidence": "IOC associated with ThreatFox malware/campaign data", "raw": data}
        return {"source": "threatfox", "status": "not_found", "score_delta": 0, "evidence": "No ThreatFox match"}
    except Exception as exc:
        return {"source": "threatfox", "status": "error", "score_delta": 0, "evidence": str(exc)}
