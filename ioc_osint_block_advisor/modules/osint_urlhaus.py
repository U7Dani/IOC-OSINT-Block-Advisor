from __future__ import annotations

import requests


def query(value: str, ioc_type: str) -> dict:
    try:
        if ioc_type == "url":
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
            payload = {"url": value}
        elif ioc_type == "domain":
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            payload = {"host": value}
        else:
            return {"source": "urlhaus", "status": "skipped", "score_delta": 0, "evidence": "URLhaus supports URL/domain in this tool"}
        response = requests.post(endpoint, data=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") in {"ok", "malicious"}:
            return {"source": "urlhaus", "status": "hit", "score_delta": 50, "evidence": "IOC reported by URLhaus", "raw": data}
        return {"source": "urlhaus", "status": "not_found", "score_delta": 0, "evidence": "No URLhaus match"}
    except Exception as exc:
        return {"source": "urlhaus", "status": "error", "score_delta": 0, "evidence": str(exc)}
