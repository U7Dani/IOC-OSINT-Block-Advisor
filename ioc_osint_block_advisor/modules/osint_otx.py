from __future__ import annotations

import os

import requests
from dotenv import load_dotenv


def query(value: str, ioc_type: str) -> dict:
    load_dotenv()
    key = os.getenv("OTX_API_KEY", "").strip()
    if not key:
        return {"source": "otx", "status": "skipped", "score_delta": 0, "evidence": "OTX_API_KEY not configured"}
    section = {"ip": "IPv4", "domain": "domain", "url": "url"}.get(ioc_type, "file")
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        score_delta = 25 if pulse_count else 0
        status = "hit" if pulse_count else "not_found"
        return {"source": "otx", "status": status, "score_delta": score_delta, "evidence": f"OTX pulse count={pulse_count}", "raw": data}
    except Exception as exc:
        return {"source": "otx", "status": "error", "score_delta": 0, "evidence": str(exc)}
