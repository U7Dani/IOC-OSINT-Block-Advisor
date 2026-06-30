from __future__ import annotations

import os

import requests
from dotenv import load_dotenv


def query(value: str) -> dict:
    load_dotenv()
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    auto_submit = os.getenv("URLSCAN_AUTO_SUBMIT", "false").lower() == "true"
    if auto_submit:
        evidence_note = "Auto submit is enabled, but MVP only searches existing scans."
    else:
        evidence_note = "Auto submit disabled; searched existing scans only."
    headers = {"API-Key": key} if key else {}
    try:
        response = requests.get("https://urlscan.io/api/v1/search/", params={"q": f'page.url:"{value}"'}, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        total = data.get("total", 0)
        verdict_score = 20 if total else 0
        return {
            "source": "urlscan",
            "status": "ok" if total else "not_found",
            "score_delta": verdict_score,
            "evidence": f"{evidence_note} Existing scans={total}",
            "raw": data,
        }
    except Exception as exc:
        return {"source": "urlscan", "status": "error", "score_delta": 0, "evidence": str(exc)}
