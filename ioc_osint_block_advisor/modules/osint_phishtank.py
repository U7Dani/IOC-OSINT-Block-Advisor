from __future__ import annotations


def query(url: str) -> dict:
    return {
        "source": "phishtank",
        "status": "skipped",
        "score_delta": 0,
        "evidence": "PhishTank public API access is optional and not queried in MVP.",
    }
