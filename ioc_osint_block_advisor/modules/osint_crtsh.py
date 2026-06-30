from __future__ import annotations

import requests


KEYWORDS = {"login", "sso", "secure", "verify", "auth", "account", "meta", "microsoft", "wallet", "bank", "payment"}


def query(domain: str) -> dict:
    try:
        response = requests.get("https://crt.sh/", params={"q": domain, "output": "json"}, timeout=10)
        if response.status_code >= 500:
            return {"source": "crtsh", "status": "error", "score_delta": 0, "evidence": f"crt.sh HTTP {response.status_code}"}
        data = response.json() if response.text.strip() else []
        names = sorted({name.lower().strip() for row in data[:200] for name in row.get("name_value", "").splitlines()})
        suspicious = [name for name in names if any(keyword in name for keyword in KEYWORDS)]
        score_delta = 20 if len(suspicious) >= 5 else 15 if suspicious else 0
        return {
            "source": "crtsh",
            "status": "ok",
            "subdomains": names[:100],
            "suspicious_subdomains": suspicious[:50],
            "score_delta": score_delta,
            "evidence": f"Found {len(names)} certificate names; suspicious={len(suspicious)}",
        }
    except Exception as exc:
        return {"source": "crtsh", "status": "error", "score_delta": 0, "evidence": str(exc)}
