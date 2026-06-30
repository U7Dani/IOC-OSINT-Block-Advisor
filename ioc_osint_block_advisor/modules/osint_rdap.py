from __future__ import annotations

from datetime import datetime, timezone

import requests


def query(domain: str) -> dict:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        if response.status_code == 404:
            return {"source": "rdap", "status": "not_found", "score_delta": 0, "evidence": "No RDAP data found"}
        response.raise_for_status()
        data = response.json()
        created = _created_date(data)
        age_days = None
        score_delta = 0
        if created:
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 7:
                score_delta = 35
            elif age_days < 30:
                score_delta = 25
            else:
                score_delta = -5
        registrar = _registrar(data)
        evidence = f"RDAP collected; registrar={registrar or 'unknown'}; age_days={age_days if age_days is not None else 'unknown'}"
        return {
            "source": "rdap",
            "status": "ok",
            "created": created.isoformat() if created else "",
            "registrar": registrar,
            "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            "events": data.get("events", []),
            "age_days": age_days,
            "score_delta": score_delta,
            "evidence": evidence,
        }
    except Exception as exc:
        return {"source": "rdap", "status": "error", "score_delta": 0, "evidence": str(exc)}


def _created_date(data: dict):
    for event in data.get("events", []):
        if event.get("eventAction") in {"registration", "created"} and event.get("eventDate"):
            raw = event["eventDate"].replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(raw)
            except ValueError:
                return None
    return None


def _registrar(data: dict) -> str:
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        return field[-1]
    return ""
