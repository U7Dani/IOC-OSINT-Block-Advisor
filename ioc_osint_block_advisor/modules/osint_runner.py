from __future__ import annotations

from . import osint_crtsh, osint_dns, osint_malwarebazaar, osint_otx, osint_phishtank, osint_rdap, osint_threatfox, osint_urlhaus, osint_urlscan


def collect(item) -> list[dict]:
    results: list[dict] = []
    if item.domain:
        results.append(_safe_query("dns", osint_dns.query, item.domain))
        results.append(_safe_query("rdap", osint_rdap.query, item.root_domain or item.domain))
        results.append(_safe_query("crtsh", osint_crtsh.query, item.root_domain or item.domain))
    if item.ioc_type in {"url", "domain"}:
        lookup_value = item.normalized if item.ioc_type == "url" else item.domain
        results.append(_safe_query("urlhaus", osint_urlhaus.query, lookup_value, item.ioc_type))
    if item.ioc_type == "url":
        results.append(_safe_query("phishtank", osint_phishtank.query, item.normalized))
        results.append(_safe_query("urlscan", osint_urlscan.query, item.normalized))
    if item.ioc_type in {"ip", "domain", "url"} or item.ioc_type.startswith("hash"):
        results.append(_safe_query("threatfox", osint_threatfox.query, item.normalized))
        results.append(_safe_query("otx", osint_otx.query, item.normalized, _otx_type(item.ioc_type)))
    if item.ioc_type.startswith("hash"):
        results.append(_safe_query("malwarebazaar", osint_malwarebazaar.query, item.normalized))
    item.osint_results = results
    return results


def _otx_type(ioc_type: str) -> str:
    if ioc_type.startswith("hash"):
        return "hash"
    return ioc_type


def _safe_query(source: str, func, *args) -> dict:
    try:
        result = func(*args)
        if not isinstance(result, dict):
            return {"source": source, "status": "error", "score_delta": 0, "evidence": "OSINT module returned non-dict result"}
        result.setdefault("source", source)
        result.setdefault("status", "ok")
        result.setdefault("score_delta", 0)
        result.setdefault("evidence", "")
        return result
    except Exception as exc:
        return {"source": source, "status": "error", "score_delta": 0, "evidence": str(exc)}
