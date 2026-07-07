from __future__ import annotations

from . import osint_crtsh, osint_dns, osint_malwarebazaar, osint_otx, osint_phishtank, osint_rdap, osint_threatfox, osint_urlhaus, osint_urlscan


def collect(item, include_url_lookups: bool = False) -> list[dict]:
    """Consulta las fuentes OSINT implementadas para un IOC.

    Privacidad:
    - Solo se ejecuta si el usuario activa OSINT externo (deshabilitado por defecto).
    - Por defecto NO se envían URLs completas a terceros: las fuentes que
      requieren la URL exacta (phishtank, urlscan por URL, urlhaus por URL)
      se consultan por dominio o se marcan como not_checked, salvo que el
      usuario active explícitamente `include_url_lookups`.
    """
    results: list[dict] = []
    if item.domain:
        results.append(_safe_query("dns", osint_dns.query, item.domain))
        results.append(_safe_query("rdap", osint_rdap.query, item.root_domain or item.domain))
        results.append(_safe_query("crtsh", osint_crtsh.query, item.root_domain or item.domain))
    if item.ioc_type in {"url", "domain"}:
        if item.ioc_type == "url" and not include_url_lookups:
            # Preferir consulta por host: no exponer la URL completa.
            results.append(_safe_query("urlhaus", osint_urlhaus.query, item.domain, "domain"))
        else:
            lookup_value = item.normalized if item.ioc_type == "url" else item.domain
            results.append(_safe_query("urlhaus", osint_urlhaus.query, lookup_value, item.ioc_type))
    if item.ioc_type == "url":
        if include_url_lookups:
            results.append(_safe_query("phishtank", osint_phishtank.query, item.normalized))
            results.append(_safe_query("urlscan", osint_urlscan.query, item.normalized))
        else:
            note = "Consulta por URL completa deshabilitada para proteger la privacidad del IOC (activar 'incluir URL completa' si se necesita)."
            results.append({"source": "phishtank", "status": "not_checked", "score_delta": 0, "evidence": note})
            results.append({"source": "urlscan", "status": "not_checked", "score_delta": 0, "evidence": note})
    if item.ioc_type in {"ip", "domain", "url"} or item.ioc_type.startswith("hash"):
        lookup = item.domain if item.ioc_type == "url" and not include_url_lookups else item.normalized
        results.append(_safe_query("threatfox", osint_threatfox.query, lookup))
        results.append(_safe_query("otx", osint_otx.query, lookup, _otx_type("domain" if item.ioc_type == "url" and not include_url_lookups else item.ioc_type)))
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
