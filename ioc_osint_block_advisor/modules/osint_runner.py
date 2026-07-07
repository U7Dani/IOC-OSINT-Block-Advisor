from __future__ import annotations

from . import (
    osint_abuseipdb,
    osint_crtsh,
    osint_dns,
    osint_malwarebazaar,
    osint_otx,
    osint_phishtank,
    osint_rdap,
    osint_threatfox,
    osint_urlhaus,
    osint_urlscan,
    osint_virustotal,
)

# Verdicts normalizados que puede devolver cualquier proveedor.
VERDICTS = ("malicious", "suspicious", "clean", "unknown", "not_checked", "error")

_STATUS_TO_VERDICT = {
    "hit": "malicious",
    "malicious": "malicious",
    "suspicious": "suspicious",
    "ok": "unknown",
    "clean": "clean",
    "not_found": "clean",
    "skipped": "not_checked",
    "not_checked": "not_checked",
    "error": "error",
}


def collect(item, include_url_lookups: bool = False) -> list[dict]:
    """Consulta las fuentes OSINT implementadas para un IOC.

    Arquitectura multi-proveedor: cada proveedor devuelve un resultado con
    el esquema legado (source/status/score_delta/evidence), que aquí se
    envuelve además en el esquema estructurado solicitado (provider,
    checked, artifact_type, verdict, confidence, details, error) sin
    romper a los consumidores existentes.

    Privacidad:
    - Solo se ejecuta si el usuario activa OSINT externo (deshabilitado
      por defecto).
    - Por defecto NO se envían URLs completas a terceros: las fuentes que
      requieren la URL exacta (phishtank, urlscan, virustotal por URL)
      se consultan por dominio o se marcan como not_checked, salvo que el
      usuario active explícitamente `include_url_lookups`.
    - Si una fuente no tiene API key configurada, se marca "skipped" /
      "no configurado": nunca se inventa un veredicto.
    """
    results: list[dict] = []
    domain_target = item.root_domain or item.domain

    if item.domain:
        results.append(_wrap(_safe_query("dns", osint_dns.query, item.domain), "domain"))
        results.append(_wrap(_safe_query("rdap", osint_rdap.query, domain_target), "domain"))
        results.append(_wrap(_safe_query("crtsh", osint_crtsh.query, domain_target), "domain"))

    if item.ioc_type in {"url", "domain"}:
        if item.ioc_type == "url" and not include_url_lookups:
            # Preferir consulta por host: no exponer la URL completa.
            results.append(_wrap(_safe_query("urlhaus", osint_urlhaus.query, item.domain, "domain"), "domain"))
        else:
            lookup_value = item.normalized if item.ioc_type == "url" else item.domain
            results.append(_wrap(_safe_query("urlhaus", osint_urlhaus.query, lookup_value, item.ioc_type), item.ioc_type))

    if item.ioc_type == "url":
        if include_url_lookups:
            results.append(_wrap(_safe_query("phishtank", osint_phishtank.query, item.normalized), "url"))
            results.append(_wrap(_safe_query("urlscan", osint_urlscan.query, item.normalized), "url"))
            results.append(_wrap(_safe_query("virustotal", osint_virustotal.query, item.normalized, "url"), "url"))
        else:
            note = "Consulta por URL completa deshabilitada para proteger la privacidad del IOC (activar 'incluir URL completa' si se necesita)."
            for source in ("phishtank", "urlscan", "virustotal"):
                results.append(_wrap({"source": source, "status": "not_checked", "score_delta": 0, "evidence": note}, "url"))

    if item.ioc_type in {"ip", "domain", "url"} or item.ioc_type.startswith("hash"):
        lookup = domain_target if item.ioc_type == "url" and not include_url_lookups else item.normalized
        lookup_type = "domain" if item.ioc_type == "url" and not include_url_lookups else item.ioc_type
        results.append(_wrap(_safe_query("threatfox", osint_threatfox.query, lookup), lookup_type))
        results.append(_wrap(_safe_query("otx", osint_otx.query, lookup, _otx_type(lookup_type)), lookup_type))
        if item.ioc_type in {"domain", "hash"} or (item.ioc_type == "ip"):
            vt_value = domain_target if item.ioc_type in {"url", "domain"} else item.normalized
            vt_type = "domain" if item.ioc_type in {"url", "domain"} else item.ioc_type
            results.append(_wrap(_safe_query("virustotal", osint_virustotal.query, vt_value, vt_type), vt_type))

    if item.ioc_type == "ip":
        results.append(_wrap(_safe_query("abuseipdb", osint_abuseipdb.query, item.normalized), "ip"))

    if item.ioc_type.startswith("hash"):
        results.append(_wrap(_safe_query("malwarebazaar", osint_malwarebazaar.query, item.normalized), "hash"))
        results.append(_wrap(_safe_query("virustotal", osint_virustotal.query, item.normalized, "hash"), "hash"))

    # correo: sin fuente OSINT directa implementada, se deja preparado y
    # explícito en vez de inventar un veredicto.
    if item.ioc_type == "email":
        results.append(
            _wrap(
                {
                    "source": "email_reputation",
                    "status": "skipped",
                    "score_delta": 0,
                    "evidence": "No hay proveedor de reputación de correo integrado; validar mediante SPF/DKIM/DMARC y contexto.",
                },
                "email",
            )
        )

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
            return {"source": source, "status": "error", "score_delta": 0, "evidence": "El módulo OSINT devolvió un resultado no válido"}
        result.setdefault("source", source)
        result.setdefault("status", "ok")
        result.setdefault("score_delta", 0)
        result.setdefault("evidence", "")
        return result
    except Exception as exc:
        return {"source": source, "status": "error", "score_delta": 0, "evidence": str(exc)}


def _wrap(result: dict, artifact_type: str) -> dict:
    """Añade el esquema estructurado sin romper los campos legados."""
    status = result.get("status", "unknown")
    verdict = _STATUS_TO_VERDICT.get(status, "unknown")
    result["provider"] = result.get("source", "")
    result["checked"] = status not in {"skipped", "not_checked"}
    result["artifact_type"] = artifact_type
    result["verdict"] = verdict
    result["confidence"] = _confidence_for(result, verdict)
    result["details"] = result.get("evidence", "")
    result["error"] = result.get("evidence", "") if status == "error" else ""
    return result


def _confidence_for(result: dict, verdict: str) -> str:
    if verdict in {"not_checked", "unknown"}:
        return "n/a"
    try:
        delta = abs(int(result.get("score_delta", 0)))
    except (TypeError, ValueError):
        delta = 0
    if delta >= 40:
        return "alta"
    if delta >= 15:
        return "media"
    return "baja"
