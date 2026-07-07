from __future__ import annotations

from . import context_signals
from .utils import is_allowlisted, is_trusted_saas


ACTIONS = {
    "BLOCK_DOMAIN": "Bloquear dominio completo",
    "BLOCK_URL_EXACT": "Bloquear URL exacta",
    "BLOCK_SENDER_EXACT": "Bloquear sender exacto",
    "BLOCK_HASH": "Bloquear hash",
    "DO_NOT_BLOCK": "No bloquear",
    "OBSERVED_ONLY": "Mantener como observado",
    "REVIEW": "Revisión manual",
}

# Umbrales de decisión (ver README). No se aplican solos: hay gating.
BLOCK_THRESHOLD = 90
REVIEW_HIGH_THRESHOLD = 60
REVIEW_THRESHOLD = 30
OBSERVED_THRESHOLD = 10

# Mapeo de status de módulos OSINT a veredictos normalizados.
_OSINT_VERDICTS = {
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


def osint_verdict(result: dict) -> str:
    return _OSINT_VERDICTS.get(str(result.get("status", "")).lower(), "unknown")


def apply_osint_score(item) -> None:
    if getattr(item, "_osint_score_applied", False):
        return
    if not item.osint_results:
        return
    for result in item.osint_results:
        try:
            delta = int(result.get("score_delta", 0))
        except (TypeError, ValueError):
            continue
        item.score += delta
        verdict = osint_verdict(result)
        if delta:
            getattr(item, "score_breakdown", []).append(
                f"{'+' if delta > 0 else ''}{delta} osint_{result.get('source', '?')}:{verdict}"
            )
        if verdict == "malicious" or delta >= 20:
            item.evidence.append(
                f"Fuente OSINT {result.get('source')} devuelve veredicto '{verdict}': {result.get('evidence', '')}".strip()
            )
            item.positive_signals.append(f"osint_{verdict}_hit" if verdict in {"malicious", "suspicious"} else "osint_positive")
    item._osint_score_applied = True


def has_osint_malicious_verdict(item) -> bool:
    return any(osint_verdict(r) == "malicious" for r in getattr(item, "osint_results", []) or [])


def gates(item) -> dict:
    """Reglas de gating explícitas: la decisión no depende solo del score."""
    direct_strong = context_signals.direct_strong_signals(item)
    return {
        "required_direct_malicious_signal": bool(direct_strong),
        "is_client_protected": bool(
            getattr(item, "is_client_allowlisted", False)
            or getattr(item, "is_client_sender_flag", False)
            or getattr(item, "is_tenant", False)
        ),
        "is_trusted_saas": bool(getattr(item, "is_trusted_saas", False)),
        "is_allowlisted": bool(getattr(item, "is_allowlisted", False)),
        "is_review_only": bool(getattr(item, "is_review_only_flag", False)),
        "is_sender": item.ioc_type == "email",
        "is_exact_url": item.ioc_type == "url",
        "is_landing_final": item.role == "landing_final",
        "has_osint_malicious_verdict": has_osint_malicious_verdict(item),
    }


def decide(item):
    apply_osint_score(item)
    _collect_sources(item)
    g = gates(item)

    if g["is_client_protected"]:
        return _decide_client_protected(item)
    if g["is_trusted_saas"] or g["is_allowlisted"] or (item.domain and (is_allowlisted(item.domain) or is_trusted_saas(item.domain))):
        return _decide_protected(item)

    if item.ioc_type.startswith("hash"):
        return _decide_hash(item)
    if item.ioc_type == "email":
        return _decide_sender(item, g)
    if item.ioc_type == "ip":
        return _decide_ip(item, g)
    if item.role == "unsubscribe":
        return _finalize(
            item, "DO_NOT_BLOCK", "Alto",
            why_not="Se trata de un enlace de baja/gestión de notificaciones. No debe considerarse IOC de bloqueo por sí solo.",
        )
    return _decide_domain_or_url(item, g)


def decide_many(items):
    return [decide(item) for item in items]


# ---------------------------------------------------------------------------
# Decisiones por tipo
# ---------------------------------------------------------------------------

def _decide_domain_or_url(item, g: dict):
    strong = context_signals.strong_signals(item)
    direct_strong = context_signals.direct_strong_signals(item)
    strong_names = {s.name for s in strong}

    # Gating de bloqueo: score alto Y >=2 señales fuertes Y >=1 directa,
    # o veredicto OSINT malicioso con al menos una señal fuerte directa.
    strong_enough = (
        item.score >= BLOCK_THRESHOLD
        and len(strong) >= 2
        and g["required_direct_malicious_signal"]
    ) or (
        g["has_osint_malicious_verdict"]
        and item.score >= REVIEW_HIGH_THRESHOLD
        and g["required_direct_malicious_signal"]
    )

    if g["is_review_only"] and strong_enough:
        return _finalize(
            item, "REVIEW", "Alto", priority="alta",
            why_not="El dominio figura en la allowlist review_only: nunca se bloquea automáticamente aunque la evidencia sea fuerte. Escalar a validación manual prioritaria.",
        )

    if strong_enough:
        if g["is_landing_final"] or item.ioc_type == "domain":
            item.block_value = item.domain or item.normalized
            return _finalize(
                item, "BLOCK_DOMAIN",
                _fp_risk_for_block(item),
                why="El contexto y las señales acumuladas identifican este dominio como infraestructura maliciosa controlada por el atacante (no como servicio legítimo abusado), por lo que el bloqueo de dominio completo es proporcionado.",
            )
        item.block_value = item.normalized
        return _finalize(
            item, "BLOCK_URL_EXACT",
            _fp_risk_for_block(item),
            why="La URL concreta acumula evidencia fuerte de participación en actividad maliciosa; se recomienda bloqueo quirúrgico de la URL exacta.",
        )

    if item.score >= REVIEW_HIGH_THRESHOLD:
        why_not = "Señales fuertes acumuladas pero por debajo del umbral de bloqueo automático"
        if strong and not direct_strong:
            why_not += " (las señales proceden del contexto general y no están ligadas explícitamente a este IOC)"
        return _finalize(item, "REVIEW", "Medio", priority="alta", why_not=why_not + ". Validación manual prioritaria.")

    if item.score >= REVIEW_THRESHOLD or strong:
        why_not = "Hay señales relevantes pero la evidencia no alcanza el umbral de bloqueo automático"
        if strong and not direct_strong:
            why_not += " (las señales de maliciosidad proceden del contexto general y no están ligadas explícitamente a este IOC)"
        if "recently_created_domain" in strong_names and len(strong) == 1:
            why_not = "Un dominio recientemente creado, sin otras señales de maliciosidad, no es evidencia suficiente para bloqueo automático"
        return _finalize(item, "REVIEW", "Medio", priority="media", why_not=why_not + ".")

    if item.score >= OBSERVED_THRESHOLD:
        return _finalize(
            item, "OBSERVED_ONLY", "Medio",
            why_not="El IOC presenta señales limitadas; no hay evidencia suficiente para recomendar bloqueo.",
        )
    return _finalize(
        item, "DO_NOT_BLOCK", "Bajo",
        why_not="No hay evidencia de maliciosidad asociada a este IOC. IOC observado no significa IOC bloqueable.",
    )


def _decide_sender(item, g: dict):
    strong = context_signals.strong_signals(item)
    direct_strong = context_signals.direct_strong_signals(item)
    direct_names = {s.name for s in direct_strong}
    explicit_sender_evidence = bool(direct_names & {"confirmed_abuse", "impersonation", "auth_failed", "malware_payload"})

    if item.score >= BLOCK_THRESHOLD and explicit_sender_evidence and (_has_strong_evidence(item) or g["has_osint_malicious_verdict"]):
        item.block_value = item.normalized
        return _finalize(
            item, "BLOCK_SENDER_EXACT", "Medio",
            why="El remitente cuenta con evidencia fuerte y explícita (abuso confirmado, spoofing, malware o fallo de autenticación) ligada directamente a la entrega maliciosa, confirmada además por OSINT.",
        )
    if item.score >= BLOCK_THRESHOLD and explicit_sender_evidence:
        return _finalize(
            item, "REVIEW", "Medio", priority="alta",
            why_not="Existen señales fuertes y directas contra el remitente, pero conviene confirmar con OSINT o cabeceras antes de bloquear el sender exacto. Revisión prioritaria.",
        )
    if strong or item.score >= REVIEW_THRESHOLD:
        return _finalize(
            item, "REVIEW", "Medio", priority="media",
            why_not="El remitente está relacionado con el correo observado, pero no hay evidencia fuerte (spoofing, abuso confirmado o campañas previas) que justifique bloqueo automático del sender.",
        )
    return _finalize(
        item, "REVIEW", "Medio", priority="media",
        why_not="Sender observado sin evidencia suficiente para bloqueo automático. Validar contenido, autenticación (SPF/DKIM/DMARC) y relación legítima antes de bloquear.",
    )


def _decide_ip(item, g: dict):
    caution_names = {s.name for s in context_signals.caution_signals(item)}
    strong = context_signals.strong_signals(item)
    if (item.score >= BLOCK_THRESHOLD and g["required_direct_malicious_signal"] and len(strong) >= 2) or g["has_osint_malicious_verdict"]:
        return _finalize(
            item, "REVIEW", "Medio", priority="alta",
            why_not="La IP acumula evidencia fuerte (contexto/OSINT) como origen malicioso, pero esta herramienta no exporta blocklist de IPs y el bloqueo de IPs debe validarse manualmente por el riesgo de infraestructura compartida. Revisión prioritaria.",
        )
    if "shared_cloud_infrastructure" in caution_names or "legitimate_infrastructure" in caution_names:
        return _finalize(
            item, "DO_NOT_BLOCK", "Alto",
            why_not="La IP pertenece a infraestructura legítima o compartida (correo/hosting/CDN). Bloquearla afectaría servicios legítimos.",
        )
    if strong or item.score >= REVIEW_THRESHOLD:
        return _finalize(item, "REVIEW", "Medio", priority="media", why_not="IP relacionada con la actividad observada; validar titularidad y reputación antes de cualquier bloqueo.")
    return _finalize(item, "OBSERVED_ONLY", "Medio", why_not="IP observada sin evidencia de abuso directo. No inventar reputación: validar con OSINT si es necesario.")


def _decide_hash(item):
    if item.score >= 70 or _has_source_hit(item, "malwarebazaar") or has_osint_malicious_verdict(item):
        item.block_value = item.normalized
        return _finalize(item, "BLOCK_HASH", "Bajo", why="Hash reportado por fuente OSINT o asociado a malware en el contexto.")
    return _finalize(item, "OBSERVED_ONLY", "Medio", why_not="Hash observado sin evidencia suficiente para bloqueo.")


def _decide_client_protected(item):
    """Allowlist fuerte de cliente (Fluidra): nunca BLOCK_DOMAIN ni BLOCK_SENDER_EXACT."""
    root = item.root_domain or item.domain
    if item.is_client_allowlisted:
        entity = f"El dominio {item.domain} pertenece a la organización protegida (allowlist de cliente/Fluidra)."
    elif item.is_tenant:
        entity = f"El recurso {item.domain} es un tenant corporativo legítimo de la organización protegida (allowlist de tenants, p. ej. SharePoint/OneDrive de Fluidra)."
    else:
        entity = f"El remitente {item.normalized} figura como remitente legítimo protegido de la organización (Fluidra/cliente)."

    direct_names = {s.name for s in context_signals.direct_strong_signals(item)}
    suspicious = direct_names & {"confirmed_abuse", "auth_failed", "malware_payload", "credential_theft"}
    if suspicious or has_osint_malicious_verdict(item):
        return _finalize(
            item, "REVIEW", "Alto", priority="alta",
            why_not=entity + " Sin embargo, el contexto u OSINT describen actividad sospechosa (posible spoofing, cuenta comprometida o recurso interno abusado). Nunca bloquear el dominio/remitente automáticamente: escalar para validación manual con el equipo correspondiente. Protegido por allowlist de cliente.",
        )
    return _finalize(
        item, "DO_NOT_BLOCK", "Alto",
        why_not=entity + " Bloquearlo afectaría servicios o comunicaciones corporativas legítimas. Protegido por allowlist de cliente: nunca BLOCK_DOMAIN ni BLOCK_SENDER_EXACT automático. Si existiera evidencia adicional sobre una URL exacta, revisarla de forma individual.",
    )


def _decide_protected(item):
    """Dominios en allowlist o trusted_saas: nunca BLOCK_DOMAIN."""
    root = item.root_domain or item.domain
    origin = "trusted_saas_domains" if item.is_trusted_saas else "allowlist"
    strong = context_signals.strong_signals(item)
    direct_strong = context_signals.direct_strong_signals(item)
    direct_names = {s.name for s in direct_strong}

    if item.role == "unsubscribe":
        return _finalize(
            item, "DO_NOT_BLOCK", "Alto",
            why_not=f"Enlace de baja asociado a infraestructura legítima ({root}). Bloquearlo tendría alto riesgo de falso positivo.",
        )

    if item.ioc_type == "email":
        if direct_names & {"confirmed_abuse", "auth_failed"}:
            return _finalize(
                item, "REVIEW", "Alto", priority="alta",
                why_not=f"El dominio remitente {root} es legítimo, pero el contexto sugiere posible spoofing o abuso. Validar cabeceras de autenticación antes de decidir; no bloquear el dominio.",
            )
        return _finalize(
            item, "DO_NOT_BLOCK", "Alto",
            why_not=f"Remitente asociado a infraestructura legítima ({root}), como notificaciones o eventos de plataforma. Bloquearlo afectaría comunicaciones legítimas.",
        )

    if item.ioc_type == "url":
        confirmed_abuse = "confirmed_abuse" in direct_names or _has_strong_evidence(item) or has_osint_malicious_verdict(item)
        if confirmed_abuse:
            item.block_value = item.normalized
            return _finalize(
                item, "BLOCK_URL_EXACT", "Medio",
                why=f"El dominio raíz {root} es una plataforma legítima ({origin}) y no debe bloquearse por completo, pero la URL exacta cuenta con abuso confirmado (contexto u OSINT). Se recomienda bloqueo quirúrgico de la URL exacta.",
            )
        priority = "alta" if strong else "media"
        return _finalize(
            item, "REVIEW", "Alto", priority=priority,
            why_not=f"La URL pertenece a infraestructura legítima ({root}, presente en {origin}). Bloquear el dominio completo tendría alto riesgo de falso positivo. Si se confirma que esta URL exacta participa en la cadena maliciosa (redirección o alojamiento de phishing), aplicar bloqueo quirúrgico de la URL exacta.",
        )

    extra = ""
    if strong:
        extra = " El contexto describe actividad maliciosa en la cadena, pero se apoya en esta plataforma legítima como infraestructura: el bloqueo debe dirigirse a la URL exacta o al destino final, no a este dominio."
    return _finalize(
        item, "OBSERVED_ONLY", "Alto",
        why_not=f"Infraestructura legítima observada ({root}, presente en {origin}). No se recomienda bloqueo de dominio completo por abuso puntual.{extra}",
    )


# ---------------------------------------------------------------------------
# Composición de motivo, confianza y salida
# ---------------------------------------------------------------------------

def _finalize(item, decision: str, false_positive_risk: str, why: str = "", why_not: str = "", priority: str = ""):
    item.decision = decision
    item.recommended_action = ACTIONS[decision]
    item.false_positive_risk = false_positive_risk
    item.review_priority = priority if decision == "REVIEW" else ""
    item.why_blockable = why
    item.why_not_blockable = why_not
    item.confidence = _confidence(item)
    if decision.startswith("BLOCK") and not item.block_value:
        item.block_value = item.domain if decision == "BLOCK_DOMAIN" else item.normalized
    if not decision.startswith("BLOCK"):
        item.block_value = ""
    item.reason = _compose_reason(item, why or why_not)
    item.soc_conclusion = _compose_soc_conclusion(item)
    item.analyst_reasoning = _compose_analyst_reasoning(item)
    return item


def _compose_reason(item, headline: str) -> str:
    parts = [headline.strip()] if headline else []
    evidence = [e for e in getattr(item, "evidence", []) if e]
    if evidence:
        parts.append("Evidencias: " + " ".join(f"({i}) {e}" for i, e in enumerate(evidence, 1)))
    return " ".join(parts) if parts else "Sin evidencia registrada."


def _compose_soc_conclusion(item) -> str:
    """Conclusión SOC clara y accionable para ticket/Jira."""
    protected = getattr(item, "protected_by", "")
    role_desc = {
        "landing_final": "destino final de la cadena de redirección",
        "redirect_initial": "redirección inicial de la cadena",
        "redirect_intermediate": "redirección intermedia de la cadena",
        "visible_url": "URL visible en el correo/cadena",
        "sender_observed": "remitente observado",
        "domain_observed": "dominio observado",
        "ip_observed": "IP observada",
        "hash_observed": "hash observado",
        "unsubscribe": "enlace de baja/notificación",
    }.get(item.role, item.role)

    positives = [s.name for s in context_signals.strong_signals(item)]
    fragments = [f"El IOC actúa como {role_desc}."]
    if positives:
        fragments.append("Señales de maliciosidad detectadas: " + ", ".join(sorted(set(positives))) + ".")
    if protected in {"client_allowlist", "client_sender_allowlist", "client_tenant_allowlist"}:
        fragments.append("Pertenece a la organización protegida (Fluidra/cliente) o a un recurso corporativo suyo; bloquearlo afectaría servicios legítimos.")
    elif protected == "trusted_saas":
        fragments.append("El dominio raíz pertenece a un proveedor SaaS confiable configurado; el dominio completo no debe bloquearse.")
    elif protected == "allowlist":
        fragments.append("El dominio figura en la allowlist técnica general.")
    elif protected == "review_only":
        fragments.append("El dominio está marcado como review_only: nunca bloqueo automático.")
    else:
        fragments.append("No pertenece a Fluidra/cliente protegido, ni a un proveedor SaaS confiable configurado, ni figura en allowlist.")
    fragments.append(
        f"Se recomienda {item.decision} (confianza {item.confidence}, riesgo de falso positivo {item.false_positive_risk.lower()}"
        + (f", prioridad de revisión {item.review_priority}" if getattr(item, "review_priority", "") else "")
        + ")."
    )
    return " ".join(fragments)


def _compose_analyst_reasoning(item) -> str:
    lines = [
        f"Decisión {item.decision} con confianza {item.confidence.lower()} (score {item.score}).",
    ]
    if getattr(item, "score_breakdown", None):
        lines.append("Desglose de score: " + ", ".join(item.score_breakdown) + ".")
    g = gates(item)
    active = ", ".join(name for name, value in g.items() if value) or "ninguna"
    lines.append(f"Gates activos: {active}.")
    if item.why_blockable:
        lines.append(f"Por qué es bloqueable: {item.why_blockable}")
    if item.why_not_blockable:
        lines.append(f"Por qué no bloquear (o no bloquear más): {item.why_not_blockable}")
    if not getattr(item, "osint_results", None):
        lines.append("OSINT externo no consultado: análisis basado únicamente en contexto, reglas locales y configuración.")
    lines.append("Recordatorio: IOC observado no significa IOC bloqueable. La recomendación debe validarse antes de aplicar bloqueo.")
    return "\n".join(lines)


def _confidence(item) -> str:
    strong = context_signals.strong_signals(item)
    direct = context_signals.direct_strong_signals(item)
    if len(direct) >= 3 or (len(direct) >= 2 and abs(item.score) >= 90):
        return "Alta"
    if len(strong) >= 2 or abs(item.score) >= 60:
        return "Media"
    return "Baja"


def _fp_risk_for_block(item) -> str:
    direct = context_signals.direct_strong_signals(item)
    names = {s.name for s in direct}
    if len(direct) >= 3 and names & {"landing_final", "credential_theft"}:
        return "Bajo"
    return "Medio-Bajo"


def _collect_sources(item) -> None:
    sources = ["local_rules", "context_analysis"]
    results = getattr(item, "osint_results", []) or []
    if not results:
        sources.append("osint_externo:no_consultado")
    for result in results:
        source = result.get("source")
        if source:
            tagged = f"{source}:{osint_verdict(result)}"
            if tagged not in sources:
                sources.append(tagged)
    item.sources_used = sources


def _has_source_hit(item, source: str) -> bool:
    return any(result.get("source") == source and result.get("status") in {"hit", "malicious"} for result in item.osint_results)


def _has_strong_evidence(item) -> bool:
    for result in item.osint_results:
        try:
            if int(result.get("score_delta", 0) or 0) >= 50:
                return True
        except (TypeError, ValueError):
            continue
    return False
