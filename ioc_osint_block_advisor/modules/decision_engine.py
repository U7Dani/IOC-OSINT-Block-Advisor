from __future__ import annotations

from .utils import is_allowlisted


ACTIONS = {
    "BLOCK_DOMAIN": "Bloquear dominio completo",
    "BLOCK_URL_EXACT": "Bloquear URL exacta",
    "BLOCK_SENDER_EXACT": "Bloquear sender exacto",
    "BLOCK_HASH": "Bloquear hash",
    "DO_NOT_BLOCK": "No bloquear",
    "OBSERVED_ONLY": "Mantener como observado",
    "REVIEW": "Revisión manual",
}


def apply_osint_score(item) -> None:
    if getattr(item, "_osint_score_applied", False):
        return
    if not item.osint_results:
        return
    for result in item.osint_results:
        try:
            item.score += int(result.get("score_delta", 0))
        except (TypeError, ValueError):
            continue
    item._osint_score_applied = True


def decide(item):
    apply_osint_score(item)

    if item.is_allowlisted or (item.domain and is_allowlisted(item.domain)):
        return _decide_allowlisted(item)

    if item.ioc_type.startswith("hash"):
        if item.score >= 70 or _has_source_hit(item, "malwarebazaar"):
            return _set(item, "BLOCK_HASH", "Hash reportado por fuente OSINT o asociado a malware.", "Bajo")
        return _set(item, "OBSERVED_ONLY", "Hash observado sin evidencia suficiente para bloqueo.", "Medio")

    if item.ioc_type == "email":
        if item.score >= 80 and _has_strong_evidence(item):
            return _set(item, "BLOCK_SENDER_EXACT", "Sender con evidencia fuerte asociada a actividad maliciosa.", "Medio")
        return _set(
            item,
            "REVIEW",
            "Sender observado sin evidencia suficiente para bloqueo automático. Validar contenido, autenticación y relación legítima antes de bloquear.",
            "Medio",
        )

    if item.role == "unsubscribe":
        return _set(
            item,
            "DO_NOT_BLOCK",
            "Enlace de baja/notificación. No debe considerarse IOC de bloqueo por sí solo.",
            "Alto",
        )

    if item.role == "landing_final" and item.score >= 70:
        return _set(
            item,
            "BLOCK_DOMAIN",
            "Dominio final asociado a phishing/suplantación, portal de login fraudulento y señales suficientes como dominio reciente o no relacionado con un proveedor legítimo.",
            "Bajo",
        )

    if item.ioc_type == "url" and item.score >= 80:
        return _set(item, "BLOCK_URL_EXACT", "URL con evidencia fuerte de actividad maliciosa.", "Bajo")

    if item.ioc_type == "domain" and item.score >= 80:
        return _set(item, "BLOCK_DOMAIN", "Dominio con evidencia fuerte de actividad maliciosa.", "Bajo")

    if 50 <= item.score < 80:
        if item.ioc_type == "url":
            return _set(item, "REVIEW", "Señales relevantes detectadas; validar antes de aplicar bloqueo exacto.", "Medio")
        return _set(item, "REVIEW", "Señales relevantes detectadas; requiere validación manual.", "Medio")

    if "new_domain" in getattr(item, "risk_flags", []) and item.score < 80:
        return _set(item, "REVIEW", "Dominio reciente detectado, pero un dominio nuevo no es evidencia suficiente para bloqueo automático.", "Medio")

    if 20 <= item.score < 50:
        return _set(item, "OBSERVED_ONLY", "IOC observado con señales limitadas. No hay evidencia suficiente para bloqueo.", "Medio")

    return _set(item, "DO_NOT_BLOCK", "IOC observado sin evidencia suficiente de bloqueo. IOC observado no significa IOC bloqueable.", "Bajo")


def decide_many(items):
    return [decide(item) for item in items]


def _decide_allowlisted(item):
    if item.role == "unsubscribe":
        return _set(
            item,
            "DO_NOT_BLOCK",
            "Enlace de baja asociado a infraestructura legítima. Bloquearlo tendría alto riesgo de falso positivo.",
            "Alto",
        )
    if item.ioc_type == "email":
        provider = f" ({item.domain})" if item.domain else ""
        return _set(
            item,
            "DO_NOT_BLOCK",
            f"Remitente asociado a infraestructura legítima{provider}, como notificaciones o eventos. Bloquearlo podría afectar comunicaciones legítimas.",
            "Alto",
        )
    if item.ioc_type == "url":
        decision = "BLOCK_URL_EXACT" if _has_strong_evidence(item) else "REVIEW"
        return _set(
            item,
            decision,
            "URL perteneciente a infraestructura legítima. No se recomienda bloquear dominio completo. Si se confirma redirección maliciosa, aplicar bloqueo quirúrgico de URL exacta.",
            "Alto",
        )
    return _set(
        item,
        "OBSERVED_ONLY",
        "Infraestructura legítima observada. No se recomienda bloqueo de dominio completo.",
        "Alto",
    )


def _set(item, decision: str, reason: str, false_positive_risk: str):
    item.decision = decision
    item.recommended_action = ACTIONS[decision]
    item.reason = reason
    item.false_positive_risk = false_positive_risk
    return item


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
