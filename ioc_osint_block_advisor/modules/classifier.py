from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

from . import context_signals
from .context_signals import Signal
from .fang import normalize_domain, normalize_url, refang
from .utils import (
    is_allowlisted,
    is_client_domain,
    is_client_sender,
    is_client_tenant,
    is_review_only,
    is_trusted_saas,
    load_client_allowlist,
    load_client_keywords,
    load_client_senders,
    load_review_only,
    load_suspicious_keywords,
    load_tenant_allowlist,
    load_trusted_saas,
)


_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# TLDs con abuso frecuente en campañas de phishing. Señal débil por sí sola.
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "icu", "click", "gq", "tk", "ml", "cf", "cam", "rest", "monster"}

# Plegado canónico para typosquatting: se aplica tanto a la marca como al
# dominio, de modo que 'flu1dra', 'fluidra' y 'fIuidra' colisionen.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "i", "l": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})


@dataclass
class ClassifiedIOC:
    original: str
    normalized: str
    defanged: str
    source: str
    ioc_type: str
    domain: str = ""
    root_domain: str = ""
    subdomain: str = ""
    path: str = ""
    role: str = "unknown"
    is_allowlisted: bool = False
    is_trusted_saas: bool = False
    # Capas de protección de cliente/organización (Fluidra)
    is_client_allowlisted: bool = False
    is_client_sender_flag: bool = False
    is_tenant: bool = False
    is_review_only_flag: bool = False
    protected_by: str = ""
    score: int = 0
    osint_results: list[dict] = field(default_factory=list)
    decision: str = ""
    recommended_action: str = ""
    reason: str = ""
    false_positive_risk: str = ""
    review_priority: str = ""
    risk_flags: list[str] = field(default_factory=list)
    # Modelo de evidencia detallado
    signals: list[Signal] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    positive_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)
    score_breakdown: list[str] = field(default_factory=list)
    analyst_reasoning: str = ""
    confidence: str = ""
    block_value: str = ""
    sources_used: list[str] = field(default_factory=list)
    why_blockable: str = ""
    why_not_blockable: str = ""
    soc_conclusion: str = ""
    # Enriquecimiento BBOT (opcional): nunca alimenta osint_results
    # directamente. Ver integrations/bbot/mapper.py.
    bbot_scan_id: str = ""
    bbot_status: str = ""
    bbot_events: list = field(default_factory=list)
    bbot_relationships: list = field(default_factory=list)
    related_assets: list = field(default_factory=list)
    technical_findings: list = field(default_factory=list)
    bbot_warnings: list = field(default_factory=list)
    bbot_score_delta: int = 0


def _root_parts(domain: str) -> tuple[str, str]:
    ext = _TLD_EXTRACT(domain)
    root = ".".join(part for part in (ext.domain, ext.suffix) if part)
    return root, ext.subdomain


def _type(value: str) -> str:
    v = refang(value)
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "hash_md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "hash_sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "hash_sha256"
    if re.fullmatch(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)", v):
        return "ip"
    if "@" in v and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        return "email"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return "url"
    return "domain"


def _build_base(extracted, allowlist: set[str] | None, trusted_saas: set[str] | None) -> ClassifiedIOC:
    value = refang(extracted.refanged)
    ioc_type = _type(value)
    domain = ""
    path = ""
    normalized = value.lower() if ioc_type.startswith("hash") else value

    if ioc_type == "url":
        normalized = normalize_url(value)
        parts = urlsplit(normalized)
        domain = normalize_domain(parts.netloc)
        path = parts.path or "/"
    elif ioc_type == "email":
        local, domain_part = value.rsplit("@", 1)
        domain = normalize_domain(domain_part)
        normalized = f"{local}@{domain}"
    elif ioc_type == "domain":
        domain = normalize_domain(value)
        normalized = domain

    root_domain, subdomain = _root_parts(domain) if domain else ("", "")
    allowlisted = bool(domain and is_allowlisted(domain, allowlist))
    trusted = bool(domain and is_trusted_saas(domain, trusted_saas))

    client_domains = load_client_allowlist()
    client_domain = bool(domain and is_client_domain(domain, client_domains))
    tenant = bool(domain and is_client_tenant(domain, load_tenant_allowlist()))
    client_sender = bool(
        ioc_type == "email" and is_client_sender(normalized, load_client_senders(), client_domains)
    )
    review_only = bool(domain and is_review_only(domain, load_review_only()))

    protected_by = ""
    if client_domain:
        protected_by = "client_allowlist"
    elif client_sender:
        protected_by = "client_sender_allowlist"
    elif tenant:
        protected_by = "client_tenant_allowlist"
    elif trusted:
        protected_by = "trusted_saas"
    elif allowlisted:
        protected_by = "allowlist"
    elif review_only:
        protected_by = "review_only"

    return ClassifiedIOC(
        original=extracted.original,
        normalized=normalized,
        defanged=extracted.defanged,
        source=extracted.source,
        ioc_type=ioc_type,
        domain=domain,
        root_domain=root_domain,
        subdomain=subdomain,
        path=path,
        is_allowlisted=allowlisted,
        is_trusted_saas=trusted,
        is_client_allowlisted=client_domain,
        is_client_sender_flag=client_sender,
        is_tenant=tenant,
        is_review_only_flag=review_only,
        protected_by=protected_by,
    )


def classify_many(extracted_iocs, context: str, allowlist: set[str] | None = None, trusted_saas: set[str] | None = None) -> list[ClassifiedIOC]:
    if trusted_saas is None:
        trusted_saas = load_trusted_saas()
    items = [_build_base(item, allowlist, trusted_saas) for item in extracted_iocs]
    # Análisis contextual conjunto: asocia señales frase a frase a cada IOC.
    context_signals.analyze_context(items, context or "")
    for item in items:
        item.role = _role_for(item, context or "")
        _score_item(item)
    return items


def classify_ioc(extracted, context: str, allowlist: set[str] | None = None, trusted_saas: set[str] | None = None) -> ClassifiedIOC:
    return classify_many([extracted], context, allowlist, trusted_saas)[0]


def _is_protected(item: ClassifiedIOC) -> bool:
    return bool(
        item.is_allowlisted
        or item.is_trusted_saas
        or item.is_client_allowlisted
        or item.is_client_sender_flag
        or item.is_tenant
    )


def _role_for(item: ClassifiedIOC, context: str) -> str:
    lower = f"{item.normalized} {item.path}".lower()
    context_lower = (context or "").lower()
    if any(word in lower for word in ("unsubscribe", "optout", "email-preferences")):
        return "unsubscribe"
    if item.ioc_type == "email":
        return "sender_observed"
    if item.ioc_type == "ip":
        return "ip_observed"
    if item.ioc_type.startswith("hash"):
        return "hash_observed"
    if item.ioc_type in {"url", "domain"}:
        if context_signals.implies_landing_final(item):
            # Un dominio/URL protegido nunca se etiqueta como landing final.
            if not _is_protected(item):
                return "landing_final"
        if item.ioc_type == "url":
            names = {s.name for s in context_signals.direct_strong_signals(item)}
            if any(word in context_lower for word in ("redirección inicial", "redireccion inicial", "initial redirect", "empieza en", "inicia una cadena")):
                if "final_redirect" not in names or _is_protected(item):
                    return "redirect_initial"
            if any(word in context_lower for word in ("redirección intermedia", "redireccion intermedia", "intermediate redirect")):
                return "redirect_intermediate"
            return "visible_url"
        return "domain_observed"
    return "unknown"


def _brand_impersonation_hit(item: ClassifiedIOC) -> str:
    """Detección léxica de lookalike/typosquatting sobre marcas protegidas.

    Si un dominio NO protegido contiene una keyword de cliente (p. ej.
    'fluidra'), incluso con sustituciones homógrafas (flu1dra, fluidr4),
    se considera suplantación de marca. Nunca aplica a dominios que
    realmente pertenecen al cliente.
    """
    if _is_protected(item) or not item.domain:
        return ""
    haystack = item.domain.lower().translate(_HOMOGLYPHS)
    for keyword in load_client_keywords():
        normalized_kw = keyword.lower().translate(_HOMOGLYPHS)
        if len(normalized_kw) >= 4 and normalized_kw in haystack:
            return keyword
    return ""


def _score_item(item: ClassifiedIOC) -> None:
    """Scoring explicable: cada delta queda registrado en score_breakdown."""
    score = 0
    breakdown: list[str] = []
    keywords = load_suspicious_keywords()
    value_text = f"{item.normalized} {item.path}".lower()

    strong = context_signals.strong_signals(item)
    caution = context_signals.caution_signals(item)
    protected = _is_protected(item)

    # --- Señales contextuales fuertes -------------------------------------
    weights = {s.name: s.weight for s in strong}
    if item.role == "landing_final" and "landing_final" not in weights:
        # landing derivado de redirección final + credenciales/suplantación
        weights["landing_final_derived"] = 40
        item.evidence.append("El IOC se comporta como landing final según el contexto (redirección final hacia portal que solicita credenciales o suplanta una marca).")
    for signal in strong:
        scope = "" if signal.direct else " (señal global del contexto, no ligada explícitamente a este IOC)"
        item.evidence.append(signal.evidence + scope)
        item.positive_signals.append(signal.name)
    for name, weight in weights.items():
        score += weight
        breakdown.append(f"+{weight} {name}")
        if name in {"recently_created_domain"}:
            item.risk_flags.append("new_domain")

    # --- Suplantación léxica de marca protegida ----------------------------
    brand = _brand_impersonation_hit(item)
    if brand and "lookalike_domain" not in weights:
        score += 35
        breakdown.append("+35 brand_impersonation")
        item.positive_signals.append("brand_impersonation")
        item.risk_flags.append("brand_lookalike")
        item.evidence.append(
            f"El dominio contiene la marca protegida '{brand}' sin pertenecer a la organización ni a su allowlist: posible typosquatting/lookalike para suplantación."
        )

    # --- Señales contextuales de cautela ----------------------------------
    for signal in caution:
        score += signal.weight
        breakdown.append(f"{signal.weight} {signal.name}")
        item.evidence.append("[cautela] " + signal.evidence)
        item.negative_signals.append(signal.name)

    # --- Capas de protección (allowlists) ----------------------------------
    if item.is_client_allowlisted or item.is_tenant:
        label = "client_allowlist_domain" if item.is_client_allowlisted else "client_tenant_domain"
        score -= 80
        breakdown.append(f"-80 {label}")
        item.negative_signals.append(label)
        origin = "allowlist de cliente" if item.is_client_allowlisted else "allowlist de tenants corporativos del cliente"
        item.evidence.append(f"[cautela] El dominio {item.domain} pertenece a la organización protegida o a un recurso corporativo suyo ({origin}).")
    if item.is_client_sender_flag:
        score -= 80
        breakdown.append("-80 client_allowlist_sender")
        item.negative_signals.append("client_allowlist_sender")
        item.evidence.append(f"[cautela] El remitente {item.normalized} figura como remitente legítimo protegido de la organización (client_allowlist_senders).")
    if item.is_trusted_saas and not (item.is_client_allowlisted or item.is_tenant):
        score -= 60
        breakdown.append("-60 trusted_saas_root_domain")
        item.negative_signals.append("trusted_saas_root_domain")
        item.evidence.append(f"[cautela] El dominio raíz {item.root_domain or item.domain} pertenece a una plataforma SaaS confiable (trusted_saas_domains).")
    if item.is_allowlisted and not (item.is_client_allowlisted or item.is_tenant):
        score -= 50
        breakdown.append("-50 allowlisted_domain")
        item.negative_signals.append("allowlisted_domain")
        item.evidence.append(f"[cautela] El dominio {item.domain} figura en la allowlist de dominios legítimos.")
    if item.ioc_type == "email" and protected:
        score -= 40
        breakdown.append("-40 legitimate_sender_domain")
        item.negative_signals.append("legitimate_sender_domain")
    if not protected and strong:
        score += 20
        breakdown.append("+20 not_in_allowlist")
        item.positive_signals.append("not_in_allowlist")
        item.evidence.append("El dominio no aparece en la allowlist de cliente, en allowlist general ni en trusted_saas_domains.")
    if item.role == "unsubscribe":
        score -= 60
        breakdown.append("-60 unsubscribe_link")
        item.negative_signals.append("unsubscribe_link")

    # --- Indicadores léxicos ------------------------------------------------
    tld = item.root_domain.rsplit(".", 1)[-1] if "." in (item.root_domain or "") else ""
    keyword_hit = "" if protected else next((k for k in keywords if k in value_text), "")
    if keyword_hit:
        score += 15
        breakdown.append("+15 suspicious_keyword")
        item.positive_signals.append("suspicious_keyword")
        item.evidence.append(f"El IOC contiene la palabra clave sospechosa '{keyword_hit}'.")
    if tld in SUSPICIOUS_TLDS:
        score += 10
        breakdown.append("+10 suspicious_tld")
        item.positive_signals.append("suspicious_tld")
        item.evidence.append(f"El TLD .{tld} presenta abuso frecuente en campañas de phishing.")
    if item.ioc_type == "url" and item.path and item.path != "/" and not protected:
        path_hit = next((k for k in keywords if k in item.path.lower()), "")
        if path_hit:
            score += 20
            breakdown.append("+20 suspicious_login_path")
            item.positive_signals.append("suspicious_login_path")
            item.evidence.append(f"La ruta de la URL contiene el patrón sospechoso '{path_hit}'.")

    # --- Ausencia de evidencia ----------------------------------------------
    if not strong and item.role in {"domain_observed", "visible_url", "ip_observed", "sender_observed"}:
        score -= 30
        breakdown.append("-30 only_observed")
        item.negative_signals.append("only_observed")
        item.evidence.append("[cautela] El IOC solo aparece como observado; el contexto no le atribuye comportamiento malicioso.")
    elif strong and not context_signals.direct_strong_signals(item):
        score -= 20
        breakdown.append("-20 insufficient_direct_evidence")
        item.negative_signals.append("insufficient_direct_evidence")
        item.evidence.append("[cautela] Las señales de maliciosidad proceden del contexto general y no están ligadas explícitamente a este IOC.")

    item.score = score
    item.score_breakdown = breakdown
