from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

from . import context_signals
from .context_signals import Signal
from .fang import normalize_domain, normalize_url, refang
from .utils import is_allowlisted, is_trusted_saas, load_suspicious_keywords, load_trusted_saas


_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# TLDs con abuso frecuente en campañas de phishing. Señal débil por sí sola.
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "icu", "click", "gq", "tk", "ml", "cf", "cam", "rest", "monster"}


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
    score: int = 0
    osint_results: list[dict] = field(default_factory=list)
    decision: str = ""
    recommended_action: str = ""
    reason: str = ""
    false_positive_risk: str = ""
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
            if not (item.is_allowlisted or item.is_trusted_saas):
                return "landing_final"
        if item.ioc_type == "url":
            names = {s.name for s in context_signals.direct_strong_signals(item)}
            if any(word in context_lower for word in ("redirección inicial", "redireccion inicial", "initial redirect", "empieza en", "inicia una cadena")):
                if "final_redirect" not in names or item.is_trusted_saas or item.is_allowlisted:
                    return "redirect_initial"
            if any(word in context_lower for word in ("redirección intermedia", "redireccion intermedia", "intermediate redirect")):
                return "redirect_intermediate"
            return "visible_url"
        return "domain_observed"
    return "unknown"


def _score_item(item: ClassifiedIOC) -> None:
    """Scoring explicable: cada delta queda registrado en score_breakdown."""
    score = 0
    breakdown: list[str] = []
    keywords = load_suspicious_keywords()
    value_text = f"{item.normalized} {item.path}".lower()

    strong = context_signals.strong_signals(item)
    caution = context_signals.caution_signals(item)

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

    # --- Señales contextuales de cautela ----------------------------------
    for signal in caution:
        score += signal.weight
        breakdown.append(f"{signal.weight} {signal.name}")
        item.evidence.append(signal.evidence)
        item.negative_signals.append(signal.name)

    # --- Señales intrínsecas del propio IOC --------------------------------
    if item.is_trusted_saas:
        score -= 50
        breakdown.append("-50 trusted_saas_root_domain")
        item.negative_signals.append("trusted_saas_root_domain")
        item.evidence.append(f"El dominio raíz {item.root_domain or item.domain} pertenece a una plataforma SaaS confiable (trusted_saas_domains).")
    if item.is_allowlisted:
        score -= 40
        breakdown.append("-40 allowlisted_domain")
        item.negative_signals.append("allowlisted_domain")
        item.evidence.append(f"El dominio {item.domain} figura en la allowlist de dominios legítimos.")
    if item.ioc_type == "email" and (item.is_allowlisted or item.is_trusted_saas):
        score -= 30
        breakdown.append("-30 legitimate_sender_domain")
        item.negative_signals.append("legitimate_sender_domain")
    if not (item.is_allowlisted or item.is_trusted_saas):
        if strong:
            score += 20
            breakdown.append("+20 not_in_allowlist")
            item.positive_signals.append("not_in_allowlist")
            item.evidence.append("El dominio no aparece en allowlist ni en trusted_saas_domains.")
    if item.role == "unsubscribe":
        score -= 60
        breakdown.append("-60 unsubscribe_link")
        item.negative_signals.append("unsubscribe_link")

    tld = item.root_domain.rsplit(".", 1)[-1] if "." in (item.root_domain or "") else ""
    keyword_hit = next((k for k in keywords if k in value_text), "")
    if tld in SUSPICIOUS_TLDS or keyword_hit:
        score += 15
        detail = f"TLD .{tld}" if tld in SUSPICIOUS_TLDS else f"palabra clave '{keyword_hit}' en el IOC"
        breakdown.append("+15 suspicious_tld_or_keyword")
        item.positive_signals.append("suspicious_tld_or_keyword")
        item.evidence.append(f"El IOC contiene un indicador léxico sospechoso ({detail}).")
    if item.ioc_type == "url" and item.path and item.path != "/":
        path_hit = next((k for k in keywords if k in item.path.lower()), "")
        if path_hit:
            score += 10
            breakdown.append("+10 suspicious_path")
            item.positive_signals.append("suspicious_path")

    if not strong and item.role in {"domain_observed", "visible_url", "ip_observed", "sender_observed"}:
        score -= 20
        breakdown.append("-20 only_observed")
        item.negative_signals.append("only_observed")
        item.evidence.append("El IOC solo aparece como observado; el contexto no le atribuye comportamiento malicioso.")

    item.score = score
    item.score_breakdown = breakdown
