from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import tldextract

from .fang import normalize_domain, normalize_url, refang
from .utils import is_allowlisted, load_suspicious_keywords


_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


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
    score: int = 0
    osint_results: list[dict] = field(default_factory=list)
    decision: str = ""
    recommended_action: str = ""
    reason: str = ""
    false_positive_risk: str = ""
    risk_flags: list[str] = field(default_factory=list)


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


def classify_ioc(extracted, context: str, allowlist: set[str] | None = None) -> ClassifiedIOC:
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
    role = _role_for(ioc_type, normalized, path, context, allowlisted)

    classified = ClassifiedIOC(
        original=extracted.original,
        normalized=normalized,
        defanged=extracted.defanged,
        source=extracted.source,
        ioc_type=ioc_type,
        domain=domain,
        root_domain=root_domain,
        subdomain=subdomain,
        path=path,
        role=role,
        is_allowlisted=allowlisted,
    )
    classified.score = _initial_score(classified, context)
    return classified


def classify_many(extracted_iocs, context: str, allowlist: set[str] | None = None) -> list[ClassifiedIOC]:
    return [classify_ioc(item, context, allowlist) for item in extracted_iocs]


def _role_for(ioc_type: str, normalized: str, path: str, context: str, allowlisted: bool) -> str:
    lower = f"{normalized} {path}".lower()
    context_lower = (context or "").lower()
    if any(word in lower for word in ("unsubscribe", "optout", "email-preferences")):
        return "unsubscribe"
    if ioc_type == "email":
        return "sender_observed"
    if ioc_type == "url":
        if any(word in context_lower for word in ("redirección inicial", "redireccion inicial", "initial redirect")):
            return "redirect_initial"
        if any(word in context_lower for word in ("redirección intermedia", "redireccion intermedia", "intermediate redirect")):
            return "redirect_intermediate"
        if any(word in context_lower for word in ("redirección final", "redireccion final", "landing", "portal de login", "credenciales")):
            return "landing_final" if not allowlisted else "visible_url"
        return "visible_url"
    if ioc_type == "domain":
        return "domain_observed"
    if ioc_type == "ip":
        return "ip_observed"
    if ioc_type.startswith("hash"):
        return "hash_observed"
    return "unknown"


def _initial_score(item: ClassifiedIOC, context: str) -> int:
    score = 0
    text = f"{context} {item.normalized} {item.path}".lower()
    keywords = load_suspicious_keywords()
    if item.is_allowlisted:
        score -= 70 if item.ioc_type == "email" else 60
    if item.role == "unsubscribe":
        score -= 60
    if item.role == "landing_final":
        score += 40
    age_score = _domain_age_score(text)
    if age_score:
        score += age_score
        item.risk_flags.append("new_domain")
    if "credenciales" in text or "credentials" in text or "portal de login" in text:
        score += 20
    if "suplanta" in text or "impersona" in text or "phishing" in text:
        score += 30
    if any(keyword in text for keyword in keywords):
        score += 10
    if any(phrase in text for phrase in ("sin interacción", "sin interaccion", "no user interaction")):
        score -= 10
    if item.is_allowlisted and item.ioc_type == "url":
        score -= 10
    return score


def _domain_age_score(text: str) -> int:
    match = re.search(r"(?:dominio\s+)?(?:fue\s+)?cread[oa]\s+hace\s+(\d+)\s+d[ií]as", text, re.I)
    if not match:
        return 0
    days = int(match.group(1))
    if days < 7:
        return 35
    if days < 30:
        return 25
    return -5
