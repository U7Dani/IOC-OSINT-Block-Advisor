from __future__ import annotations

"""Análisis contextual por IOC.

Lee el texto de investigación aportado por el analista, lo divide en
frases, y asocia señales fuertes (evidencia de maliciosidad) y señales
de cautela (evidencia de legitimidad) a cada IOC concreto.

Reglas clave:
- Una señal es "directa" si aparece en una frase que menciona el IOC
  (o su dominio/raíz). Solo las señales fuertes directas habilitan
  decisiones BLOCK_*.
- Las frases que no mencionan ningún IOC generan señales "globales",
  que suman score pero no habilitan bloqueo por sí solas, salvo que
  toda la investigación gire en torno a una única infraestructura
  sospechosa (un solo dominio raíz no protegido).
"""

import re
from dataclasses import dataclass, field

from .fang import refang


@dataclass
class Signal:
    name: str
    kind: str          # "strong" | "caution"
    weight: int
    direct: bool       # la frase menciona explícitamente el IOC
    evidence: str      # descripción legible para el analista
    sentence: str = ""


# ---------------------------------------------------------------------------
# Patrones de señales fuertes (elevan la recomendación de bloqueo)
# ---------------------------------------------------------------------------

STRONG_PATTERNS: tuple[tuple[str, int, tuple[str, ...], str], ...] = (
    (
        "landing_final",
        40,
        (
            r"landing\s+final",
            r"landing\s+(?:page\s+)?de\s+phishing",
            r"p[aá]gina\s+final",
            r"destino\s+final",
            r"final\s+landing",
            r"phishing\s+landing",
        ),
        "El IOC aparece descrito como landing final en el contexto.",
    ),
    (
        "final_redirect",
        20,
        (
            r"redirecci[oó]n\s+final",
            r"final\s+redirect",
            r"redirige\s+finalmente",
            r"dirige\s+finalmente",
            r"termina\s+en",
            r"finaliza\s+en",
            r"posteriormente\s+dirige\s+a",
            r"redirecci[oó]n\s+.{0,40}termina",
        ),
        "El contexto identifica el IOC como destino de la redirección final.",
    ),
    (
        "credential_theft",
        35,
        (
            r"solicita\s+credenciales",
            r"solicitud\s+de\s+credenciales",
            r"captura(?:r)?\s+(?:de\s+)?credenciales",
            r"robo\s+de\s+credenciales",
            r"pide\s+credenciales",
            r"credential\s+harvesting",
            r"credential\s+theft",
            r"harvesting\s+de\s+credenciales",
            r"recolecci[oó]n\s+de\s+credenciales",
        ),
        "El contexto indica solicitud o captura de credenciales.",
    ),
    (
        "impersonation",
        30,
        (
            r"suplanta(?:ci[oó]n|ndo|r)?",
            r"impersona(?:tion|ting)?",
            r"se\s+hace\s+pasar\s+por",
            r"spoof(?:ing|ed)?",
        ),
        "El contexto indica suplantación de una marca o servicio legítimo.",
    ),
    (
        "phishing_keyword",
        25,
        (
            r"phishing",
            r"smishing",
            r"portal\s+fraudulento",
            r"sitio\s+fraudulento",
            r"p[aá]gina\s+fraudulenta",
            r"login\s+fraudulento",
            r"fraudulent\s+(?:site|portal|login)",
        ),
        "El contexto describe el IOC en relación directa con phishing o fraude.",
    ),
    (
        "login_form",
        15,
        (
            r"formulario\s+de\s+(?:login|inicio\s+de\s+sesi[oó]n|acceso)",
            r"portal\s+de\s+login",
            r"p[aá]gina\s+de\s+login",
            r"login\s+form",
            r"formulario\s+que\s+solicita",
        ),
        "El contexto describe un formulario o portal de login asociado al IOC.",
    ),
    (
        "recently_created_domain",
        25,
        (
            r"cread[oa]\s+hace\s+\d+\s+d[ií]as",
            r"registrad[oa]\s+hace\s+\d+\s+d[ií]as",
            r"recientemente\s+cread[oa]",
            r"cread[oa]\s+recientemente",
            r"recientemente\s+registrad[oa]",
            r"registrad[oa]\s+recientemente",
            r"registrad[oa]\s+en\s+los\s+[uú]ltimos\s+\d+\s+d[ií]as",
            r"dominio\s+reciente",
            r"recently\s+(?:created|registered)",
            r"newly\s+registered",
        ),
        "El dominio se menciona como recientemente creado o registrado.",
    ),
    (
        "not_legitimate_provider",
        20,
        (
            r"no\s+(?:est[aá]\s+)?relacionad[oa]\s+con\s+(?:un\s+|el\s+)?proveedor\s+leg[ií]timo",
            r"no\s+pertenece\s+a\s+(?:un\s+|el\s+)?proveedor\s+leg[ií]timo",
            r"no\s+corresponde\s+a\s+(?:un\s+|el\s+)?(?:proveedor|servicio|infraestructura)\s+leg[ií]tim[oa]",
            r"not\s+related\s+to\s+a?\s*legitimate\s+provider",
            r"no\s+es\s+infraestructura\s+leg[ií]tima",
        ),
        "El contexto indica que el IOC no pertenece a un proveedor legítimo.",
    ),
    (
        "auth_failed",
        15,
        (
            r"spf[\s:=]+(?:hard|soft)?fail(?:ed)?",
            r"dkim[\s:=]+fail(?:ed)?",
            r"dmarc[\s:=]+fail(?:ed)?",
            r"autenticaci[oó]n\s+fallida",
            r"fall[oó]\s+la\s+autenticaci[oó]n",
        ),
        "La autenticación de correo (SPF/DKIM/DMARC) aparece como fallida.",
    ),
    (
        "confirmed_abuse",
        30,
        (
            r"abuso\s+confirmad[oa]",
            r"confirmad[oa]\s+como\s+malicios[oa]",
            r"remitente\s+confirmado\s+como\s+malicioso",
            r"url\s+maliciosa\s+confirmada",
            r"campañas?\s+previas?",
            r"confirmed\s+(?:malicious|abuse)",
            r"phishing\s+confirmado",
        ),
        "El contexto confirma explícitamente el abuso o la maliciosidad del IOC.",
    ),
)

# ---------------------------------------------------------------------------
# Patrones de cautela (reducen la recomendación de bloqueo)
# ---------------------------------------------------------------------------

CAUTION_PATTERNS: tuple[tuple[str, int, tuple[str, ...], str], ...] = (
    (
        "legitimate_infrastructure",
        -25,
        (
            r"infraestructura\s+leg[ií]tima",
            r"servicio\s+leg[ií]timo",
            r"plataforma\s+leg[ií]tima",
            r"proveedor\s+leg[ií]timo",
            r"legitimate\s+(?:infrastructure|service|platform|provider)",
            r"es\s+leg[ií]tim[oa]",
            r"remitente\s+leg[ií]timo",
        ),
        "El contexto describe el IOC como infraestructura o servicio legítimo.",
    ),
    (
        "email_auth_passed",
        -25,
        (
            r"spf[\s:=]+pass(?:ed)?",
            r"dkim[\s:=]+(?:pass(?:ed)?|v[aá]lid[oa])",
            r"dmarc[\s:=]+pass(?:ed)?",
            r"spf\s+passed",
            r"dkim\s+v[aá]lido",
            r"dmarc\s+passed",
            r"autenticaci[oó]n\s+v[aá]lida",
            r"authentication\s+passed",
        ),
        "La autenticación de correo (SPF/DKIM/DMARC) aparece como válida.",
    ),
    (
        "trusted_vendor_mention",
        -15,
        (
            r"outlook\s+protection",
            r"microsoft\s+corporation",
            r"cloudflare\s+como\s+infraestructura",
            r"infraestructura\s+de\s+(?:google|microsoft|cloudflare|amazon|azure)",
        ),
        "El contexto asocia el IOC a infraestructura corporativa conocida.",
    ),
    (
        "shared_cloud_infrastructure",
        -20,
        (
            r"infraestructura\s+compartida",
            r"shared\s+(?:cloud\s+)?(?:hosting|infrastructure)",
            r"hosting\s+compartido",
            r"cdn\s+compartid[oa]",
        ),
        "El IOC corresponde a infraestructura cloud/hosting compartida.",
    ),
)

# Verbos de suplantación: si preceden a un patrón de cautela de marca,
# la mención NO es legitimadora (p.ej. "suplanta Microsoft Corporation").
_IMPERSONATION_BEFORE = re.compile(
    r"(?:suplanta(?:ndo)?|impersona(?:ting)?|se\s+hace\s+pasar\s+por|spoof(?:ing)?|phishing\s+de)\s*(?:a\s+)?$",
    re.I,
)

# Negaciones que invalidan una señal de legitimidad
_NEGATION_BEFORE = re.compile(
    r"(?:\bno\b|\bnot\b|\bsin\b|\bningún\b|\bninguna\b)[^.]{0,40}$",
    re.I,
)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")

_COMPILED_STRONG = tuple(
    (name, weight, tuple(re.compile(p, re.I) for p in patterns), desc)
    for name, weight, patterns, desc in STRONG_PATTERNS
)
_COMPILED_CAUTION = tuple(
    (name, weight, tuple(re.compile(p, re.I) for p in patterns), desc)
    for name, weight, patterns, desc in CAUTION_PATTERNS
)


def split_sentences(context: str) -> list[str]:
    """Divide el contexto en frases refangeadas para facilitar el matching."""
    text = context or ""
    raw = [s.strip() for s in _SENTENCE_SPLIT.split(text) if s and s.strip()]
    return [refang_sentence(s) for s in raw]


def refang_sentence(sentence: str) -> str:
    """Refanguea los IOCs dentro de una frase sin destruir el texto."""
    result = sentence
    result = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}", ".", result)
    result = re.sub(r"\[\s*@\s*\]|\(\s*@\s*\)|\{\s*@\s*\}", "@", result)
    result = re.sub(r"\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}", ":", result)
    result = re.sub(r"\bhxxp", "http", result, flags=re.I)
    return result


def mention_candidates(item) -> set[str]:
    """Cadenas que identifican al IOC dentro de una frase de contexto."""
    candidates: set[str] = set()
    for value in (
        getattr(item, "normalized", ""),
        refang(getattr(item, "original", "") or ""),
        getattr(item, "domain", ""),
        getattr(item, "root_domain", ""),
    ):
        value = (value or "").strip().lower()
        if not value:
            continue
        candidates.add(value)
        if value.startswith("https://") or value.startswith("http://"):
            candidates.add(value.split("://", 1)[1].rstrip("/"))
        if value.startswith("www."):
            candidates.add(value[4:])
    return {c for c in candidates if len(c) >= 5}


def _sentence_signals(sentence: str) -> list[tuple[str, str, int, str, str]]:
    """Devuelve (name, kind, weight, description, sentence) por frase."""
    found: list[tuple[str, str, int, str, str]] = []
    lower = sentence.lower()
    for name, weight, patterns, desc in _COMPILED_STRONG:
        for pattern in patterns:
            if pattern.search(lower):
                found.append((name, "strong", weight, desc, sentence))
                break
    for name, weight, patterns, desc in _COMPILED_CAUTION:
        for pattern in patterns:
            match = pattern.search(lower)
            if not match:
                continue
            prefix = lower[: match.start()]
            if _IMPERSONATION_BEFORE.search(prefix) or _NEGATION_BEFORE.search(prefix):
                # "suplanta Microsoft ..." o "no es infraestructura legítima"
                # no cuentan como señal de legitimidad.
                break
            found.append((name, "caution", weight, desc, sentence))
            break
    return found


def analyze_context(items, context: str) -> None:
    """Asigna a cada item una lista de Signal en item.signals.

    - Señal directa: la frase menciona el IOC (o su dominio/raíz).
    - Señal global: la frase no menciona ningún IOC del análisis; se
      aplica a los IOCs no protegidos (no allowlist / no trusted SaaS).
    - Si todos los IOCs no protegidos comparten un único dominio raíz,
      las señales fuertes globales se consideran directas (toda la
      investigación gira en torno a esa infraestructura).
    """
    sentences = split_sentences(context)
    per_item_candidates = [(item, mention_candidates(item)) for item in items]

    protected = lambda it: bool(
        getattr(it, "is_allowlisted", False) or getattr(it, "is_trusted_saas", False)
    )
    suspicious_roots = {
        (getattr(it, "root_domain", "") or getattr(it, "normalized", "")).lower()
        for it in items
        if not protected(it) and getattr(it, "ioc_type", "") in {"url", "domain", "ip", "email"}
    }
    suspicious_roots.discard("")
    single_infrastructure = len(suspicious_roots) == 1

    for item, _ in per_item_candidates:
        if not hasattr(item, "signals") or item.signals is None:
            item.signals = []

    for sentence in sentences:
        found = _sentence_signals(sentence)
        if not found:
            continue
        lower = sentence.lower()
        mentioned = [
            item
            for item, candidates in per_item_candidates
            if any(candidate in lower for candidate in candidates)
        ]
        if mentioned:
            for item in mentioned:
                for name, kind, weight, desc, sent in found:
                    _add_signal(item, name, kind, weight, direct=True, desc=desc, sentence=sent)
        else:
            # Frase sin mención explícita: señal global.
            for item, _ in per_item_candidates:
                if protected(item):
                    # Las señales fuertes globales no se cargan contra
                    # infraestructura legítima; las de cautela sí aplican.
                    for name, kind, weight, desc, sent in found:
                        if kind == "caution":
                            _add_signal(item, name, kind, weight, direct=False, desc=desc, sentence=sent)
                    continue
                for name, kind, weight, desc, sent in found:
                    direct = single_infrastructure and kind == "strong"
                    _add_signal(item, name, kind, weight, direct=direct, desc=desc, sentence=sent)


def _add_signal(item, name: str, kind: str, weight: int, direct: bool, desc: str, sentence: str) -> None:
    for existing in item.signals:
        if existing.name == name:
            # Conservar la versión directa si aparece en varias frases.
            if direct and not existing.direct:
                existing.direct = True
                existing.evidence = desc
                existing.sentence = sentence
            return
    item.signals.append(Signal(name=name, kind=kind, weight=weight, direct=direct, evidence=desc, sentence=sentence))


def strong_signals(item) -> list[Signal]:
    return [s for s in getattr(item, "signals", []) if s.kind == "strong"]


def direct_strong_signals(item) -> list[Signal]:
    return [s for s in getattr(item, "signals", []) if s.kind == "strong" and s.direct]


def caution_signals(item) -> list[Signal]:
    return [s for s in getattr(item, "signals", []) if s.kind == "caution"]


def implies_landing_final(item) -> bool:
    """Landing final explícito, o redirección final + (credenciales/login/suplantación/phishing)."""
    names = {s.name for s in direct_strong_signals(item)}
    if "landing_final" in names:
        return True
    if "final_redirect" in names and names & {
        "credential_theft",
        "login_form",
        "impersonation",
        "phishing_keyword",
    }:
        return True
    return False
