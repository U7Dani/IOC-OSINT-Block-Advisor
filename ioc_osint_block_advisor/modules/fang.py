from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_PROTOCOL_REPLACEMENTS = (
    (re.compile(r"\bhxxps\s*(?:\[\s*:\s*\]//|\(\s*:\s*\)//|\{\s*:\s*\}//|\[\s*://\s*\]|\(\s*://\s*\)|\{\s*://\s*\}|://)", re.I), "https://"),
    (re.compile(r"\bhxxp\s*(?:\[\s*:\s*\]//|\(\s*:\s*\)//|\{\s*:\s*\}//|\[\s*://\s*\]|\(\s*://\s*\)|\{\s*://\s*\}|://)", re.I), "http://"),
)

_DEFANG_REPLACEMENTS = (
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\(\s*/\s*\)"), "/"),
    (re.compile(r"\{\s*/\s*\}"), "/"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
    (re.compile(r"\(\s*@\s*\)"), "@"),
    (re.compile(r"\{\s*@\s*\}"), "@"),
    (re.compile(r"\s+dot\s+", re.I), "."),
    (re.compile(r"\bdot\b", re.I), "."),
)


def refang(value: str) -> str:
    """Return a refanged IOC suitable for parsing and OSINT lookups."""
    result = (value or "").strip().strip("<>").strip()
    for pattern, replacement in _PROTOCOL_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    for pattern, replacement in _DEFANG_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    for pattern, replacement in _PROTOCOL_REPLACEMENTS:
        result = pattern.sub(replacement, result)
    result = re.sub(r"\s+", "", result)
    return result


def defang(value: str) -> str:
    """Return a CyberChef-style defanged representation."""
    result = refang(value)
    result = re.sub(r"^https://", "hxxps[://]", result, flags=re.I)
    result = re.sub(r"^http://", "hxxp[://]", result, flags=re.I)
    result = result.replace(".", "[.]")
    return result


def normalize_domain(value: str) -> str:
    domain = refang(value).lower().strip()
    domain = domain.strip(".,;:()[]{}'\"")
    if "://" in domain:
        domain = urlsplit(domain).netloc
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    domain = domain.split(":", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.rstrip(".")


def normalize_url(value: str) -> str:
    url = refang(value).strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = f"https://{url}"
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))
