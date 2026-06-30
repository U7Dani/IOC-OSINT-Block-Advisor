from __future__ import annotations

import re
from dataclasses import dataclass

from .fang import defang, refang


HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+(?:\[\.\]|\(\.\)|\.)[A-Z]{2,}\b", re.I)
URL_RE = re.compile(
    r"\b(?:https?://|hxxps?(?:\[\s*://\s*\]|\(\s*://\s*\)|://))"
    r"[^\s<>'\"]+",
    re.I,
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)|\s+dot\s+)){1,}[a-z]{2,}\b",
    re.I,
)


@dataclass(frozen=True)
class ExtractedIOC:
    original: str
    refanged: str
    defanged: str
    source: str


def _clean(value: str) -> str:
    return value.strip().strip(".,;\"'<>[]()")


def extract_iocs(context: str, iocs_text: str) -> list[ExtractedIOC]:
    seen: set[str] = set()
    results: list[ExtractedIOC] = []

    for source, text in (("context", context or ""), ("ioc_list", iocs_text or "")):
        occupied_spans: list[tuple[int, int]] = []
        for pattern in (URL_RE, EMAIL_RE, IP_RE, HASH_RE, DOMAIN_RE):
            for match in pattern.finditer(text):
                if pattern is DOMAIN_RE and any(_overlaps(match.span(), span) for span in occupied_spans):
                    continue
                original = _clean(match.group(0))
                if not original:
                    continue
                refanged = refang(original)
                key = refanged.lower()
                if key in seen:
                    continue
                seen.add(key)
                if pattern is URL_RE or pattern is EMAIL_RE:
                    occupied_spans.append(match.span())
                results.append(
                    ExtractedIOC(
                        original=original,
                        refanged=refanged,
                        defanged=defang(refanged),
                        source=source,
                    )
                )
    return results


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return max(a[0], b[0]) < min(a[1], b[1])
