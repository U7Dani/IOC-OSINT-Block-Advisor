"""Maps raw BBOT events/relationships onto SOC evidence for a ClassifiedIOC.

This is the single choke point that prevents "BBOT found something" from
turning into "this IOC is malicious." Read this module before adding a new
finding rule or preset — see also README's BBOT section ("cómo añadir un
nuevo mapper").

Design invariants (do not weaken without updating tests in tests/bbot/):
  * A technical relationship (parent/child event) is NEVER, by itself,
    evidence of maliciousness — see ``build_relationships``.
  * Every score contribution is capped per category (``CATEGORY_CAPS``)
    and deduplicated semantically before being applied, so that scanning
    the same asset twice, or a module emitting the same finding for many
    child events, cannot inflate the score.
  * Only a short, explicit allowlist of confirmed-finding rules
    (``POSITIVE_FINDING_RULES``) can raise ``osint_results`` to a
    malicious/suspicious verdict. Everything else is informational or
    "caution" (reduces false-positive risk framing, never raises risk).
  * IP addresses are never pushed toward a blockable verdict here — that
    restriction lives in decision_engine._decide_ip and is untouched by
    this module; BBOT only ever contributes score/evidence, never gating.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import BBOTEvent, BBOTRelationship, BBOTScanResult
from .parser import event_display_value

# ---------------------------------------------------------------------------
# Category score caps (FASE 11)
# ---------------------------------------------------------------------------

CATEGORY_CAPS = {
    "reputation": 40,
    "certificate": 20,
    "relationship": 20,
    "hosting_context": 10,
}

# ---------------------------------------------------------------------------
# Relationship semantics (FASE 9)
# ---------------------------------------------------------------------------

_RELATION_BY_EVENT_TYPE = {
    "IP_ADDRESS": "resolves_to",
    "IP_RANGE": "belongs_to_asn",
    "ASN": "belongs_to_asn",
    "OPEN_TCP_PORT": "exposes_port",
    "PROTOCOL": "serves_protocol",
    "TECHNOLOGY": "uses_technology",
    "EMAIL_ADDRESS": "references_email",
    "CODE_REPOSITORY": "found_in_repository",
}

_MODULE_RELATION_HINTS = (
    ("certificate", "related_by_certificate"),
    ("crt", "related_by_certificate"),
    ("passivedns", "related_by_passive_dns"),
    ("passive_dns", "related_by_passive_dns"),
    ("redirect", "redirects_to"),
)


def _infer_relation_type(event: BBOTEvent) -> str:
    module = (event.module or "").lower()
    for hint, relation in _MODULE_RELATION_HINTS:
        if hint in module:
            return relation
    if event.event_type in _RELATION_BY_EVENT_TYPE:
        return _RELATION_BY_EVENT_TYPE[event.event_type]
    if event.event_type == "DNS_NAME" and event.parent_id:
        return "discovered_from"
    return "discovered_from"


def build_relationships(events: list[BBOTEvent]) -> list[BBOTRelationship]:
    """Build parent/child relationships. Never invents a relation that
    isn't backed by an actual parent_id from BBOT's own event graph."""
    relationships: list[BBOTRelationship] = []
    for event in events:
        # Real BBOT SCAN lifecycle events self-reference (parent == id);
        # that's not a parent/child relationship between two assets.
        if not event.parent_id or event.parent_id == event.event_id:
            continue
        direct = event.scope_distance is not None and 0 <= event.scope_distance <= 1
        relationships.append(
            BBOTRelationship(
                source_id=event.parent_id,
                target_id=event.event_id,
                relation_type=_infer_relation_type(event),
                source_module=event.module,
                confidence="alta" if direct else "media",
                direct=direct,
                technical_only=True,
            )
        )
    return relationships


# ---------------------------------------------------------------------------
# Finding classification (FASE 10)
# ---------------------------------------------------------------------------


@dataclass
class MappedFinding:
    group: str  # "informational" | "caution" | "positive"
    label: str
    category: str  # key into CATEGORY_CAPS, only meaningful for caution/positive
    base_delta: int
    module: str
    event_id: str
    event_type: str
    value: str
    direct: bool
    explanation: str


# Tags/module substrings that describe shared/legitimate infrastructure —
# these exist to explain *reduced* false-positive risk, never to raise it.
_CAUTION_KEYWORDS = {
    "cdn": "cdn_or_waf",
    "waf": "cdn_or_waf",
    "cloud": "shared_cloud_infrastructure",
    "shared": "shared_cloud_infrastructure",
    "saas": "trusted_saas_relation",
    "letsencrypt": "common_certificate_authority",
    "let's encrypt": "common_certificate_authority",
    "historical": "historical_only",
    "wayback": "historical_only",
    "out-of-scope": "out_of_scope_relation",
    "out_of_scope": "out_of_scope_relation",
}

# Explicit, narrow allowlist of confirmed-finding rules. Each entry matches
# on (event_type, required tag substrings) and produces a bounded, labeled
# score contribution. This is intentionally short: a BBOT module *name*
# alone is never sufficient signal (see module docstring).
POSITIVE_FINDING_RULES = (
    {
        "label": "confirmed_takeover",
        "category": "relationship",
        "base_delta": 20,
        "event_types": {"FINDING", "VULNERABILITY"},
        "tag_any": {"takeover", "subdomain-takeover", "subdomain_takeover"},
        "explanation": "Hallazgo de takeover de subdominio confirmado por un módulo BBOT (evento directo).",
    },
    {
        "label": "confirmed_exposed_secret",
        "category": "reputation",
        "base_delta": 30,
        "event_types": {"FINDING"},
        "tag_any": {"secret", "exposed-secret", "credential-leak", "leak"},
        "explanation": "Secreto/credencial expuesta confirmada (repositorio de código o endpoint público).",
    },
    {
        "label": "known_malware_infrastructure",
        "category": "reputation",
        "base_delta": 40,
        "event_types": {"FINDING", "VULNERABILITY"},
        "tag_any": {"malware", "c2", "botnet"},
        "explanation": "Infraestructura asociada a malware/C2 conocido según un módulo de reputación de BBOT.",
    },
    {
        "label": "direct_phishing_landing",
        "category": "relationship",
        "base_delta": 20,
        "event_types": {"FINDING", "URL"},
        "tag_any": {"phishing", "phish"},
        "explanation": "Landing final identificado como phishing por un módulo BBOT.",
    },
    {
        "label": "direct_malicious_redirect",
        "category": "relationship",
        "base_delta": 15,
        "event_types": {"FINDING", "URL"},
        "tag_any": {"malicious-redirect", "malicious_redirect"},
        "explanation": "Redirección maliciosa confirmada en la cadena analizada.",
    },
    {
        "label": "high_confidence_vulnerability",
        "category": "reputation",
        "base_delta": 25,
        "event_types": {"VULNERABILITY", "FINDING"},
        "tag_any": {"critical", "high-confidence", "confirmed"},
        "explanation": "Vulnerabilidad de severidad alta/crítica confirmada por un módulo BBOT (p. ej. Nuclei).",
    },
)


def _matches_positive_rule(event: BBOTEvent, rule: dict) -> bool:
    if event.event_type not in rule["event_types"]:
        return False
    tags_lower = {t.lower() for t in event.tags}
    return bool(tags_lower & rule["tag_any"])


def _caution_label(event: BBOTEvent) -> str | None:
    haystack = " ".join([event.module or "", " ".join(event.tags)]).lower()
    for keyword, label in _CAUTION_KEYWORDS.items():
        if keyword in haystack:
            return label
    return None



# Scan lifecycle/meta event types (observed on a real BBOT 3.0.0 install):
# not discovered infrastructure, so never turned into a finding/asset.
# Real SCAN events carry a "name" key in their data_json (BBOT's own
# random scan codename, e.g. "strenuous_lois") which would otherwise be
# misread as an asset value by event_display_value's generic key lookup.
_NON_ASSET_EVENT_TYPES = {"SCAN"}


def classify_events(events: list[BBOTEvent]) -> list[MappedFinding]:
    findings: list[MappedFinding] = []
    for event in events:
        if event.event_type in _NON_ASSET_EVENT_TYPES:
            continue
        direct = event.scope_distance is not None and 0 <= event.scope_distance <= 1
        value = event_display_value(event)

        matched_positive = None
        for rule in POSITIVE_FINDING_RULES:
            if _matches_positive_rule(event, rule):
                matched_positive = rule
                break

        if matched_positive:
            findings.append(
                MappedFinding(
                    group="positive",
                    label=matched_positive["label"],
                    category=matched_positive["category"],
                    base_delta=matched_positive["base_delta"],
                    module=event.module,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    value=value,
                    direct=direct,
                    explanation=matched_positive["explanation"],
                )
            )
            continue

        caution_label = _caution_label(event)
        if caution_label:
            findings.append(
                MappedFinding(
                    group="caution",
                    label=caution_label,
                    category="hosting_context",
                    base_delta=-10,
                    module=event.module,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    value=value,
                    direct=direct,
                    explanation="Señal de infraestructura compartida/legítima: no debe aumentar el riesgo del IOC.",
                )
            )
            continue

        findings.append(
            MappedFinding(
                group="informational",
                label=f"observed_{event.event_type.lower()}",
                category="hosting_context",
                base_delta=0,
                module=event.module,
                event_id=event.event_id,
                event_type=event.event_type,
                value=value,
                direct=direct,
                explanation="Evento técnico informativo: no aporta señal de maliciosidad por sí solo.",
            )
        )
    return findings


def _dedup_key(finding: MappedFinding) -> tuple:
    return (finding.label, finding.value)


def apply_capped_score(findings: list[MappedFinding]) -> tuple[int, list[str]]:
    """Sum findings per category, deduplicated, capped. Returns (total, breakdown)."""
    seen: set[tuple] = set()
    per_category: dict[str, int] = {}
    breakdown: list[str] = []

    for finding in findings:
        if finding.base_delta == 0:
            continue
        key = _dedup_key(finding)
        if key in seen:
            continue
        seen.add(key)
        per_category[finding.category] = per_category.get(finding.category, 0) + finding.base_delta

    total = 0
    for category, raw_value in per_category.items():
        cap = CATEGORY_CAPS.get(category, 0)
        if raw_value >= 0:
            capped = min(raw_value, cap)
        else:
            capped = max(raw_value, -cap)
        if capped != raw_value:
            breakdown.append(f"bbot_{category}: {raw_value:+d} capado a {capped:+d} (máximo por categoría {cap})")
        else:
            breakdown.append(f"bbot_{category}: {capped:+d}")
        total += capped
    return total, breakdown


def apply_bbot_evidence(item, scan_result: BBOTScanResult) -> None:
    """Attach BBOT evidence to a ClassifiedIOC. Never mutates item.decision."""
    item.bbot_scan_id = scan_result.scan_id
    item.bbot_status = scan_result.status
    item.bbot_warnings = list(scan_result.warnings) + list(scan_result.errors)

    relationships = build_relationships(scan_result.events)
    item.bbot_relationships = [
        {
            "source_id": r.source_id,
            "target_id": r.target_id,
            "relation_type": r.relation_type,
            "source_module": r.source_module,
            "confidence": r.confidence,
            "direct": r.direct,
            "technical_only": r.technical_only,
        }
        for r in relationships
    ]

    findings = classify_events(scan_result.events)
    item.bbot_events = [
        {
            "event_id": f.event_id,
            "event_type": f.event_type,
            "value": f.value,
            "module": f.module,
            "direct": f.direct,
            "group": f.group,
            "label": f.label,
            "score_impact_reason": f.explanation,
        }
        for f in findings
    ]

    related_values = {f.value for f in findings if f.value}
    item.related_assets = sorted(v for v in related_values if v and v != item.normalized)

    positive_or_caution = [f for f in findings if f.group in ("positive", "caution")]
    item.technical_findings = [
        {
            "label": f.label,
            "group": f.group,
            "module": f.module,
            "event_type": f.event_type,
            "value": f.value,
            "direct": f.direct,
            "explanation": f.explanation,
        }
        for f in positive_or_caution
    ]

    total_delta, breakdown = apply_capped_score(findings)
    item.bbot_score_delta = total_delta

    if total_delta != 0:
        direct_positive = [f for f in findings if f.group == "positive" and f.direct]
        verdict = "malicious" if direct_positive and total_delta > 0 else (
            "suspicious" if total_delta > 0 else "clean"
        )
        evidence_text = "; ".join(
            f"{f.label} ({f.module or 'bbot'}): {f.explanation}" for f in positive_or_caution
        )[:1000]
        item.osint_results.append(
            {
                "source": "bbot",
                "status": "hit" if verdict == "malicious" else ("suspicious" if verdict == "suspicious" else "ok"),
                "score_delta": total_delta,
                "evidence": evidence_text or "Evidencia BBOT agregada.",
                "provider": "bbot",
                "checked": True,
                "artifact_type": item.ioc_type,
                "verdict": verdict,
                "confidence": "media",
                "details": "; ".join(breakdown),
                "error": "",
            }
        )
    if not positive_or_caution and not findings:
        item.bbot_warnings.append("BBOT no devolvió eventos para este objetivo.")
