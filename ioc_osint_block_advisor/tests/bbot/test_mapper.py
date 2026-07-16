from integrations.bbot.mapper import (
    apply_bbot_evidence,
    apply_capped_score,
    build_relationships,
    classify_events,
)
from integrations.bbot.models import BBOTEvent, BBOTScanResult, RUN_COMPLETED


def _event(event_id, event_type, data, parent_id=None, module="", tags=None, scope_distance=0):
    return BBOTEvent(
        event_id=event_id,
        event_type=event_type,
        data=data,
        data_json=None,
        parent_id=parent_id,
        module=module,
        module_sequence="",
        scope_distance=scope_distance,
        tags=tags or [],
        timestamp=1700000000.0,
        resolved_hosts=[],
        raw={"type": event_type, "data": data},
    )


class DummyItem:
    """Minimal stand-in for ClassifiedIOC, only the fields the mapper touches."""

    def __init__(self, ioc_type="domain", normalized="example.com"):
        self.ioc_type = ioc_type
        self.normalized = normalized
        self.osint_results = []
        self.bbot_scan_id = ""
        self.bbot_status = ""
        self.bbot_events = []
        self.bbot_relationships = []
        self.related_assets = []
        self.technical_findings = []
        self.bbot_warnings = []
        self.bbot_score_delta = 0


def test_purely_informational_events_never_add_score():
    events = [
        _event("e1", "DNS_NAME", "sub.example.com"),
        _event("e2", "IP_ADDRESS", "93.184.216.34", parent_id="e1"),
        _event("e3", "OPEN_TCP_PORT", "93.184.216.34:443", parent_id="e2"),
    ]
    findings = classify_events(events)
    total, _ = apply_capped_score(findings)
    assert total == 0
    assert all(f.group == "informational" for f in findings)


def test_letsencrypt_certificate_event_scores_zero():
    events = [_event("e1", "TECHNOLOGY", "Let's Encrypt certificate", module="certificate_authority")]
    findings = classify_events(events)
    total, _ = apply_capped_score(findings)
    # A CA/certificate observation alone is informational or caution (never positive).
    assert total <= 0


def test_caution_signal_reduces_but_never_below_category_cap():
    events = [_event(f"e{i}", "IP_ADDRESS", "1.2.3.4", module="cloud_provider_lookup", tags=["cloud"]) for i in range(20)]
    findings = classify_events(events)
    total, breakdown = apply_capped_score(findings)
    # 20 identical caution findings must dedupe to a single -10 contribution,
    # not -200: no "quantity == increased signal" effect (also applies to
    # caution direction, not just positive).
    assert total == -10
    assert any("hosting_context" in line for line in breakdown)


def test_many_subdomains_do_not_increase_risk_automatically():
    events = [_event(f"e{i}", "DNS_NAME", f"sub{i}.example.com", module="subdomain_enum") for i in range(200)]
    findings = classify_events(events)
    total, _ = apply_capped_score(findings)
    assert total == 0


def test_positive_finding_requires_explicit_tag_match_not_just_module_name():
    # A module *named* like a scary thing, but without a matching confirmed
    # tag, must NOT be treated as a positive finding.
    events = [_event("e1", "FINDING", "something", module="nuclei_scary_module_name", tags=["informational"])]
    findings = classify_events(events)
    assert all(f.group != "positive" for f in findings)


def test_confirmed_takeover_is_positive_and_capped_at_relationship_cap():
    events = [_event(f"e{i}", "FINDING", "takeover.example.com", module="subdomain_takeover", tags=["takeover"]) for i in range(5)]
    findings = classify_events(events)
    total, breakdown = apply_capped_score(findings)
    # Dedup by (label, value): all 5 events share the same `value`, so they
    # collapse into a single contribution, capped at the relationship cap (20).
    assert total == 20
    assert any("relationship" in line for line in breakdown)


def test_reputation_cap_enforced_even_with_multiple_distinct_findings():
    events = [
        _event("e1", "FINDING", "malware.example.com", module="threat_intel", tags=["malware"]),
        _event("e2", "VULNERABILITY", "cve-in-example.com", module="nuclei", tags=["critical"]),
    ]
    findings = classify_events(events)
    total, breakdown = apply_capped_score(findings)
    # 40 (malware) + 25 (vuln) = 65 raw, capped to the reputation cap of 40.
    assert total == 40
    assert any("capado" in line for line in breakdown)


def test_relationships_preserve_parent_child_and_direct_vs_indirect():
    events = [
        _event("root", "DNS_NAME", "example.com", scope_distance=0),
        _event("child", "IP_ADDRESS", "1.2.3.4", parent_id="root", scope_distance=1),
        _event("grandchild", "OPEN_TCP_PORT", "1.2.3.4:22", parent_id="child", scope_distance=2),
    ]
    relationships = build_relationships(events)
    by_target = {r.target_id: r for r in relationships}
    assert by_target["child"].direct is True
    assert by_target["grandchild"].direct is False
    assert by_target["child"].source_id == "root"


def test_scan_event_never_becomes_a_related_asset():
    """Regression test: a real BBOT SCAN event's data_json carries a "name"
    key (the scan's own random codename, e.g. "strenuous_lois") which
    event_display_value's generic key lookup would otherwise misread as a
    discovered asset value."""
    scan_event = _event("SCAN:abc", "SCAN", None)
    scan_event.data_json = {"name": "strenuous_lois", "target": {"target": ["example.com"]}}
    findings = classify_events([scan_event])
    assert findings == []


def test_scan_lifecycle_self_referencing_event_produces_no_relationship():
    """Regression test: real BBOT SCAN events set parent == id (observed
    on a real BBOT 3.0.0 install during manual validation). That must not
    produce a self-loop relationship."""
    events = [_event("SCAN:abc123", "SCAN", None, parent_id="SCAN:abc123", scope_distance=0)]
    relationships = build_relationships(events)
    assert relationships == []


def test_relationship_alone_is_never_evidence_of_maliciousness():
    events = [
        _event("root", "DNS_NAME", "example.com", scope_distance=0),
        _event("child", "IP_ADDRESS", "1.2.3.4", parent_id="root", scope_distance=1),
    ]
    findings = classify_events(events)
    total, _ = apply_capped_score(findings)
    assert total == 0
    relationships = build_relationships(events)
    assert all(r.technical_only for r in relationships)


def test_apply_bbot_evidence_never_touches_decision_field():
    item = DummyItem()
    result = BBOTScanResult(
        scan_id="scan-1",
        status=RUN_COMPLETED,
        events=[_event("e1", "FINDING", "phish.example.com", module="phishing_detector", tags=["phishing"])],
    )
    apply_bbot_evidence(item, result)
    assert not hasattr(item, "decision") or getattr(item, "decision", "") == ""
    assert item.bbot_scan_id == "scan-1"
    assert item.bbot_status == RUN_COMPLETED
    assert item.osint_results, "confirmed phishing finding should surface as osint evidence for decision_engine"
    assert item.osint_results[0]["source"] == "bbot"


def test_apply_bbot_evidence_populates_related_assets_and_findings():
    item = DummyItem()
    result = BBOTScanResult(
        scan_id="scan-2",
        status=RUN_COMPLETED,
        events=[
            _event("root", "DNS_NAME", "example.com", scope_distance=0),
            _event("sub", "DNS_NAME", "sub.example.com", parent_id="root", scope_distance=1),
        ],
    )
    apply_bbot_evidence(item, result)
    assert "sub.example.com" in item.related_assets
    assert item.bbot_relationships
    assert item.bbot_relationships[0]["relation_type"]


def test_ip_target_evidence_never_marked_as_block_ready():
    """The mapper must never itself gate a block decision for IPs; that
    restriction belongs to decision_engine._decide_ip and stays untouched."""
    item = DummyItem(ioc_type="ip", normalized="1.2.3.4")
    result = BBOTScanResult(
        scan_id="scan-3",
        status=RUN_COMPLETED,
        events=[_event("e1", "FINDING", "1.2.3.4", module="threat_intel", tags=["malware"])],
    )
    apply_bbot_evidence(item, result)
    assert item.osint_results
    # The mapper only ever produces *evidence*; it has no "decision" field
    # or gating concept of its own.
    for result_dict in item.osint_results:
        assert "decision" not in result_dict
