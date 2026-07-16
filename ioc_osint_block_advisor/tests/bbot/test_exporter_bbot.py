import json

from modules.classifier import ClassifiedIOC
from modules.exporter import export_results


def _item(decision, **bbot_fields):
    item = ClassifiedIOC(
        original="evil.example.com",
        normalized="evil.example.com",
        defanged="evil[.]example[.]com",
        source="context",
        ioc_type="domain",
        domain="evil.example.com",
        root_domain="evil.example.com",
    )
    item.decision = decision
    item.recommended_action = "x"
    item.false_positive_risk = "Medio"
    item.reason = "test"
    for key, value in bbot_fields.items():
        setattr(item, key, value)
    return item


def test_no_bbot_files_when_no_item_used_bbot(tmp_path):
    item = _item("DO_NOT_BLOCK")
    files = export_results([item], "", output_dir=tmp_path)
    assert "bbot_summary" not in files
    assert not (tmp_path / "bbot_summary.json").exists()


def test_bbot_files_created_when_bbot_ran(tmp_path):
    item = _item(
        "REVIEW",
        bbot_scan_id="scan-1",
        bbot_status="completed",
        bbot_score_delta=10,
        bbot_events=[{"event_id": "e1", "event_type": "DNS_NAME", "value": "evil.example.com", "module": "dnsresolve", "direct": True, "group": "informational", "label": "observed_dns_name", "score_impact_reason": "x"}],
        bbot_relationships=[{"source_id": "root", "target_id": "e1", "relation_type": "resolves_to", "source_module": "dnsresolve", "confidence": "alta", "direct": True, "technical_only": True}],
        related_assets=["1.2.3.4"],
        technical_findings=[{"label": "shared_cloud_infrastructure", "group": "caution", "module": "cloud_lookup", "event_type": "IP_ADDRESS", "value": "1.2.3.4", "direct": True, "explanation": "shared cloud"}],
    )
    files = export_results([item], "", output_dir=tmp_path)
    assert "bbot_summary" in files
    summary = json.loads(files["bbot_summary"].read_text(encoding="utf-8"))
    assert summary[0]["ioc"] == "evil.example.com"
    assert summary[0]["final_recommendation"] == "REVIEW"
    assert "1.2.3.4" in summary[0]["shared_infrastructure"]

    events_lines = files["bbot_events"].read_text(encoding="utf-8").strip().splitlines()
    assert len(events_lines) == 1
    assert json.loads(events_lines[0])["ioc"] == "evil.example.com"

    relationships = json.loads(files["bbot_relationships"].read_text(encoding="utf-8"))
    assert relationships[0]["relation_type"] == "resolves_to"

    assets_csv = files["bbot_assets"].read_text(encoding="utf-8")
    assert "1.2.3.4" in assets_csv

    findings_csv = files["bbot_findings"].read_text(encoding="utf-8")
    assert "shared_cloud_infrastructure" in findings_csv


def test_bbot_evidence_never_appears_in_blocklist_files(tmp_path):
    item = _item(
        "DO_NOT_BLOCK",
        bbot_scan_id="scan-2",
        bbot_status="completed",
        technical_findings=[{"label": "known_malware_infrastructure", "group": "positive", "module": "threat_intel", "event_type": "FINDING", "value": "evil.example.com", "direct": True, "explanation": "x"}],
    )
    files = export_results([item], "", output_dir=tmp_path)
    domains = files["domains"].read_text(encoding="utf-8")
    assert "evil.example.com" not in domains
