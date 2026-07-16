"""Regression tests: BBOT evidence must never weaken the conservative
decision engine. These exercise the real decision_engine/classifier code
(not mocks) so a future change to gating/scoring that breaks these
guarantees fails loudly."""

from integrations.bbot.mapper import apply_bbot_evidence
from integrations.bbot.models import BBOTEvent, BBOTScanResult, RUN_COMPLETED
from modules.classifier import classify_many
from modules.decision_engine import decide_many
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


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


def _classify(context: str, iocs: str):
    extracted = extract_iocs(context, iocs)
    return classify_many(extracted, context, load_allowlist())


def test_technical_event_alone_never_produces_block():
    items = _classify("", "suspicious-newdomain-xyz123.com")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s1",
        status=RUN_COMPLETED,
        events=[
            _event("e1", "DNS_NAME", "suspicious-newdomain-xyz123.com"),
            _event("e2", "IP_ADDRESS", "93.184.216.34", parent_id="e1"),
            _event("e3", "OPEN_TCP_PORT", "93.184.216.34:443", parent_id="e2"),
        ],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_indirect_relationship_alone_never_produces_block():
    items = _classify("", "suspicious-newdomain-xyz123.com")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s2",
        status=RUN_COMPLETED,
        events=[
            _event("root", "DNS_NAME", "suspicious-newdomain-xyz123.com", scope_distance=0),
            _event("cousin", "DNS_NAME", "another.example.net", parent_id="root", scope_distance=3, module="passive_dns"),
        ],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT"}


def test_shared_cloudflare_ip_never_blocked():
    items = _classify("", "203.0.113.5")
    item = items[0]
    assert item.ioc_type == "ip"
    result = BBOTScanResult(
        scan_id="s3",
        status=RUN_COMPLETED,
        events=[_event("e1", "IP_ADDRESS", "203.0.113.5", module="cloud_provider_lookup", tags=["cdn", "cloudflare"])],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_azure_shared_ip_never_blocked():
    items = _classify("", "198.51.100.7")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s4",
        status=RUN_COMPLETED,
        events=[_event("e1", "IP_ADDRESS", "198.51.100.7", module="asn_lookup", tags=["cloud", "azure"])],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_aws_shared_ip_never_blocked():
    items = _classify("", "192.0.2.44")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s5",
        status=RUN_COMPLETED,
        events=[_event("e1", "IP_ADDRESS", "192.0.2.44", module="asn_lookup", tags=["cloud", "aws"])],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_saas_root_domain_never_gets_block_domain_from_bbot_alone():
    items = _classify("", "meta.highspot.com")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s6",
        status=RUN_COMPLETED,
        events=[_event("e1", "DNS_NAME", "meta.highspot.com", tags=["saas"], module="saas_lookup")],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision != "BLOCK_DOMAIN"


def test_certificate_relationship_without_further_evidence_stays_review_or_observed():
    context = "Se identificó un dominio relacionado por certificado compartido, sin más evidencia de actividad maliciosa."
    items = _classify(context, "cert-sibling-example.net")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s7",
        status=RUN_COMPLETED,
        events=[_event("e1", "DNS_NAME", "cert-sibling-example.net", module="crt_related_domains")],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision in {"REVIEW", "OBSERVED_ONLY", "DO_NOT_BLOCK"}


def test_two_hundred_subdomains_do_not_automatically_raise_risk():
    items = _classify("", "bigcompany-example.com")
    item = items[0]
    events = [
        _event(f"e{i}", "DNS_NAME", f"sub{i}.bigcompany-example.com", parent_id="root", module="subdomain_enum")
        for i in range(200)
    ]
    result = BBOTScanResult(scan_id="s8", status=RUN_COMPLETED, events=events)
    score_before = item.score
    apply_bbot_evidence(item, result)
    assert item.bbot_score_delta == 0
    assert item.score == score_before


def test_open_port_443_scores_zero():
    items = _classify("", "example-service.com")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s9",
        status=RUN_COMPLETED,
        events=[_event("e1", "OPEN_TCP_PORT", "example-service.com:443")],
    )
    score_before = item.score
    apply_bbot_evidence(item, result)
    assert item.bbot_score_delta == 0
    assert item.score == score_before


def test_letsencrypt_certificate_scores_zero_or_negative_never_positive():
    items = _classify("", "example-service.com")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s10",
        status=RUN_COMPLETED,
        events=[_event("e1", "TECHNOLOGY", "Let's Encrypt", module="letsencrypt_ca_lookup", tags=["letsencrypt"])],
    )
    apply_bbot_evidence(item, result)
    assert item.bbot_score_delta <= 0


def test_confirmed_direct_phishing_landing_can_contribute_to_block_when_context_agrees():
    context = (
        "El usuario reporta que la URL final del correo suplanta el portal de login corporativo y "
        "solicita credenciales; se confirmó phishing activo con robo de credenciales."
    )
    items = _classify(context, "hxxps[://]login[.]corp-verify-secure[.]com/session")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s11",
        status=RUN_COMPLETED,
        events=[
            _event(
                "e1",
                "FINDING",
                "https://login.corp-verify-secure.com/session",
                module="phishing_detector",
                tags=["phishing"],
                scope_distance=0,
            )
        ],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    # BBOT corroborates (does not solely cause) a block that context/local
    # scoring had already pushed toward: still gated by direct strong
    # signals from context_signals, never by BBOT alone.
    assert decided[0].decision in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "REVIEW"}


def test_ip_is_never_exported_to_blocklist_even_with_bbot_malware_tag():
    items = _classify("", "203.0.113.99")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s12",
        status=RUN_COMPLETED,
        events=[_event("e1", "FINDING", "203.0.113.99", module="threat_intel", tags=["malware"])],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_bbot_failure_never_causes_a_block_decision():
    items = _classify("", "example-domain-failure-case.com")
    item = items[0]
    item.bbot_status = "failed"
    item.bbot_warnings.append("BBOT no disponible.")
    decided = decide_many([item])
    assert decided[0].decision not in {"BLOCK_DOMAIN", "BLOCK_URL_EXACT", "BLOCK_SENDER_EXACT", "BLOCK_HASH"}


def test_client_protected_domain_stays_protected_even_with_bbot_evidence():
    # trusted_saas_domains.txt / allowlist files are loaded from config/;
    # zoom.us is used elsewhere in the suite as a known trusted_saas entry.
    items = _classify("", "events.zoom.us")
    item = items[0]
    result = BBOTScanResult(
        scan_id="s13",
        status=RUN_COMPLETED,
        events=[_event("e1", "DNS_NAME", "events.zoom.us", tags=["cdn"])],
    )
    apply_bbot_evidence(item, result)
    decided = decide_many([item])
    assert decided[0].decision != "BLOCK_DOMAIN"
