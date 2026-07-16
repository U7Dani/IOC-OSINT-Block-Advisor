"""Tests for modules/osint_bbot.py: the single seam between the app's
analysis worker and the BBOT integration package."""

from unittest.mock import patch

from integrations.bbot.models import (
    PROFILE_AUTHORIZED_ACTIVE,
    PROFILE_SOC_PASSIVE,
    RUN_COMPLETED,
    RUN_FAILED,
    BBOTEvent,
    BBOTScanResult,
)
from modules.classifier import ClassifiedIOC
from modules.osint_bbot import (
    BBOTEnrichmentOptions,
    bbot_applicable,
    bbot_target_for,
    collect_bbot_many,
)


def _ioc(ioc_type, normalized, domain="", root_domain="", subdomain=""):
    return ClassifiedIOC(
        original=normalized,
        normalized=normalized,
        defanged=normalized,
        source="context",
        ioc_type=ioc_type,
        domain=domain,
        root_domain=root_domain,
        subdomain=subdomain,
    )


def test_bbot_never_applicable_to_hashes():
    item = _ioc("hash_sha256", "a" * 64)
    assert bbot_applicable(item) is False
    assert bbot_target_for(item) is None


def test_bbot_applicable_to_domain_url_ip_email():
    for ioc_type in ("domain", "url", "ip", "email"):
        item = _ioc(ioc_type, "x")
        assert bbot_applicable(item) is True


def test_email_target_is_domain_only_never_full_address():
    item = _ioc("email", "attacker@evil.example.com", domain="evil.example.com")
    target = bbot_target_for(item)
    assert target == "evil.example.com"
    assert "@" not in target


def test_url_target_defaults_to_domain_not_full_url():
    item = _ioc("url", "https://evil.example.com/login?token=SECRET123", domain="evil.example.com", root_domain="example.com")
    target = bbot_target_for(item, include_full_url=False)
    assert target == "example.com"
    assert "token" not in target
    assert "SECRET123" not in target


def test_url_target_includes_full_url_only_when_explicitly_requested():
    item = _ioc("url", "https://evil.example.com/login?token=SECRET123", domain="evil.example.com", root_domain="example.com")
    target = bbot_target_for(item, include_full_url=True)
    assert target == "https://evil.example.com/login?token=SECRET123"


def test_domain_target_uses_root_domain():
    item = _ioc("domain", "sub.evil.example.com", domain="sub.evil.example.com", root_domain="example.com")
    assert bbot_target_for(item) == "example.com"


def test_ip_target_is_normalized_value():
    item = _ioc("ip", "1.2.3.4")
    assert bbot_target_for(item) == "1.2.3.4"


def test_disabled_options_never_calls_run_scan():
    item = _ioc("domain", "example.com", domain="example.com", root_domain="example.com")
    with patch("modules.osint_bbot.run_scan") as mock_run:
        collect_bbot_many([item], BBOTEnrichmentOptions(enabled=False))
    mock_run.assert_not_called()
    assert item.bbot_status == ""


def test_active_profile_without_authorization_is_refused():
    item = _ioc("domain", "example.com", domain="example.com", root_domain="example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_AUTHORIZED_ACTIVE, authorized=False)
    with patch("modules.osint_bbot.run_scan") as mock_run:
        collect_bbot_many([item], options)
    mock_run.assert_not_called()
    assert item.bbot_status == "failed"
    assert any("autorización" in w for w in item.bbot_warnings)


def test_active_profile_with_authorization_proceeds():
    item = _ioc("domain", "example.com", domain="example.com", root_domain="example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_AUTHORIZED_ACTIVE, authorized=True)
    fake_result = BBOTScanResult(scan_id="s1", status=RUN_COMPLETED)
    with patch("modules.osint_bbot.run_scan", return_value=fake_result) as mock_run:
        collect_bbot_many([item], options)
    mock_run.assert_called_once()
    assert item.bbot_scan_id == "s1"


def test_bbot_process_error_never_raises_and_marks_item_failed():
    item = _ioc("domain", "example.com", domain="example.com", root_domain="example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_SOC_PASSIVE)
    with patch("modules.osint_bbot.run_scan", side_effect=RuntimeError("boom")):
        collect_bbot_many([item], options)  # must not raise
    assert item.bbot_status == "failed"
    assert item.bbot_warnings


def test_bbot_not_installed_reported_as_warning_not_exception():
    item = _ioc("domain", "example.com", domain="example.com", root_domain="example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_SOC_PASSIVE)
    fake_result = BBOTScanResult(scan_id="", status=RUN_FAILED, errors=["BBOT no disponible."])
    with patch("modules.osint_bbot.run_scan", return_value=fake_result):
        collect_bbot_many([item], options)  # must not raise
    assert item.bbot_status == RUN_FAILED
    assert "BBOT no disponible." in item.bbot_warnings


def test_items_sharing_root_domain_trigger_a_single_scan():
    item1 = _ioc("domain", "a.evil.example.com", domain="a.evil.example.com", root_domain="evil.example.com")
    item2 = _ioc("url", "https://b.evil.example.com/x", domain="b.evil.example.com", root_domain="evil.example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_SOC_PASSIVE)
    fake_result = BBOTScanResult(scan_id="shared-scan", status=RUN_COMPLETED)
    with patch("modules.osint_bbot.run_scan", return_value=fake_result) as mock_run:
        collect_bbot_many([item1, item2], options)
    assert mock_run.call_count == 1
    assert item1.bbot_scan_id == "shared-scan"
    assert item2.bbot_scan_id == "shared-scan"


def test_different_root_domains_trigger_separate_scans():
    item1 = _ioc("domain", "evil1.example.com", domain="evil1.example.com", root_domain="evil1.example.com")
    item2 = _ioc("domain", "evil2.example.com", domain="evil2.example.com", root_domain="evil2.example.com")
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_SOC_PASSIVE)
    fake_result = BBOTScanResult(scan_id="s", status=RUN_COMPLETED)
    with patch("modules.osint_bbot.run_scan", return_value=fake_result) as mock_run:
        collect_bbot_many([item1, item2], options)
    assert mock_run.call_count == 2


def test_hash_items_never_trigger_a_scan():
    item = _ioc("hash_sha256", "a" * 64)
    options = BBOTEnrichmentOptions(enabled=True, profile=PROFILE_SOC_PASSIVE)
    with patch("modules.osint_bbot.run_scan") as mock_run:
        collect_bbot_many([item], options)
    mock_run.assert_not_called()
