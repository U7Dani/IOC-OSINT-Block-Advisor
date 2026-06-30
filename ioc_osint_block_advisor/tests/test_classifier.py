from modules.classifier import classify_many
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


def test_allowlisted_zoom_sender():
    items = classify_many(extract_iocs("", "noreply-zoomevents@zoom.us"), "", load_allowlist())
    assert items[0].ioc_type == "email"
    assert items[0].is_allowlisted is True
    assert items[0].role == "sender_observed"


def test_unsubscribe_role():
    items = classify_many(extract_iocs("", "hxxps[://]events[.]zoom[.]us/unsubscribe/x"), "", load_allowlist())
    assert items[0].role == "unsubscribe"
