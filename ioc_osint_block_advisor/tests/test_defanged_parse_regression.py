from modules.classifier import classify_many
from modules.extractor import extract_iocs
from modules.fang import normalize_domain, normalize_url, refang
from modules.utils import load_allowlist


def test_reported_defanged_iocs_normalize_without_invalid_ipv6_url():
    context = """
    Sender: servicedesk@varna-mardhika[.]com
    URL inicial: hxxps[:]//ptrvc[.]net/test
    Redirección final: Isabel[.]formulier-be[.]com
    Dominio recientemente creado: formulier-be[.]com
    """
    items = extract_iocs(context, "")
    classified = classify_many(items, context, load_allowlist())
    normalized = {item.normalized for item in classified}

    assert refang("hxxps[:]//ptrvc[.]net/test") == "https://ptrvc.net/test"
    assert normalize_url("hxxps[:]//ptrvc[.]net/test") == "https://ptrvc.net/test"
    assert normalize_url("hxxps[://]events[.]zoom[.]us/e/view/test") == "https://events.zoom.us/e/view/test"
    assert "servicedesk@varna-mardhika.com" in normalized
    assert "https://ptrvc.net/test" in normalized
    assert "isabel.formulier-be.com" in normalized
    assert normalize_domain("formulier-be[.]com") == "formulier-be.com"
