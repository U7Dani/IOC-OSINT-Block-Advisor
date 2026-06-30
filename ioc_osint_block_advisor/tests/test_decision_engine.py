from modules.classifier import classify_many
from modules.decision_engine import decide_many
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


def _run(context: str, iocs: str):
    extracted = extract_iocs(context, iocs)
    classified = classify_many(extracted, context, load_allowlist())
    return decide_many(classified)


def test_zoom_sender_do_not_block():
    item = _run("", "noreply-zoomevents@zoom.us")[0]
    assert item.decision in {"DO_NOT_BLOCK", "OBSERVED_ONLY"}
    assert item.decision != "BLOCK_SENDER_EXACT"
    assert item.false_positive_risk == "Alto"


def test_zoom_events_url_review_not_domain_block():
    item = _run("", "hxxps[://]events[.]zoom[.]us/e/view/UhGj24Z2R4G98fMEFfYeKg")[0]
    assert item.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    assert item.decision != "BLOCK_DOMAIN"
    assert item.recommended_action != "Bloquear dominio completo"


def test_final_landing_phishing_blocks_domain():
    context = "La URL redirige finalmente a un portal de login que suplanta a Meta y solicita credenciales. El dominio fue creado hace 7 días."
    item = _run(context, "hxxps[://]login[.]workportalsso[.]com/")[0]
    assert item.decision == "BLOCK_DOMAIN"
    assert item.false_positive_risk == "Bajo"
    assert "phishing" in item.reason.lower() or "suplantación" in item.reason.lower()


def test_unknown_sender_requires_review():
    item = _run("", "j.richards@copromopro[.]biz")[0]
    assert item.decision == "REVIEW"
    assert item.decision != "BLOCK_SENDER_EXACT"


def test_allowlisted_unsubscribe_do_not_block():
    item = _run("To unsubscribe click here", "hxxps[://]events[.]zoom[.]us/unsubscribe/test")[0]
    assert item.role == "unsubscribe"
    assert item.decision == "DO_NOT_BLOCK"


def test_highspot_url_never_blocks_domain():
    item = _run("", "hxxps[://]meta[.]highspot[.]com/viewer/db17d43e16d2b3d51d46df9c8d5226f0")[0]
    assert item.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    assert item.decision != "BLOCK_DOMAIN"
    assert "legítima" in item.reason


def test_new_domain_without_other_evidence_is_review_not_block():
    item = _run("El dominio fue creado hace 3 días.", "new-example-login.biz")[0]
    assert item.decision == "REVIEW"
    assert item.decision != "BLOCK_DOMAIN"


def test_decision_is_idempotent_with_osint_score():
    item = _run("", "hxxps[://]example[.]biz/path")[0]
    item.osint_results = [{"source": "urlhaus", "status": "hit", "score_delta": 50, "evidence": "test"}]
    first = decide_many([item])[0].score
    second = decide_many([item])[0].score
    assert first == second
