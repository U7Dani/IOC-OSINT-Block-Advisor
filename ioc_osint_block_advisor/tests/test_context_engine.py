"""Tests de los casos de aceptación del motor contextual mejorado.

Cubren los 6 escenarios de la especificación:
1. SaaS legítimo observado (Zoom).
2. Landing final de phishing (BLOCK_DOMAIN).
3. Dropbox como redirección (infraestructura legítima abusada).
4. Dominio final reciente con formulario de login (BLOCK_DOMAIN).
5. Sender sospechoso sin evidencia fuerte (REVIEW).
6. Allowlist/trusted_saas nunca produce BLOCK_DOMAIN.
"""

from modules.classifier import classify_many
from modules.decision_engine import decide_many
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


def _run(context: str, iocs: str):
    extracted = extract_iocs(context, iocs)
    classified = classify_many(extracted, context, load_allowlist())
    return decide_many(classified)


def _by_value(items, needle: str):
    for item in items:
        if needle in item.normalized:
            return item
    raise AssertionError(f"IOC {needle} no encontrado en {[i.normalized for i in items]}")


# --- Caso 1: SaaS legítimo observado ---------------------------------------

def test_case1_legit_saas_observed():
    context = (
        "Se observa una invitación desde Zoom Events. El enlace visible pertenece a "
        "events.zoom.us. El remitente noreply-zoomevents@zoom.us es legítimo."
    )
    items = _run(context, "noreply-zoomevents@zoom.us\nhxxps[://]events[.]zoom[.]us/e/view/test")
    sender = _by_value(items, "noreply-zoomevents@zoom.us")
    url = _by_value(items, "https://events.zoom.us/e/view/test")
    assert sender.decision == "DO_NOT_BLOCK"
    assert url.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    for item in items:
        assert item.decision != "BLOCK_DOMAIN"
    assert "legítima" in url.reason


# --- Caso 2: landing final de phishing --------------------------------------

def test_case2_final_landing_blocks_domain():
    context = (
        "Durante la cadena de redirecciones termina en login.workportalsso.com, que "
        "suplanta Meta y solicita credenciales. El dominio fue creado recientemente."
    )
    items = _run(context, "hxxps[://]login[.]workportalsso[.]com/\nworkportalsso[.]com")
    landing = _by_value(items, "https://login.workportalsso.com/")
    root = _by_value(items, "workportalsso.com")
    assert landing.decision == "BLOCK_DOMAIN"
    assert root.decision == "BLOCK_DOMAIN"
    assert landing.false_positive_risk in {"Bajo", "Medio-Bajo"}
    assert landing.block_value
    assert landing.evidence, "la decisión debe incluir evidencias"
    assert any("credenciales" in e.lower() for e in landing.evidence)


# --- Caso 3: Dropbox como redirección ----------------------------------------

def test_case3_dropbox_redirect_never_blocks_domain():
    context = (
        "La URL incluida en el correo inicia una cadena de redirecciones que empieza en la "
        "plataforma Dropbox y posteriormente dirige a un sitio externo de phishing."
    )
    items = _run(context, "hxxps[://]www[.]dropbox[.]com/scl/fi/test")
    url = _by_value(items, "dropbox.com/scl/fi/test")
    assert url.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    assert url.decision != "BLOCK_DOMAIN"
    assert "legítima" in url.reason
    for item in items:
        assert item.decision != "BLOCK_DOMAIN"


# --- Caso 4: dominio final reciente ------------------------------------------

def test_case4_recent_final_domain_blocks():
    context = (
        "La redirección final dirige a Isabel.formulier-be.com, dominio recientemente creado, "
        "con formulario de login que suplanta Microsoft para capturar credenciales."
    )
    items = _run(context, "Isabel[.]formulier-be[.]com\nformulier-be[.]com")
    sub = _by_value(items, "isabel.formulier-be.com")
    root = _by_value(items, "formulier-be.com")
    assert sub.decision == "BLOCK_DOMAIN"
    assert root.decision == "BLOCK_DOMAIN"
    assert sub.role == "landing_final"
    assert "recient" in " ".join(sub.evidence).lower()


# --- Caso 5: sender sospechoso sin evidencia fuerte ---------------------------

def test_case5_suspicious_sender_review():
    context = (
        "El correo fue enviado por servicedesk@varna-mardhika.com. No hay evidencia suficiente "
        "de que el dominio del remitente deba bloquearse, aunque está relacionado con el correo observado."
    )
    items = _run(context, "servicedesk@varna-mardhika[.]com")
    sender = _by_value(items, "servicedesk@varna-mardhika.com")
    assert sender.decision == "REVIEW"
    assert sender.decision != "BLOCK_SENDER_EXACT"


def test_sender_blocked_only_with_explicit_strong_evidence():
    context = (
        "El remitente attacker@evil-payroll.top fue confirmado como malicioso, con abuso confirmado "
        "en campañas previas de phishing, suplantación de Microsoft y captura de credenciales, "
        "con autenticación fallida SPF fail."
    )
    items = _run(context, "attacker@evil-payroll[.]top")
    sender = _by_value(items, "attacker@evil-payroll.top")
    # Sin hit OSINT >= 50, se mantiene conservador: nunca peor que REVIEW,
    # nunca DO_NOT_BLOCK ni OBSERVED_ONLY con evidencia tan explícita.
    assert sender.decision in {"REVIEW", "BLOCK_SENDER_EXACT"}
    sender.osint_results = [{"source": "otx", "status": "hit", "score_delta": 50, "evidence": "sender in campaign"}]
    sender._osint_score_applied = False
    decided = decide_many([sender])[0]
    assert decided.decision == "BLOCK_SENDER_EXACT"


# --- Caso 6: allowlist / trusted_saas ----------------------------------------

def test_case6_allowlisted_domain_never_block_domain_even_with_phishing_context():
    context = (
        "La cadena de phishing suplanta a Microsoft, solicita credenciales en la redirección final "
        "y utiliza sharepoint.com como infraestructura legítima."
    )
    items = _run(context, "sharepoint[.]com\nhxxps[://]sharepoint[.]com/sites/abused/doc")
    for item in items:
        assert item.decision != "BLOCK_DOMAIN", f"{item.normalized} no debe ser BLOCK_DOMAIN"
    url = _by_value(items, "/sites/abused/doc")
    assert url.decision in {"REVIEW", "BLOCK_URL_EXACT"}


# --- Modelo de evidencia y campos nuevos --------------------------------------

def test_evidence_model_fields_present():
    context = (
        "La redirección final termina en portal-secure-login.xyz, que suplanta Meta, "
        "solicita credenciales y fue registrado hace 3 días."
    )
    item = _run(context, "portal-secure-login[.]xyz")[0]
    assert item.decision == "BLOCK_DOMAIN"
    assert item.confidence in {"Alta", "Media", "Baja"}
    assert item.block_value == "portal-secure-login.xyz"
    assert item.positive_signals
    assert item.score_breakdown
    assert item.why_blockable
    assert "context_analysis" in item.sources_used
    assert len(item.reason) > 80, "el motivo debe ser detallado, no genérico"


def test_global_context_signals_alone_do_not_block_unrelated_iocs():
    # Dos infraestructuras distintas: las señales de una frase sin mención
    # explícita no deben permitir bloquear un IOC no relacionado.
    context = (
        "Se detecta phishing con captura de credenciales en la campaña. "
        "El sitio final es la landing final maligna-final.top que suplanta Meta. "
        "También se observó otro-dominio-neutro.com en las cabeceras."
    )
    items = _run(context, "maligna-final[.]top\notro-dominio-neutro[.]com")
    bad = _by_value(items, "maligna-final.top")
    neutral = _by_value(items, "otro-dominio-neutro.com")
    assert bad.decision == "BLOCK_DOMAIN"
    assert neutral.decision != "BLOCK_DOMAIN"


def test_recent_domain_alone_stays_review():
    items = _run("El dominio fue creado hace 3 días.", "new-example-login.biz")
    assert items[0].decision == "REVIEW"


def test_email_auth_passed_reduces_score():
    context = "El remitente notifications@known-vendor.com presenta SPF passed, DKIM válido y DMARC passed."
    item = _run(context, "notifications@known-vendor[.]com")[0]
    assert "email_auth_passed" in item.negative_signals
    assert item.decision in {"REVIEW", "DO_NOT_BLOCK"}
    assert item.decision != "BLOCK_SENDER_EXACT"
