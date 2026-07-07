"""Tests de la capa de allowlist de cliente (Fluidra) y motor v3.

Casos A–I de la especificación:
A. Dominios/senders de Fluidra protegidos.
B. Tenant SharePoint de Fluidra protegido.
C. SharePoint genérico abusado: nunca BLOCK_DOMAIN.
D. Landing final que suplanta a Fluidra: BLOCK_DOMAIN (no confundir con Fluidra legítimo).
E. Sender legítimo de Fluidra: DO_NOT_BLOCK.
F. Sender externo que suplanta a Fluidra: REVIEW salvo evidencia fuerte.
G. SaaS legítimo con URL abusada: no BLOCK_DOMAIN.
H. OSINT deshabilitado: sin servicios externos, fuentes locales marcadas.
I. Export: solo BLOCK_* en blocklists.
"""

import pytest

from modules import osint_runner
from modules.classifier import classify_many
from modules.decision_engine import decide_many, gates
from modules.exporter import export_results
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


# --- A. Fluidra domain protected ---------------------------------------------

def test_a_fluidra_domains_and_sender_protected():
    context = "El correo pertenece a una comunicación legítima de Fluidra."
    items = _run(context, "fluidra.com\nportal.fluidra.com\nusuario@fluidra.com")
    for item in items:
        assert item.decision in {"DO_NOT_BLOCK", "REVIEW"}, item.normalized
        assert item.decision not in {"BLOCK_DOMAIN", "BLOCK_SENDER_EXACT"}
        assert item.false_positive_risk == "Alto"
        low = item.reason.lower()
        assert "fluidra" in low or "cliente" in low or "allowlist" in low
    sender = _by_value(items, "usuario@fluidra.com")
    assert sender.is_client_sender_flag
    assert sender.decision == "DO_NOT_BLOCK"
    assert _by_value(items, "portal.fluidra.com").is_client_allowlisted


# --- B. Fluidra SharePoint tenant protected -----------------------------------

def test_b_fluidra_sharepoint_tenant_protected():
    context = "El enlace pertenece al SharePoint corporativo legítimo de Fluidra."
    items = _run(context, "hxxps[://]fluidra[.]sharepoint[.]com/sites/test")
    url = _by_value(items, "fluidra.sharepoint.com/sites/test")
    assert url.is_tenant
    assert url.decision in {"DO_NOT_BLOCK", "REVIEW"}
    assert url.decision != "BLOCK_DOMAIN"
    assert "fluidra" in url.reason.lower() or "tenant" in url.reason.lower()
    for item in items:
        assert item.decision != "BLOCK_DOMAIN"


# --- C. SharePoint genérico abusado --------------------------------------------

def test_c_generic_sharepoint_abused_never_block_domain():
    context = (
        "Se observa una URL de SharePoint usada como redirección inicial en una campaña de "
        "phishing, posteriormente redirige a dominio externo malicioso."
    )
    items = _run(context, "hxxps[://]exampletenant[.]sharepoint[.]com/sites/x")
    url = _by_value(items, "exampletenant.sharepoint.com")
    assert not url.is_tenant, "un tenant genérico no debe heredar la protección de cliente"
    assert url.is_trusted_saas
    assert url.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    assert url.decision != "BLOCK_DOMAIN"


def test_c_generic_sharepoint_confirmed_abuse_allows_exact_url_block():
    context = "La URL de SharePoint tiene abuso confirmado: aloja phishing con captura de credenciales."
    items = _run(context, "hxxps[://]exampletenant[.]sharepoint[.]com/sites/x")
    url = _by_value(items, "exampletenant.sharepoint.com")
    assert url.decision == "BLOCK_URL_EXACT"
    assert url.block_value == url.normalized
    for item in items:
        assert item.decision != "BLOCK_DOMAIN"


# --- D. Landing final que suplanta a Fluidra -----------------------------------

def test_d_lookalike_fluidra_landing_blocks_domain():
    context = (
        "La redirección final termina en login-fluidra-security.example, que suplanta a "
        "Fluidra y solicita credenciales. Dominio registrado recientemente."
    )
    items = _run(context, "login-fluidra-security.example")
    item = _by_value(items, "login-fluidra-security.example")
    # Contiene la marca pero NO pertenece a Fluidra: es suplantación, no protección.
    assert not item.is_client_allowlisted
    assert "brand_impersonation" in item.positive_signals
    assert item.decision == "BLOCK_DOMAIN"
    assert item.role == "landing_final"
    assert item.false_positive_risk in {"Bajo", "Medio-Bajo"}


def test_d_homoglyph_lookalike_detected():
    context = "La redirección final termina en flu1dra-portal.top, que solicita credenciales y suplanta a Fluidra."
    item = _run(context, "flu1dra-portal.top")[0]
    assert "brand_impersonation" in item.positive_signals
    assert item.decision == "BLOCK_DOMAIN"


# --- E. Sender Fluidra legítimo -------------------------------------------------

def test_e_fluidra_sender_do_not_block():
    items = _run("", "soporte@fluidra.com")
    sender = _by_value(items, "soporte@fluidra.com")
    assert sender.decision == "DO_NOT_BLOCK"
    assert sender.false_positive_risk == "Alto"
    assert "fluidra" in sender.reason.lower() or "protegid" in sender.reason.lower()


# --- F. Sender externo que suplanta a Fluidra -----------------------------------

def test_f_external_sender_impersonating_fluidra():
    context = "El correo fue enviado por support@fluidra-secure-login.example y suplanta a Fluidra."
    items = _run(context, "support@fluidra-secure-login[.]example")
    sender = _by_value(items, "support@fluidra-secure-login.example")
    assert not sender.is_client_sender_flag
    assert sender.decision in {"REVIEW", "BLOCK_SENDER_EXACT"}
    # Sin confirmación OSINT no debe bloquearse el sender automáticamente.
    assert sender.decision == "REVIEW"
    assert sender.review_priority in {"alta", "media"}


# --- G. SaaS legítimo con URL abusada -------------------------------------------

def test_g_saas_url_in_phishing_chain_never_block_domain():
    context = (
        "La URL de Dropbox incluida en el correo inicia una cadena de redirecciones que "
        "posteriormente dirige a un sitio externo de phishing con captura de credenciales."
    )
    items = _run(context, "hxxps[://]www[.]dropbox[.]com/scl/fi/test")
    url = _by_value(items, "dropbox.com/scl/fi/test")
    assert url.decision in {"REVIEW", "BLOCK_URL_EXACT"}
    for item in items:
        assert item.decision != "BLOCK_DOMAIN"


# --- H. OSINT deshabilitado -------------------------------------------------------

def test_h_osint_disabled_marks_local_sources_only():
    item = _run("El dominio observado no presenta actividad conocida.", "ejemplo-neutro.com")[0]
    assert item.osint_results == []
    assert "local_rules" in item.sources_used
    assert "context_analysis" in item.sources_used
    assert "osint_externo:no_consultado" in item.sources_used
    assert "OSINT externo no consultado" in item.analyst_reasoning


def test_h_osint_runner_does_not_send_full_urls_by_default(monkeypatch):
    calls = {}

    def fake(source, capture_value=None):
        def _q(*args):
            calls.setdefault(source, []).append(args)
            return {"source": source, "status": "clean", "score_delta": 0, "evidence": "stub"}
        return _q

    monkeypatch.setattr(osint_runner.osint_dns, "query", fake("dns"))
    monkeypatch.setattr(osint_runner.osint_rdap, "query", fake("rdap"))
    monkeypatch.setattr(osint_runner.osint_crtsh, "query", fake("crtsh"))
    monkeypatch.setattr(osint_runner.osint_urlhaus, "query", fake("urlhaus"))
    monkeypatch.setattr(osint_runner.osint_threatfox, "query", fake("threatfox"))
    monkeypatch.setattr(osint_runner.osint_otx, "query", fake("otx"))

    def fail(*args):  # urlscan/phishtank no deben invocarse por defecto
        raise AssertionError("No debe enviarse la URL completa a terceros por defecto")

    monkeypatch.setattr(osint_runner.osint_urlscan, "query", fail)
    monkeypatch.setattr(osint_runner.osint_phishtank, "query", fail)

    items = classify_many(extract_iocs("", "hxxps[://]sitio-prueba[.]example/ruta/secreta?token=abc"), "", load_allowlist())
    results = osint_runner.collect(items[0], include_url_lookups=False)

    full_url = items[0].normalized
    for source, arg_calls in calls.items():
        for args in arg_calls:
            assert full_url not in args, f"{source} recibió la URL completa"
    statuses = {r["source"]: r["status"] for r in results}
    assert statuses.get("urlscan") == "not_checked"
    assert statuses.get("phishtank") == "not_checked"


# --- I. Export -----------------------------------------------------------------

def test_i_export_blocklists_only_block_decisions(tmp_path):
    context = (
        "La redirección final termina en login-fluidra-security.example, que suplanta a "
        "Fluidra y solicita credenciales. Dominio registrado recientemente. "
        "El correo pertenece a una comunicación legítima de Fluidra desde soporte@fluidra.com."
    )
    items = []
    items.extend(_run(context, "login-fluidra-security.example"))
    items.extend(_run("El correo pertenece a una comunicación legítima de Fluidra.", "soporte@fluidra.com\nfluidra.com"))
    items.extend(_run("", "hxxps[://]events[.]zoom[.]us/e/view/test"))

    files = export_results(items, context, tmp_path)
    domains = files["domains"].read_text(encoding="utf-8")
    assert "login-fluidra-security.example" in domains
    assert "fluidra.com\n" not in domains.replace("login-fluidra-security.example", "")
    assert "zoom.us" not in domains
    assert files["senders"].read_text(encoding="utf-8") == ""
    assert files["urls"].read_text(encoding="utf-8") == ""
    review = files["review"].read_text(encoding="utf-8")
    assert "DO_NOT_BLOCK" not in files["domains"].read_text(encoding="utf-8")


# --- Gating y review_only ---------------------------------------------------------

def test_gates_reported_in_reasoning():
    context = "La redirección final termina en portal-malo.top, que suplanta Meta y solicita credenciales."
    item = _run(context, "portal-malo.top")[0]
    g = gates(item)
    assert g["required_direct_malicious_signal"] is True
    assert g["is_client_protected"] is False
    assert "Gates activos" in item.analyst_reasoning


def test_review_only_domain_never_blocks(tmp_path, monkeypatch):
    from modules import classifier as classifier_mod
    monkeypatch.setattr(classifier_mod, "load_review_only", lambda: {"dominio-vigilado.com"})
    context = "La redirección final termina en dominio-vigilado.com, que suplanta Meta, solicita credenciales y fue registrado recientemente."
    extracted = extract_iocs(context, "dominio-vigilado.com")
    items = decide_many(classify_many(extracted, context, load_allowlist()))
    item = items[0]
    assert item.is_review_only_flag
    assert item.decision == "REVIEW"
    assert item.review_priority == "alta"
    assert item.decision != "BLOCK_DOMAIN"
