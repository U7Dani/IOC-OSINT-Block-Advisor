"""Tests de la ampliación de investigación OSINT (VirusTotal, AbuseIPDB) y
del resumen de ticket enriquecido con protección/confianza/fuentes.

Numeración según la especificación de la mejora UI/OSINT:
1-6. cubiertos en test_client_allowlist.py (Fluidra, SharePoint, SaaS, sender).
7. VirusTotal malicioso.
8. AbuseIPDB hit alto.
9. OSINT externo deshabilitado (ver también test_client_allowlist.py::test_h_*).
10. URL completa no enviada por defecto (ver también test_client_allowlist.py).
11. Exportación solo BLOCK_* (ver también test_client_allowlist.py::test_i_*).
12. Integración de nuevas fuentes sin red real usando mocks.
13. Resumen para ticket contiene protección, confianza y fuentes OSINT.
"""

from __future__ import annotations

from modules import osint_abuseipdb, osint_runner, osint_virustotal
from modules.classifier import classify_many
from modules.decision_engine import decide_many, apply_osint_score
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


def _classify(context: str, iocs: str):
    extracted = extract_iocs(context, iocs)
    return classify_many(extracted, context, load_allowlist())


def _run(context: str, iocs: str):
    return decide_many(_classify(context, iocs))


# --- 7. VirusTotal malicioso -----------------------------------------------

def test_virustotal_no_key_configured_is_skipped_not_invented(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(osint_virustotal, "load_dotenv", lambda: None)
    result = osint_virustotal.query("dominio-cualquiera.com", "domain")
    assert result["status"] == "skipped"
    assert result["score_delta"] == 0


def test_virustotal_hit_becomes_strong_signal(monkeypatch):
    def stub(source):
        def _q(*args):
            return {"source": source, "status": "clean", "score_delta": 0, "evidence": "stub"}
        return _q

    def fake_vt(value, ioc_type):
        return {"source": "virustotal", "status": "hit", "score_delta": 50, "evidence": "VirusTotal: 12/70 motores maliciosos"}

    monkeypatch.setattr(osint_runner.osint_dns, "query", stub("dns"))
    monkeypatch.setattr(osint_runner.osint_rdap, "query", stub("rdap"))
    monkeypatch.setattr(osint_runner.osint_crtsh, "query", stub("crtsh"))
    monkeypatch.setattr(osint_runner.osint_urlhaus, "query", lambda *a: {"source": "urlhaus", "status": "not_found", "score_delta": 0, "evidence": "stub"})
    monkeypatch.setattr(osint_runner.osint_threatfox, "query", stub("threatfox"))
    monkeypatch.setattr(osint_runner.osint_otx, "query", lambda *a: {"source": "otx", "status": "not_found", "score_delta": 0, "evidence": "stub"})
    monkeypatch.setattr(osint_runner.osint_virustotal, "query", fake_vt)

    context = "Dominio observado sin contexto adicional."
    items = _classify(context, "dominio-vt-malo.example")
    item = items[0]
    score_before = item.score
    osint_runner.collect(item, include_url_lookups=False)
    apply_osint_score(item)
    assert any(r["source"] == "virustotal" and r["verdict"] == "malicious" for r in item.osint_results)
    assert item.score == score_before + 50


# --- 8. AbuseIPDB hit alto ---------------------------------------------------

def test_abuseipdb_no_key_is_skipped(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr(osint_abuseipdb, "load_dotenv", lambda: None)
    result = osint_abuseipdb.query("203.0.113.7")
    assert result["status"] == "skipped"


def test_abuseipdb_high_score_flags_ip_as_malicious(monkeypatch):
    def fake_query(ip):
        return {"source": "abuseipdb", "status": "hit", "score_delta": 45, "evidence": "AbuseIPDB: confidence=97%, reports=40"}

    monkeypatch.setattr(osint_runner.osint_abuseipdb, "query", fake_query)
    monkeypatch.setattr(osint_runner.osint_threatfox, "query", lambda *a: {"source": "threatfox", "status": "not_found", "score_delta": 0, "evidence": "stub"})
    monkeypatch.setattr(osint_runner.osint_otx, "query", lambda *a: {"source": "otx", "status": "skipped", "score_delta": 0, "evidence": "stub"})
    monkeypatch.setattr(osint_runner.osint_virustotal, "query", lambda *a: {"source": "virustotal", "status": "skipped", "score_delta": 0, "evidence": "stub"})
    items = _classify("IP observada en los logs.", "203.0.113.7")
    item = items[0]
    osint_runner.collect(item, include_url_lookups=False)
    apply_osint_score(item)
    decided = decide_many([item])[0]
    assert any(r["source"] == "abuseipdb" and r["verdict"] == "malicious" for r in decided.osint_results)
    # La herramienta nunca exporta blocklist de IPs: máximo REVIEW con prioridad alta.
    assert decided.decision == "REVIEW"
    assert decided.review_priority == "alta"


# --- 12. Integración de nuevas fuentes sin red real -------------------------

def test_osint_collect_uses_all_providers_for_domain(monkeypatch):
    seen_sources = []

    def make_stub(source):
        def _q(*args):
            seen_sources.append(source)
            return {"source": source, "status": "clean", "score_delta": 0, "evidence": "stub"}
        return _q

    monkeypatch.setattr(osint_runner.osint_dns, "query", make_stub("dns"))
    monkeypatch.setattr(osint_runner.osint_rdap, "query", make_stub("rdap"))
    monkeypatch.setattr(osint_runner.osint_crtsh, "query", make_stub("crtsh"))
    monkeypatch.setattr(osint_runner.osint_urlhaus, "query", make_stub("urlhaus"))
    monkeypatch.setattr(osint_runner.osint_threatfox, "query", make_stub("threatfox"))
    monkeypatch.setattr(osint_runner.osint_otx, "query", make_stub("otx"))
    monkeypatch.setattr(osint_runner.osint_virustotal, "query", make_stub("virustotal"))

    item = _classify("", "dominio-de-prueba.example")[0]
    results = osint_runner.collect(item, include_url_lookups=False)

    sources = {r["source"] for r in results}
    assert {"dns", "rdap", "crtsh", "urlhaus", "threatfox", "otx", "virustotal"} <= sources
    for r in results:
        assert set(("provider", "checked", "artifact_type", "verdict", "confidence", "details", "error")) <= set(r.keys())
        assert r["verdict"] in osint_runner.VERDICTS


def test_osint_collect_ip_includes_abuseipdb_and_virustotal(monkeypatch):
    calls = []

    def stub(source):
        def _q(*args):
            calls.append(source)
            return {"source": source, "status": "not_found", "score_delta": 0, "evidence": "stub"}
        return _q

    monkeypatch.setattr(osint_runner.osint_abuseipdb, "query", stub("abuseipdb"))
    monkeypatch.setattr(osint_runner.osint_virustotal, "query", stub("virustotal"))
    monkeypatch.setattr(osint_runner.osint_threatfox, "query", stub("threatfox"))
    monkeypatch.setattr(osint_runner.osint_otx, "query", stub("otx"))

    item = _classify("", "203.0.113.9")[0]
    osint_runner.collect(item, include_url_lookups=False)
    assert "abuseipdb" in calls
    assert "virustotal" in calls


def test_osint_email_never_invents_verdict(monkeypatch):
    def stub(source):
        def _q(*args):
            return {"source": source, "status": "clean", "score_delta": 0, "evidence": "stub"}
        return _q

    monkeypatch.setattr(osint_runner.osint_dns, "query", stub("dns"))
    monkeypatch.setattr(osint_runner.osint_rdap, "query", stub("rdap"))
    monkeypatch.setattr(osint_runner.osint_crtsh, "query", stub("crtsh"))

    item = _classify("", "usuario@dominio-sin-fuente.example")[0]
    results = osint_runner.collect(item, include_url_lookups=False)
    email_result = next(r for r in results if r["source"] == "email_reputation")
    assert email_result["status"] == "skipped"
    assert email_result["verdict"] == "not_checked"


# --- 13. Resumen para ticket con protección, confianza y fuentes -----------

def test_ticket_summary_fields_available_for_ui(monkeypatch):
    """No probamos la GUI (headless), pero sí que ClassifiedIOC expone todos
    los campos que main.copy_ticket_summary necesita para construir el
    resumen (protected_by/protection label, confidence, sources_used)."""
    item = _run("El correo pertenece a una comunicación legítima de Fluidra.", "usuario@fluidra.com")[0]
    assert item.protected_by == "client_allowlist"
    assert item.confidence
    assert isinstance(item.sources_used, list) and item.sources_used
    assert "local_rules" in item.sources_used
    assert item.soc_conclusion
    assert item.analyst_reasoning
