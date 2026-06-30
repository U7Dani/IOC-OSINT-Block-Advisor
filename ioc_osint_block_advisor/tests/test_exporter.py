from modules.classifier import classify_many
from modules.decision_engine import decide_many
from modules.exporter import export_results
from modules.extractor import extract_iocs
from modules.utils import load_allowlist


def _run(context: str, iocs: str):
    extracted = extract_iocs(context, iocs)
    classified = classify_many(extracted, context, load_allowlist())
    return decide_many(classified)


def test_export_blocklists_only_include_block_decisions(tmp_path):
    context = "La URL redirige finalmente a un portal de login que suplanta a Meta y solicita credenciales. El dominio fue creado hace 7 días."
    items = []
    items.extend(_run("", "noreply-zoomevents@zoom.us"))
    items.extend(_run("", "j.richards@copromopro[.]biz"))
    items.extend(_run("", "hxxps[://]events[.]zoom[.]us/e/view/test"))
    items.extend(_run(context, "hxxps[://]login[.]workportalsso[.]com/"))

    files = export_results(items, context, tmp_path)

    assert "login.workportalsso.com" in files["domains"].read_text(encoding="utf-8")
    assert "zoom.us" not in files["domains"].read_text(encoding="utf-8")
    assert files["senders"].read_text(encoding="utf-8") == ""
    assert "events.zoom.us" not in files["urls"].read_text(encoding="utf-8")
    assert "j.richards@copromopro.biz" not in files["senders"].read_text(encoding="utf-8")
