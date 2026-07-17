from integrations.bbot.health import run_health_check
from integrations.bbot.models import BBOTCapabilities, BBOTRuntimeStatus
from integrations.bbot.settings import BBOTSettings


def test_health_check_explains_missing_runtime(monkeypatch, tmp_path):
    settings = BBOTSettings(workdir=str(tmp_path))
    monkeypatch.setattr(
        "integrations.bbot.health.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=False, reason="Ejecutable 'bbot' no encontrado en PATH."),
    )
    report = run_health_check(settings)
    assert report.ok is False
    assert any("no encontrado" in p for p in report.problems)


def test_health_check_ok_when_everything_available(monkeypatch, tmp_path):
    settings = BBOTSettings(workdir=str(tmp_path))
    monkeypatch.setattr(
        "integrations.bbot.health.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0"),
    )
    monkeypatch.setattr(
        "integrations.bbot.health.discover_capabilities",
        lambda runtime, s: BBOTCapabilities(loaded=True, version="3.1.0"),
    )
    report = run_health_check(settings)
    assert report.ok is True
    assert report.workdir_writable is True
    assert not report.problems


def test_health_check_reports_capability_warnings(monkeypatch, tmp_path):
    settings = BBOTSettings(workdir=str(tmp_path))
    monkeypatch.setattr(
        "integrations.bbot.health.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0"),
    )
    monkeypatch.setattr(
        "integrations.bbot.health.discover_capabilities",
        lambda runtime, s: BBOTCapabilities(loaded=False, warnings=["no se pudo listar módulos"]),
    )
    report = run_health_check(settings)
    assert report.ok is False
    assert "no se pudo listar módulos" in report.problems


def test_health_check_never_raises_on_unwritable_workdir(monkeypatch):
    settings = BBOTSettings(workdir="Z:\\this\\path\\should\\not\\exist\\hopefully")
    monkeypatch.setattr(
        "integrations.bbot.health.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=False, reason="no disponible"),
    )
    report = run_health_check(settings)
    assert isinstance(report.workdir_writable, bool)
