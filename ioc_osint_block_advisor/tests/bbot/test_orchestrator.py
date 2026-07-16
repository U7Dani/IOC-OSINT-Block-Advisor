from integrations.bbot import orchestrator
from integrations.bbot.models import (
    RUN_COMPLETED,
    RUN_FAILED,
    BBOTCapabilities,
    BBOTRuntimeStatus,
    BBOTScanConfig,
    BBOTScanResult,
)
from integrations.bbot.settings import BBOTSettings


def _settings(tmp_path):
    orchestrator.invalidate_capabilities_cache()
    return BBOTSettings(workdir=str(tmp_path / "bbot_work"))


def test_run_scan_fails_gracefully_when_runtime_unavailable(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=False, reason="BBOT no encontrado"),
    )
    config = BBOTScanConfig(target="example.com")
    result = orchestrator.run_scan(config, settings)
    assert result.status == RUN_FAILED
    assert "BBOT no encontrado" in result.errors[0]


def test_run_scan_invalid_target_fails_without_raising(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0"),
    )
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.get_capabilities",
        lambda s, runtime=None, force_refresh=False: BBOTCapabilities(loaded=True),
    )
    config = BBOTScanConfig(target="example.com; rm -rf /")
    result = orchestrator.run_scan(config, settings)
    assert result.status == RUN_FAILED
    assert result.errors


def test_run_scan_uses_runner_and_caches_completed_result(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0"),
    )
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.get_capabilities",
        lambda s, runtime=None, force_refresh=False: BBOTCapabilities(loaded=True),
    )

    call_count = {"n": 0}

    class FakeRunner:
        def __init__(self, argv, **kwargs):
            call_count["n"] += 1

        def run(self):
            return BBOTScanResult(scan_id="s1", status=RUN_COMPLETED)

    monkeypatch.setattr("integrations.bbot.orchestrator.BBOTRunner", FakeRunner)

    config = BBOTScanConfig(target="example.com", use_cache=True)
    result1 = orchestrator.run_scan(config, settings)
    assert result1.status == RUN_COMPLETED
    assert call_count["n"] == 1

    # Second call with the same config should hit the cache, not the runner.
    result2 = orchestrator.run_scan(config, settings)
    assert result2.status == RUN_COMPLETED
    assert result2.from_cache is True
    assert call_count["n"] == 1


def test_run_scan_force_refresh_bypasses_cache(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.detect_runtime",
        lambda s: BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0"),
    )
    monkeypatch.setattr(
        "integrations.bbot.orchestrator.get_capabilities",
        lambda s, runtime=None, force_refresh=False: BBOTCapabilities(loaded=True),
    )
    call_count = {"n": 0}

    class FakeRunner:
        def __init__(self, argv, **kwargs):
            call_count["n"] += 1

        def run(self):
            return BBOTScanResult(scan_id="s1", status=RUN_COMPLETED)

    monkeypatch.setattr("integrations.bbot.orchestrator.BBOTRunner", FakeRunner)

    config = BBOTScanConfig(target="example.com", use_cache=True)
    orchestrator.run_scan(config, settings)
    config_refresh = BBOTScanConfig(target="example.com", use_cache=True, force_refresh=True)
    orchestrator.run_scan(config_refresh, settings)
    assert call_count["n"] == 2


def test_get_capabilities_is_cached_per_backend_version(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    calls = {"n": 0}

    def fake_discover(runtime, s):
        calls["n"] += 1
        return BBOTCapabilities(loaded=True, version=runtime.version)

    monkeypatch.setattr("integrations.bbot.orchestrator.discover_capabilities", fake_discover)
    runtime = BBOTRuntimeStatus(available=True, backend="native", version="3.1.0")
    orchestrator.get_capabilities(settings, runtime=runtime)
    orchestrator.get_capabilities(settings, runtime=runtime)
    assert calls["n"] == 1
    orchestrator.get_capabilities(settings, runtime=runtime, force_refresh=True)
    assert calls["n"] == 2
