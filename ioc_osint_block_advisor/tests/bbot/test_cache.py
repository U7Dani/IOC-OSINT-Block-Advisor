import time

from integrations.bbot.cache import (
    cache_key,
    clear_cache,
    load_cached_result,
    store_cached_result,
)
from integrations.bbot.models import BBOTScanConfig, BBOTScanResult, RUN_COMPLETED
from integrations.bbot.settings import BBOTSettings


def _settings(tmp_path, ttl=3600):
    return BBOTSettings(workdir=str(tmp_path), cache_ttl_seconds=ttl)


def test_cache_key_differs_by_profile():
    base = BBOTScanConfig(target="example.com", profile="soc_passive")
    deep = BBOTScanConfig(target="example.com", profile="soc_passive_deep")
    assert cache_key(base, "native", "3.1.0") != cache_key(deep, "native", "3.1.0")


def test_cache_key_differs_by_modules():
    a = BBOTScanConfig(target="example.com", modules=["dnsresolve"])
    b = BBOTScanConfig(target="example.com", modules=["portscan"])
    assert cache_key(a, "native", "3.1.0") != cache_key(b, "native", "3.1.0")


def test_cache_key_stable_for_same_config():
    a = BBOTScanConfig(target="Example.COM", modules=["b", "a"])
    b = BBOTScanConfig(target="example.com", modules=["a", "b"])
    assert cache_key(a, "native", "3.1.0") == cache_key(b, "native", "3.1.0")


def test_store_and_load_round_trip(tmp_path):
    settings = _settings(tmp_path)
    config = BBOTScanConfig(target="example.com")
    key = cache_key(config, "native", "3.1.0")
    result = BBOTScanResult(scan_id="s1", status=RUN_COMPLETED, warnings=["w1"])
    store_cached_result(settings, key, result)
    loaded = load_cached_result(settings, key)
    assert loaded is not None
    assert loaded.status == RUN_COMPLETED
    assert loaded.warnings == ["w1"]
    assert loaded.from_cache is True


def test_cache_expires_after_ttl(tmp_path):
    settings = _settings(tmp_path, ttl=1)
    config = BBOTScanConfig(target="example.com")
    key = cache_key(config, "native", "3.1.0")
    result = BBOTScanResult(scan_id="s1", status=RUN_COMPLETED)
    store_cached_result(settings, key, result)
    time.sleep(1.2)
    assert load_cached_result(settings, key) is None


def test_missing_cache_entry_returns_none(tmp_path):
    settings = _settings(tmp_path)
    assert load_cached_result(settings, "does-not-exist") is None


def test_clear_cache_removes_all_entries(tmp_path):
    settings = _settings(tmp_path)
    for i in range(3):
        config = BBOTScanConfig(target=f"example{i}.com")
        key = cache_key(config, "native", "3.1.0")
        store_cached_result(settings, key, BBOTScanResult(scan_id=f"s{i}", status=RUN_COMPLETED))
    removed = clear_cache(settings)
    assert removed == 3
    config = BBOTScanConfig(target="example0.com")
    assert load_cached_result(settings, cache_key(config, "native", "3.1.0")) is None


def test_cache_never_stores_secret_looking_values(tmp_path):
    settings = _settings(tmp_path)
    config = BBOTScanConfig(target="example.com")
    key = cache_key(config, "native", "3.1.0")
    result = BBOTScanResult(scan_id="s1", status=RUN_COMPLETED, warnings=["some warning, no secrets here"])
    path = store_cached_result(settings, key, result)
    content = path.read_text(encoding="utf-8")
    assert "API_KEY" not in content.upper() or "api_key" not in content
