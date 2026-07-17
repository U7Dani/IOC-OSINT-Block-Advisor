import os

from integrations.bbot.settings import BBOTSettings, load_settings, redact, save_settings


def test_default_settings_are_safe_by_default():
    settings = BBOTSettings()
    assert settings.runtime == "auto"
    assert settings.default_profile == "soc_passive"


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "bbot_settings.json"
    settings = BBOTSettings(runtime="wsl", wsl_distribution="Ubuntu", timeout_seconds=120)
    save_settings(settings, path)
    loaded = load_settings(path)
    assert loaded.runtime == "wsl"
    assert loaded.wsl_distribution == "Ubuntu"
    assert loaded.timeout_seconds == 120


def test_load_settings_missing_file_returns_defaults(tmp_path):
    loaded = load_settings(tmp_path / "does_not_exist.json")
    assert loaded == BBOTSettings()


def test_load_settings_corrupt_file_returns_defaults(tmp_path):
    path = tmp_path / "bbot_settings.json"
    path.write_text("{not valid json", encoding="utf-8")
    loaded = load_settings(path)
    assert loaded == BBOTSettings()


def test_settings_file_never_contains_api_key_fields():
    settings = BBOTSettings()
    data = settings.to_dict()
    for key in data:
        assert "api_key" not in key.lower()
        assert "secret" not in key.lower()
        assert "token" not in key.lower()


def test_redact_masks_known_env_var_values(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "supersecretvalue123")
    text = "running with SHODAN_API_KEY=supersecretvalue123 in env"
    redacted = redact(text)
    assert "supersecretvalue123" not in redacted
    assert "REDACTED" in redacted


def test_redact_masks_generic_key_value_patterns():
    text = "api_key: abcd1234efgh5678"
    redacted = redact(text)
    assert "abcd1234efgh5678" not in redacted


def test_redact_does_not_alter_unrelated_text():
    text = "resolved 3 subdomains for example.com"
    assert redact(text) == text
