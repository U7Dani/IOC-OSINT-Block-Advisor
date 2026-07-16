from pathlib import Path

from integrations.bbot.discovery import (
    _CapturedRun,
    _decode_output,
    backend_prefix,
    detect_runtime,
    discover_capabilities,
    parse_flag_listing,
    parse_module_listing,
    parse_module_option_listing,
    parse_output_module_listing,
    parse_preset_listing,
)
from integrations.bbot.models import BBOTRuntimeStatus
from integrations.bbot.settings import BBOTSettings

# Fixtures below are sanitized, real `bbot --version`/`-l`/`-lp`/`-lo`/`-lf`/
# `-lmo` output captured from an actual BBOT 3.0.0 install (pipx, inside a
# WSL2 Ubuntu-24.04 distro) during manual validation - see
# tests/bbot/fixtures/ and the validation report for details. No personal
# paths, usernames, or secrets are present (this is BBOT's own static
# module/preset catalog).
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


REAL_MODULE_LISTING = _fixture("bbot_modules_real.txt")
REAL_PRESET_LISTING = _fixture("bbot_presets_real.txt")
REAL_OUTPUT_MODULE_LISTING = _fixture("bbot_outputs_real.txt")
REAL_FLAG_LISTING = _fixture("bbot_flags_real.txt")
REAL_MODULE_OPTION_LISTING = _fixture("bbot_module_options_real.txt")
REAL_VERSION_OUTPUT = _fixture("bbot_version_real.txt")


def test_parse_module_listing_against_real_bbot_output():
    modules, warnings = parse_module_listing(REAL_MODULE_LISTING)
    assert not warnings
    # Known-real module names, sampled across the catalog (see FASE 4 of the
    # validation brief): crt (passive, no key), portscan (active),
    # virustotal/otx/urlscan (present, API key required).
    for name in ("crt", "sslcert", "portscan", "http", "virustotal", "otx", "urlscan", "subdomaincenter"):
        assert name in modules, f"expected real module {name!r} to be present"

    assert modules["crt"].passive is True
    assert modules["crt"].active is False
    assert modules["crt"].auth_required is False

    assert modules["portscan"].active is True
    assert modules["portscan"].passive is False

    assert modules["virustotal"].auth_required is True
    assert modules["otx"].auth_required is True

    # dnsbrute is loud (brute force) - must not be misclassified as safe-only passive.
    assert modules["dnsbrute"].active is True
    assert modules["dnsbrute"].loud is True


def test_parse_module_listing_description_does_not_leak_into_flags():
    modules, _ = parse_module_listing(REAL_MODULE_LISTING)
    crt = modules["crt"]
    # Flags must come only from the "Flags" column, never from words that
    # happen to appear in the free-text "Description" column.
    assert crt.flags <= {
        "affiliates", "aggressive", "safe", "passive", "active", "loud",
        "invasive", "subdomain-enum", "cloud-enum", "email-enum", "web",
        "web-heavy", "web-screenshots", "portscan", "service-enum",
        "code-enum", "download", "iis-shortnames", "baddns",
        "subdomain-hijack", "social-enum", "slow",
    }


def test_parse_module_listing_handles_empty_output():
    modules, warnings = parse_module_listing("")
    assert modules == {}
    assert warnings


def test_parse_preset_listing_against_real_bbot_output():
    presets, warnings = parse_preset_listing(REAL_PRESET_LISTING)
    assert not warnings
    for name in ("kitchen-sink", "subdomain-enum", "cloud-enum", "email-enum", "fast"):
        assert name in presets, f"expected real preset {name!r} to be present"
    assert "everywhere" in presets["kitchen-sink"].description.lower()


def test_parse_output_module_listing_against_real_bbot_output():
    out_modules, warnings = parse_output_module_listing(REAL_OUTPUT_MODULE_LISTING)
    assert not warnings
    for name in ("json", "csv", "sqlite", "splunk", "elastic", "neo4j"):
        assert name in out_modules, f"expected real output module {name!r} to be present"


def test_parse_flag_listing_against_real_bbot_output():
    flags, warnings = parse_flag_listing(REAL_FLAG_LISTING)
    assert not warnings
    for name in ("safe", "passive", "active", "loud", "invasive", "subdomain-enum"):
        assert name in flags, f"expected real flag {name!r} to be present"
    assert flags["passive"].module_count > 0
    assert "crt" in flags["passive"].modules or "dnsdumpster" in flags["passive"].modules


def test_parse_module_option_listing_against_real_bbot_output():
    options, warnings = parse_module_option_listing(REAL_MODULE_OPTION_LISTING)
    assert not warnings
    assert any(name.startswith("modules.baddns.") for name in options)
    sample = options.get("modules.baddns.min_confidence")
    assert sample is not None
    assert sample.default == "MEDIUM"


def test_real_version_output_is_a_bare_version_string():
    assert REAL_VERSION_OUTPUT.strip() == "3.0.0"


def test_decode_output_handles_wsl_utf16le_quirk():
    """Regression test: wsl.exe emits UTF-16LE on piped stdout/stderr (a
    real Windows/WSL interop quirk observed during manual validation on
    this machine, distinct from the guest Linux process's own encoding)."""
    raw = "BBOT 3.1.0\n".encode("utf-16-le")
    assert _decode_output(raw) == "BBOT 3.1.0\n"


def test_decode_output_handles_plain_utf8():
    raw = "BBOT 3.1.0\n".encode("utf-8")
    assert _decode_output(raw) == "BBOT 3.1.0\n"


def test_decode_output_handles_empty_bytes():
    assert _decode_output(b"") == ""


def test_backend_prefix_native_is_empty():
    settings = BBOTSettings(runtime="native")
    assert backend_prefix("native", settings) == []


def test_backend_prefix_wsl_includes_distribution():
    settings = BBOTSettings(runtime="wsl", wsl_distribution="Ubuntu")
    prefix = backend_prefix("wsl", settings)
    assert prefix[0] == "wsl.exe"
    assert "Ubuntu" in prefix
    assert prefix[-1] == "--"


def test_backend_prefix_docker_includes_image():
    settings = BBOTSettings(runtime="docker", docker_image="blacklanternsecurity/bbot:stable")
    prefix = backend_prefix("docker", settings)
    assert "docker" in prefix
    assert "blacklanternsecurity/bbot:stable" in prefix


def test_detect_runtime_disabled():
    settings = BBOTSettings(runtime="disabled")
    status = detect_runtime(settings)
    assert status.available is False
    assert "deshabilitad" in status.reason.lower()


def test_detect_runtime_native_not_found(monkeypatch):
    settings = BBOTSettings(runtime="native", executable="bbot-does-not-exist-xyz")
    monkeypatch.setattr("shutil.which", lambda name: None)
    status = detect_runtime(settings)
    assert status.available is False
    assert status.backend == "native"


def test_detect_runtime_native_success(monkeypatch):
    settings = BBOTSettings(runtime="native", executable="bbot")

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/bbot")

    def fake_run_capture(argv, timeout=20):
        return _CapturedRun(0, REAL_VERSION_OUTPUT, "")

    monkeypatch.setattr("integrations.bbot.discovery._run_capture", fake_run_capture)
    status = detect_runtime(settings)
    assert status.available is True
    assert status.version == "3.0.0"
    assert status.backend == "native"


def test_detect_runtime_auto_falls_back_through_backends(monkeypatch):
    settings = BBOTSettings(runtime="auto")
    calls = []

    def fake_probe(backend, settings_):
        calls.append(backend)
        if backend == "docker":
            return BBOTRuntimeStatus(available=True, backend="docker", version="3.0.0")
        return BBOTRuntimeStatus(available=False, backend=backend, reason="no disponible")

    monkeypatch.setattr("integrations.bbot.discovery._probe_backend", fake_probe)
    status = detect_runtime(settings)
    assert status.available is True
    assert status.backend == "docker"
    assert calls == ["native", "wsl", "docker"]


def test_discover_capabilities_returns_unavailable_when_runtime_missing():
    runtime = BBOTRuntimeStatus(available=False, reason="no encontrado")
    caps = discover_capabilities(runtime, BBOTSettings())
    assert caps.loaded is False
    assert "no encontrado" in caps.warnings[0]


def test_discover_capabilities_parses_all_real_listings(monkeypatch):
    runtime = BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.0.0")
    settings = BBOTSettings(runtime="native")

    responses = {
        ("bbot", "-l"): REAL_MODULE_LISTING,
        ("bbot", "-lp"): REAL_PRESET_LISTING,
        ("bbot", "-lo"): REAL_OUTPUT_MODULE_LISTING,
        ("bbot", "-lf"): REAL_FLAG_LISTING,
        ("bbot", "-lmo"): REAL_MODULE_OPTION_LISTING,
    }

    def fake_run_capture(argv, timeout=20):
        return _CapturedRun(0, responses.get(tuple(argv), ""), "")

    monkeypatch.setattr("integrations.bbot.discovery._run_capture", fake_run_capture)
    caps = discover_capabilities(runtime, settings)
    assert caps.loaded is True
    assert "crt" in caps.modules
    assert "kitchen-sink" in caps.presets
    assert "json" in caps.output_modules
    assert "passive" in caps.flags
    assert any(name.startswith("modules.") for name in caps.module_options)
    assert not caps.warnings
