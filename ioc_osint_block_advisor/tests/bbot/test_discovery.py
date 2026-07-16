from unittest.mock import patch

from integrations.bbot.discovery import (
    _CapturedRun,
    _decode_output,
    backend_prefix,
    detect_runtime,
    discover_capabilities,
    parse_module_listing,
    parse_output_module_listing,
    parse_preset_listing,
)
from integrations.bbot.models import BBOTRuntimeStatus
from integrations.bbot.settings import BBOTSettings

# Representative sample text loosely modeled on BBOT's published CLI output
# format. Not captured from a real installation (none is available in this
# environment) - used only to exercise the tolerant table parser.
SAMPLE_MODULE_LISTING = """
Module          Type      Needs API Key   Flags                        Description
------          ----      -------------   -----                        -----------
dnsresolve      internal  No              passive,safe                 Resolves DNS names
httpx           scan      No              active,safe,web-basic        Visits URLs and gathers info
portscan        scan      No              active,aggressive            Scans for open ports
shodan_dns      scan      Yes             passive,safe,subdomain-enum  Queries Shodan for subdomains
"""

SAMPLE_PRESET_LISTING = """
Preset            Category        # Modules   Description
------            --------        ---------   -----------
subdomain-enum    scanning        25          Enumerate subdomains
cloud-enum        scanning        12          Enumerate cloud assets
"""

SAMPLE_OUTPUT_MODULE_LISTING = """
Output Module     Description
-------------     -----------
json              Output events as JSON
csv               Output events as CSV
"""


def test_parse_module_listing_extracts_flags_and_safety():
    modules, warnings = parse_module_listing(SAMPLE_MODULE_LISTING)
    assert not warnings
    assert "dnsresolve" in modules
    assert modules["dnsresolve"].passive is True
    assert modules["dnsresolve"].active is False
    assert modules["portscan"].active is True
    assert modules["portscan"].invasive is True
    assert modules["shodan_dns"].auth_required is True


def test_parse_module_listing_handles_empty_output():
    modules, warnings = parse_module_listing("")
    assert modules == {}
    assert warnings


def test_parse_preset_listing():
    presets, warnings = parse_preset_listing(SAMPLE_PRESET_LISTING)
    assert not warnings
    assert "subdomain-enum" in presets
    assert "cloud-enum" in presets


def test_parse_output_module_listing():
    out_modules, warnings = parse_output_module_listing(SAMPLE_OUTPUT_MODULE_LISTING)
    assert not warnings
    assert "json" in out_modules
    assert "csv" in out_modules


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
        return _CapturedRun(0, "BBOT 3.1.0\n", "")

    monkeypatch.setattr("integrations.bbot.discovery._run_capture", fake_run_capture)
    status = detect_runtime(settings)
    assert status.available is True
    assert status.version == "3.1.0"
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


def test_discover_capabilities_parses_all_three_listings(monkeypatch):
    runtime = BBOTRuntimeStatus(available=True, backend="native", executable="bbot", version="3.1.0")
    settings = BBOTSettings(runtime="native")

    responses = {
        ("bbot", "-l"): SAMPLE_MODULE_LISTING,
        ("bbot", "-lp"): SAMPLE_PRESET_LISTING,
        ("bbot", "-lo"): SAMPLE_OUTPUT_MODULE_LISTING,
    }

    def fake_run_capture(argv, timeout=20):
        return _CapturedRun(0, responses.get(tuple(argv), ""), "")

    monkeypatch.setattr("integrations.bbot.discovery._run_capture", fake_run_capture)
    caps = discover_capabilities(runtime, settings)
    assert caps.loaded is True
    assert "dnsresolve" in caps.modules
    assert "subdomain-enum" in caps.presets
    assert "json" in caps.output_modules
