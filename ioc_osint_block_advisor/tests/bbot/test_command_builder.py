import pytest

from integrations.bbot.command_builder import (
    build_bbot_argv,
    build_capability_query_argv,
    validate_module_name,
    validate_preset_file,
    validate_preset_name,
    validate_target,
)
from integrations.bbot.errors import BBOTValidationError
from integrations.bbot.models import BBOTCapabilities, BBOTModuleCapability, BBOTPresetCapability


def test_valid_target_passes_through():
    assert validate_target("example.com") == "example.com"
    assert validate_target(" 1.2.3.4 ") == "1.2.3.4"


@pytest.mark.parametrize(
    "malicious_target",
    [
        "example.com; calc.exe",
        "$(whoami)",
        "`whoami`",
        "../../etc/passwd",
        "--config=malicious=value",
        "example.com && rm -rf /",
        "example.com | cat /etc/passwd",
        "test\ninjected",
    ],
)
def test_command_injection_attempts_are_rejected(malicious_target):
    with pytest.raises(BBOTValidationError):
        validate_target(malicious_target)


def test_target_that_looks_like_a_flag_is_rejected():
    with pytest.raises(BBOTValidationError):
        validate_target("--modules=all")


def test_empty_target_is_rejected():
    with pytest.raises(BBOTValidationError):
        validate_target("")


def test_target_length_limit_enforced():
    with pytest.raises(BBOTValidationError):
        validate_target("a" * 600)


def test_argv_is_a_plain_list_never_a_shell_string():
    built = build_bbot_argv("bbot", "example.com")
    assert isinstance(built.argv, list)
    assert all(isinstance(part, str) for part in built.argv)
    assert built.argv[0] == "bbot"
    assert "-t" in built.argv
    assert "example.com" in built.argv
    # No shell metacharacters should ever need escaping in a real argv list.
    assert "shell=True" not in built.preview


def test_build_bbot_argv_rejects_malicious_target():
    with pytest.raises(BBOTValidationError):
        build_bbot_argv("bbot", "example.com; calc.exe")


def test_module_name_validated_against_capabilities():
    caps = BBOTCapabilities(loaded=True, modules={"dnsresolve": BBOTModuleCapability(name="dnsresolve")})
    assert validate_module_name("dnsresolve", caps) == "dnsresolve"
    with pytest.raises(BBOTValidationError):
        validate_module_name("not_a_real_module", caps)


def test_module_name_rejects_shell_metacharacters():
    with pytest.raises(BBOTValidationError):
        validate_module_name("dnsresolve; rm -rf /")


def test_preset_name_validated_against_capabilities():
    caps = BBOTCapabilities(loaded=True, presets={"subdomain-enum": BBOTPresetCapability(name="subdomain-enum")})
    assert validate_preset_name("subdomain-enum", caps) == "subdomain-enum"
    with pytest.raises(BBOTValidationError):
        validate_preset_name("kitchen-sink", caps)


def test_unvalidated_capabilities_allow_any_safe_name():
    # When capabilities haven't loaded (e.g. BBOT not installed), we still
    # apply syntactic validation but can't check against a real inventory.
    assert validate_module_name("anything_safe") == "anything_safe"


def test_preset_file_path_traversal_rejected(tmp_path):
    allowed_dir = tmp_path / "presets"
    allowed_dir.mkdir()
    outside_file = tmp_path / "outside.yml"
    outside_file.write_text("description: x\n")
    with pytest.raises(BBOTValidationError):
        validate_preset_file(str(outside_file), [str(allowed_dir)])


def test_preset_file_must_exist(tmp_path):
    allowed_dir = tmp_path / "presets"
    allowed_dir.mkdir()
    with pytest.raises(BBOTValidationError):
        validate_preset_file(str(allowed_dir / "missing.yml"), [str(allowed_dir)])


def test_preset_file_must_be_yaml(tmp_path):
    allowed_dir = tmp_path / "presets"
    allowed_dir.mkdir()
    bad_file = allowed_dir / "not_yaml.txt"
    bad_file.write_text("description: x\n")
    with pytest.raises(BBOTValidationError):
        validate_preset_file(str(bad_file), [str(allowed_dir)])


def test_preset_file_inside_allowed_dir_accepted(tmp_path):
    allowed_dir = tmp_path / "presets"
    allowed_dir.mkdir()
    good_file = allowed_dir / "soc_passive.yml"
    good_file.write_text("description: x\n")
    assert validate_preset_file(str(good_file), [str(allowed_dir)]) == str(good_file.resolve())


def test_build_capability_query_argv_only_allows_fixed_queries():
    assert build_capability_query_argv("bbot", "version") == ["bbot", "--version"]
    with pytest.raises(BBOTValidationError):
        build_capability_query_argv("bbot", "rm -rf /")


def test_no_executable_configured_raises():
    with pytest.raises(BBOTValidationError):
        build_bbot_argv("", "example.com")


def test_workdir_traversal_rejected():
    with pytest.raises(BBOTValidationError):
        build_bbot_argv("bbot", "example.com", workdir="../../etc")
