"""Persistent, non-secret configuration for the BBOT integration.

Secrets (API keys) are never read from or written to the settings file.
They must be supplied via environment variables (see ``.env.example``) or
BBOT's own secrets store; this module only knows the *names* of the
environment variables it expects, never their values, so that values can
be redacted from logs/exceptions/UI without a value ever being persisted
here.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import PROFILE_SOC_PASSIVE
from modules.utils import CONFIG_DIR, resource_path

SETTINGS_PATH = CONFIG_DIR / "bbot_settings.json"

# Names (not values) of environment variables that may hold secrets used by
# BBOT modules. Used only to redact values from logs/command previews.
KNOWN_SECRET_ENV_VARS = (
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "SECURITYTRAILS_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "BINARYEDGE_API_KEY",
    "GITHUB_TOKEN",
    "BEVIGIL_API_KEY",
    "C99_API_KEY",
    "FULLHUNT_API_KEY",
    "HUNTERIO_API_KEY",
    "INTELX_API_KEY",
    "LEAKIX_API_KEY",
    "NUCLEI_TEMPLATES_TOKEN",
    "PASSIVETOTAL_USERNAME",
    "PASSIVETOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "ZOOMEYE_API_KEY",
)


@dataclass
class BBOTSettings:
    runtime: str = "auto"  # auto | native | wsl | docker | disabled
    executable: str = "bbot"
    wsl_distribution: str = ""
    docker_image: str = "blacklanternsecurity/bbot:stable"
    docker_extra_args: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    max_events: int = 5000
    workdir: str = ""
    default_profile: str = PROFILE_SOC_PASSIVE
    custom_presets: list[str] = field(default_factory=list)
    allowed_modules: list[str] = field(default_factory=list)
    denied_modules: list[str] = field(default_factory=list)
    cache_ttl_seconds: int = 21600  # 6h
    retention_days: int = 30

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "BBOTSettings":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in (data or {}).items() if k in known}
        return cls(**clean)


def load_settings(path: Path | None = None) -> BBOTSettings:
    path = path or SETTINGS_PATH
    if not path.exists():
        return BBOTSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return BBOTSettings()
    return BBOTSettings.from_dict(data)


def save_settings(settings: BBOTSettings, path: Path | None = None) -> Path:
    path = path or SETTINGS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def default_workdir(settings: BBOTSettings) -> Path:
    if settings.workdir:
        return Path(settings.workdir)
    return resource_path("output") / "bbot_scans"


def redact(text: str, extra_secrets: list[str] | None = None) -> str:
    """Best-effort redaction of secret-looking values from free text.

    Used before any command preview, log line, or exception message derived
    from the BBOT process is shown to the user or written to disk.
    """
    import os
    import re

    redacted = text
    secrets = list(extra_secrets or [])
    for var in KNOWN_SECRET_ENV_VARS:
        value = os.environ.get(var)
        if value:
            secrets.append(value)
    for secret in secrets:
        if secret and len(secret) >= 4:
            redacted = redacted.replace(secret, "***REDACTED***")
    # Generic key=value / key: value patterns for common secret-ish names.
    redacted = re.sub(
        r"(?i)\b((?:api[_-]?key|token|secret|password|passwd)\s*[:=]\s*)([^\s,;]+)",
        r"\1***REDACTED***",
        redacted,
    )
    return redacted
