"""Data models shared across the BBOT integration.

None of these types embed BBOT source code; they only describe the shape
of data exchanged with the external ``bbot`` process (see NOTICE_BBOT.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Runtime / capability discovery
# ---------------------------------------------------------------------------

RUNTIME_BACKENDS = ("native", "wsl", "docker")
RUNTIME_MODES = ("auto", "native", "wsl", "docker", "disabled")


@dataclass
class BBOTRuntimeStatus:
    available: bool
    backend: str = ""
    executable: str = ""
    version: str = ""
    reason: str = ""
    capabilities_loaded: bool = False


@dataclass
class BBOTModuleCapability:
    name: str
    description: str = ""
    flags: set[str] = field(default_factory=set)
    passive: bool = False
    active: bool = False
    safe: bool = True
    loud: bool = False
    invasive: bool = False
    auth_required: bool = False
    installed: bool = True
    available: bool = True
    unavailable_reason: str = ""


@dataclass
class BBOTPresetCapability:
    name: str
    description: str = ""
    available: bool = True
    unavailable_reason: str = ""


@dataclass
class BBOTOutputModuleCapability:
    name: str
    description: str = ""
    available: bool = True
    auth_required: bool = False
    unavailable_reason: str = ""


@dataclass
class BBOTFlagCapability:
    name: str
    description: str = ""
    module_count: int = 0
    modules: list[str] = field(default_factory=list)


@dataclass
class BBOTModuleOption:
    name: str  # dotted config path, e.g. "modules.baddns.min_confidence"
    type: str = ""
    description: str = ""
    default: str = ""


@dataclass
class BBOTCapabilities:
    version: str = ""
    modules: dict[str, BBOTModuleCapability] = field(default_factory=dict)
    presets: dict[str, BBOTPresetCapability] = field(default_factory=dict)
    output_modules: dict[str, BBOTOutputModuleCapability] = field(default_factory=dict)
    flags: dict[str, BBOTFlagCapability] = field(default_factory=dict)
    module_options: dict[str, BBOTModuleOption] = field(default_factory=dict)
    loaded: bool = False
    warnings: list[str] = field(default_factory=list)
    fetched_at: float | None = None


# Availability reasons (human-readable, shown in UI instead of a bare "Error").
class Availability:
    AVAILABLE = "available"
    AVAILABLE_NO_KEY = "available_no_api_key"
    MISSING_DEPENDENCY = "missing_dependency"
    DISABLED_BY_POLICY = "disabled_by_policy"
    NOT_APPLICABLE = "not_applicable"
    LOAD_ERROR = "load_error"


# ---------------------------------------------------------------------------
# Security profiles
# ---------------------------------------------------------------------------

PROFILE_SOC_PASSIVE = "soc_passive"
PROFILE_SOC_PASSIVE_DEEP = "soc_passive_deep"
PROFILE_AUTHORIZED_ACTIVE = "authorized_active"
PROFILE_FULL_BBOT = "full_bbot"

SECURITY_PROFILES = (
    PROFILE_SOC_PASSIVE,
    PROFILE_SOC_PASSIVE_DEEP,
    PROFILE_AUTHORIZED_ACTIVE,
    PROFILE_FULL_BBOT,
)

# Profiles that touch the target directly and therefore require explicit
# analyst authorization before running.
PROFILES_REQUIRING_AUTHORIZATION = (PROFILE_AUTHORIZED_ACTIVE, PROFILE_FULL_BBOT)


# ---------------------------------------------------------------------------
# Scan configuration / lifecycle
# ---------------------------------------------------------------------------

RUN_PENDING = "pending"
RUN_STARTING = "starting"
RUN_RUNNING = "running"
RUN_CANCELLING = "cancelling"
RUN_CANCELLED = "cancelled"
RUN_COMPLETED = "completed"
RUN_FAILED = "failed"
RUN_TIMED_OUT = "timed_out"

RUN_TERMINAL_STATES = (RUN_CANCELLED, RUN_COMPLETED, RUN_FAILED, RUN_TIMED_OUT)


@dataclass
class BBOTScanConfig:
    target: str
    profile: str = PROFILE_SOC_PASSIVE
    modules: list[str] = field(default_factory=list)
    presets: list[str] = field(default_factory=list)
    preset_files: list[str] = field(default_factory=list)
    output_modules: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    require_flags: list[str] = field(default_factory=list)
    exclude_flags: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    max_events: int = 5000
    authorized: bool = False
    use_cache: bool = True
    force_refresh: bool = False


@dataclass
class BBOTScanResult:
    scan_id: str
    status: str = RUN_PENDING
    events: list["BBOTEvent"] = field(default_factory=list)
    relationships: list["BBOTRelationship"] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    exit_code: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    truncated: bool = False
    from_cache: bool = False


# ---------------------------------------------------------------------------
# Events & relationships
# ---------------------------------------------------------------------------


@dataclass
class BBOTEvent:
    event_id: str
    event_type: str
    data: Any
    data_json: dict | None
    parent_id: str | None
    module: str
    module_sequence: str
    scope_distance: int
    tags: list[str]
    timestamp: float | None
    resolved_hosts: list[str]
    raw: dict


@dataclass
class BBOTRelationship:
    source_id: str
    target_id: str
    relation_type: str
    source_module: str
    confidence: str
    direct: bool
    technical_only: bool
