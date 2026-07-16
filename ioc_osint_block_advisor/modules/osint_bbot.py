"""BBOT enrichment entry point used by the analysis worker.

This module is the ONLY place where the rest of the app talks to BBOT. It
never decides that an IOC is malicious: it only calls the external BBOT
process (see integrations/bbot) and hands the resulting evidence to
``integrations.bbot.mapper.apply_bbot_evidence``, which in turn attaches
score-capped, deduplicated evidence to the item's ``osint_results`` /
``bbot_*`` fields. The actual BLOCK/REVIEW/DO_NOT_BLOCK decision is still
made exclusively by ``modules.decision_engine``.

BBOT is optional: if it is not installed/reachable, ``collect_bbot_many``
degrades to recording a clear warning on each affected item and never
raises out to the caller.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from integrations.bbot.errors import BBOTError
from integrations.bbot.mapper import apply_bbot_evidence
from integrations.bbot.models import (
    PROFILE_AUTHORIZED_ACTIVE,
    PROFILE_FULL_BBOT,
    PROFILE_SOC_PASSIVE,
    PROFILE_SOC_PASSIVE_DEEP,
    PROFILES_REQUIRING_AUTHORIZATION,
    RUN_FAILED,
    BBOTScanConfig,
)
from integrations.bbot.orchestrator import run_scan
from integrations.bbot.settings import BBOTSettings, load_settings

from .utils import resource_path

PRESET_DIR = resource_path("presets") / "bbot"

# Maps a fixed security profile to one of our bundled preset files (FASE 5).
# "full_bbot" deliberately has no fixed preset file: it uses whatever
# modules/presets/output_modules the analyst explicitly selected.
_PROFILE_PRESET_FILES = {
    PROFILE_SOC_PASSIVE: PRESET_DIR / "soc_passive.yml",
    PROFILE_SOC_PASSIVE_DEEP: PRESET_DIR / "soc_passive_deep.yml",
    PROFILE_AUTHORIZED_ACTIVE: PRESET_DIR / "authorized_active.yml",
}


@dataclass
class BBOTEnrichmentOptions:
    enabled: bool = False
    profile: str = PROFILE_SOC_PASSIVE
    include_full_url: bool = False
    use_cache: bool = True
    force_refresh: bool = False
    authorized: bool = False
    modules: list = field(default_factory=list)
    presets: list = field(default_factory=list)
    output_modules: list = field(default_factory=list)
    timeout_seconds: int | None = None
    max_events: int | None = None


def bbot_applicable(item) -> bool:
    """BBOT is never run against hashes: there is no infrastructure to map."""
    return not item.ioc_type.startswith("hash")


def bbot_target_for(item, include_full_url: bool = False) -> str | None:
    """The value actually sent to BBOT for a given IOC.

    Privacy-by-default (FASE 12): emails are reduced to their domain, and
    URLs are reduced to their host/domain unless the analyst explicitly
    opts into sending the full URL (query strings/tokens/paths may be
    sensitive and are never sent to an external process by default).
    """
    if item.ioc_type.startswith("hash"):
        return None
    if item.ioc_type == "email":
        domain = item.domain or (item.normalized.rsplit("@", 1)[-1] if "@" in item.normalized else "")
        return domain or None
    if item.ioc_type == "url":
        if include_full_url:
            return item.normalized
        return item.root_domain or item.domain or None
    if item.ioc_type == "domain":
        return item.root_domain or item.domain or item.normalized
    if item.ioc_type == "ip":
        return item.normalized
    return None


# Profiles that must NEVER be able to run an active module, enforced here
# at the code layer (not just via preset YAML content, which could drift
# or be misconfigured). BBOT's own documented mechanism for this is
# `-rf passive` ("require flags"), which restricts the *final* module
# selection regardless of what a preset/-f/-m otherwise enabled - see
# `bbot --help`'s own EXAMPLES section ("Subdomains (passive only): bbot
# -t evilcorp.com -p subdomain-enum -rf passive"), confirmed during manual
# validation against a real BBOT 3.0.0 install.
_PASSIVE_ONLY_PROFILES = (PROFILE_SOC_PASSIVE, PROFILE_SOC_PASSIVE_DEEP)


def _build_scan_config(target: str, options: BBOTEnrichmentOptions, settings: BBOTSettings) -> BBOTScanConfig:
    preset_files: list[str] = []
    presets: list[str] = []
    if options.profile == PROFILE_FULL_BBOT:
        presets = list(options.presets)
    else:
        preset_path = _PROFILE_PRESET_FILES.get(options.profile)
        if preset_path and preset_path.exists():
            preset_files.append(str(preset_path))

    require_flags = ["passive"] if options.profile in _PASSIVE_ONLY_PROFILES else []
    # "Authorized Active" is documented as *controlled* active (see the
    # security profile table in README.md): loud/invasive modules are
    # excluded here even if a preset's own `flags:` would otherwise enable
    # them. Full BBOT is the only profile that can run loud/invasive
    # modules, and only after its own separate confirmation.
    exclude_flags = ["loud", "invasive"] if options.profile == PROFILE_AUTHORIZED_ACTIVE else []

    return BBOTScanConfig(
        target=target,
        profile=options.profile,
        modules=list(options.modules),
        presets=presets,
        preset_files=preset_files,
        output_modules=list(options.output_modules),
        require_flags=require_flags,
        exclude_flags=exclude_flags,
        timeout_seconds=options.timeout_seconds or settings.timeout_seconds,
        max_events=options.max_events or settings.max_events,
        authorized=options.authorized,
        use_cache=options.use_cache,
        force_refresh=options.force_refresh,
    )


def collect_bbot_many(
    items: list,
    options: BBOTEnrichmentOptions,
    *,
    cancel_event: threading.Event | None = None,
    on_event=None,
    on_status=None,
) -> None:
    """Enrich ``items`` in place with BBOT evidence.

    Groups items by resolved target so multiple IOCs sharing the same root
    domain (or the same IP) trigger a single BBOT scan (FASE 12/13), then
    attaches the shared result to every item in the group via the mapper.
    """
    if not options.enabled:
        return

    if options.profile in PROFILES_REQUIRING_AUTHORIZATION and not options.authorized:
        for item in items:
            if bbot_applicable(item):
                item.bbot_status = "failed"
                item.bbot_warnings.append(
                    "Perfil BBOT activo/invasivo seleccionado sin confirmación de autorización explícita: "
                    "análisis omitido por seguridad."
                )
        return

    settings = load_settings()

    groups: dict[str, list] = {}
    for item in items:
        if not bbot_applicable(item):
            continue
        target = bbot_target_for(item, include_full_url=options.include_full_url)
        if not target:
            continue
        groups.setdefault(target.lower(), []).append(item)

    for target, group_items in groups.items():
        config = _build_scan_config(target, options, settings)
        try:
            result = run_scan(
                config,
                settings,
                cancel_event=cancel_event,
                on_event=on_event,
                on_status=on_status,
            )
        except BBOTError as exc:
            for item in group_items:
                item.bbot_status = "failed"
                item.bbot_warnings.append(f"Error en la integración BBOT: {exc}")
            continue
        except Exception as exc:  # last-resort safety net: BBOT must never crash analysis
            for item in group_items:
                item.bbot_status = "failed"
                item.bbot_warnings.append(f"Fallo inesperado ejecutando BBOT: {exc}")
            continue

        if result.status == RUN_FAILED and not result.events:
            for item in group_items:
                item.bbot_status = result.status
                item.bbot_warnings.extend(result.errors or ["BBOT no devolvió resultados."])
            continue

        for item in group_items:
            apply_bbot_evidence(item, result)
