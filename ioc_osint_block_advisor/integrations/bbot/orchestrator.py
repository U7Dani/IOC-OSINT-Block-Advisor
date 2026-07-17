"""Ties discovery, caching, command building and the runner together.

This is the single entry point the rest of the app (``modules.osint_runner``)
should call. Everything else in this package is a building block used by
this orchestration (and independently unit-tested).
"""

from __future__ import annotations

import threading
import time
import uuid

from .cache import cache_key, load_cached_result, store_cached_result
from .command_builder import build_bbot_argv
from .discovery import backend_prefix, detect_runtime, discover_capabilities
from .models import (
    RUN_FAILED,
    BBOTCapabilities,
    BBOTRuntimeStatus,
    BBOTScanConfig,
    BBOTScanResult,
)
from .runner import BBOTRunner
from .settings import BBOTSettings, default_workdir

# One process-wide capability cache: capability discovery is a handful of
# subprocess calls and rarely changes within a single app session. The UI
# exposes an explicit "Actualizar capacidades" action that clears this.
_capabilities_cache: dict[str, BBOTCapabilities] = {}
_capabilities_lock = threading.Lock()


def get_capabilities(settings: BBOTSettings, runtime: BBOTRuntimeStatus | None = None, force_refresh: bool = False) -> BBOTCapabilities:
    runtime = runtime or detect_runtime(settings)
    cache_id = f"{runtime.backend}:{runtime.version}"
    with _capabilities_lock:
        if not force_refresh and cache_id in _capabilities_cache:
            return _capabilities_cache[cache_id]
    capabilities = discover_capabilities(runtime, settings)
    with _capabilities_lock:
        _capabilities_cache[cache_id] = capabilities
    return capabilities


def invalidate_capabilities_cache() -> None:
    with _capabilities_lock:
        _capabilities_cache.clear()


def _translate_windows_path_to_wsl(path_str: str) -> str:
    """Translate a resolved Windows absolute path (e.g. ``C:\\Users\\x\\y``)
    to the path WSL sees it at (``/mnt/c/Users/x/y``).

    Found during manual validation: passing a raw Windows path as a BBOT
    CLI argument (e.g. ``-p C:\\...\\soc_passive.yml``) to a process running
    *inside* WSL silently fails to load the file (BBOT looks for it
    relative to its own Linux filesystem view) - it does not raise, it
    just behaves as if the preset/argument were absent. Validation itself
    (``command_builder.validate_preset_file``) must still run against the
    real Windows-visible path, since that check runs in this (Windows)
    Python process; only the argv value handed to the wsl-wrapped process
    needs the translated form.
    """
    from pathlib import PureWindowsPath

    p = PureWindowsPath(path_str)
    if not p.drive:
        return path_str
    drive_letter = p.drive.rstrip(":").lower()
    rest = "/".join(p.parts[1:])
    return f"/mnt/{drive_letter}/{rest}"


def _preset_allowed_dirs(settings: BBOTSettings) -> list:
    from pathlib import Path

    from modules.utils import resource_path

    dirs = [resource_path("presets") / "bbot"]
    dirs += [Path(p).parent for p in (settings.custom_presets or [])]
    return dirs


def _build_argv(config: BBOTScanConfig, settings: BBOTSettings, runtime: BBOTRuntimeStatus, capabilities: BBOTCapabilities) -> list[str]:
    executable = runtime.executable or settings.executable or "bbot"
    workdir = default_workdir(settings) / config.target.replace("/", "_").replace(":", "_")

    built = build_bbot_argv(
        executable,
        config.target,
        modules=config.modules,
        presets=config.presets,
        preset_files=config.preset_files,
        preset_file_allowed_dirs=_preset_allowed_dirs(settings),
        output_modules=config.output_modules,
        exclude_modules=config.exclude_modules,
        flags=config.flags,
        require_flags=config.require_flags,
        exclude_flags=config.exclude_flags,
        workdir=str(workdir) if runtime.backend == "native" else None,
        capabilities=capabilities,
    )
    argv = built.argv
    if runtime.backend == "wsl":
        from pathlib import Path

        translations = {str(Path(p).resolve()): _translate_windows_path_to_wsl(str(Path(p).resolve())) for p in config.preset_files}
        argv = [translations.get(a, a) for a in argv]

    prefix = backend_prefix(runtime.backend, settings)
    if runtime.backend == "native":
        return argv
    return [*prefix, *argv]


def run_scan(
    config: BBOTScanConfig,
    settings: BBOTSettings,
    *,
    cancel_event: threading.Event | None = None,
    on_event=None,
    on_status=None,
) -> BBOTScanResult:
    """Run (or reuse from cache) a single BBOT scan for ``config.target``."""
    scan_id = uuid.uuid4().hex
    runtime = detect_runtime(settings)
    if not runtime.available:
        return BBOTScanResult(
            scan_id=scan_id,
            status=RUN_FAILED,
            errors=[runtime.reason or "BBOT no disponible."],
            started_at=time.time(),
            finished_at=time.time(),
        )

    capabilities = get_capabilities(settings, runtime)

    key = cache_key(config, runtime.backend, runtime.version)
    if config.use_cache and not config.force_refresh:
        cached = load_cached_result(settings, key)
        if cached is not None:
            cached.scan_id = scan_id
            return cached

    try:
        argv = _build_argv(config, settings, runtime, capabilities)
    except Exception as exc:  # BBOTValidationError and friends
        return BBOTScanResult(
            scan_id=scan_id,
            status=RUN_FAILED,
            errors=[str(exc)],
            started_at=time.time(),
            finished_at=time.time(),
        )

    runner = BBOTRunner(
        argv,
        scan_id=scan_id,
        timeout_seconds=config.timeout_seconds,
        max_events=config.max_events,
        cancel_event=cancel_event,
        on_event=on_event,
        on_status=on_status,
    )
    result = runner.run()

    from .models import RUN_COMPLETED

    if result.status == RUN_COMPLETED and config.use_cache:
        try:
            store_cached_result(settings, key, result)
        except OSError:
            result.warnings.append("No se pudo escribir en la caché local de BBOT.")

    return result
