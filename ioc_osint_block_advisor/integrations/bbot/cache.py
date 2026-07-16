"""Local disk cache for BBOT scan results.

Cache keys always include the profile/module/preset selection and the BBOT
version, so results from different security profiles or BBOT installs are
never mixed. Active-scan results are never reused as if they were passive
(the profile is part of the key), and no secret values are ever written to
the cache file.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path

from .models import BBOTScanConfig, BBOTScanResult, RUN_COMPLETED
from .settings import BBOTSettings


def _cache_dir(settings: BBOTSettings) -> Path:
    from .settings import default_workdir

    cache_dir = default_workdir(settings) / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def cache_key(config: BBOTScanConfig, runtime_backend: str, bbot_version: str) -> str:
    payload = {
        "target": config.target.strip().lower(),
        "runtime": runtime_backend,
        "version": bbot_version,
        "profile": config.profile,
        "modules": sorted(config.modules),
        "presets": sorted(config.presets),
        "preset_files": sorted(config.preset_files),
        "output_modules": sorted(config.output_modules),
        "flags": sorted(config.flags),
        "require_flags": sorted(config.require_flags),
        "exclude_flags": sorted(config.exclude_flags),
        "exclude_modules": sorted(config.exclude_modules),
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _cache_path(settings: BBOTSettings, key: str) -> Path:
    return _cache_dir(settings) / f"{key}.json"


def load_cached_result(settings: BBOTSettings, key: str) -> BBOTScanResult | None:
    path = _cache_path(settings, key)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    cached_at = payload.get("_cached_at", 0)
    ttl = settings.cache_ttl_seconds
    if ttl > 0 and (time.time() - cached_at) > ttl:
        return None

    result_data = payload.get("result")
    if not result_data:
        return None

    from .models import BBOTEvent, BBOTRelationship

    events = [BBOTEvent(**e) for e in result_data.get("events", [])]
    relationships = [BBOTRelationship(**r) for r in result_data.get("relationships", [])]
    result = BBOTScanResult(
        scan_id=result_data.get("scan_id", ""),
        status=result_data.get("status", RUN_COMPLETED),
        events=events,
        relationships=relationships,
        warnings=result_data.get("warnings", []),
        errors=result_data.get("errors", []),
        exit_code=result_data.get("exit_code"),
        started_at=result_data.get("started_at"),
        finished_at=result_data.get("finished_at"),
        truncated=result_data.get("truncated", False),
        from_cache=True,
    )
    return result


def store_cached_result(settings: BBOTSettings, key: str, result: BBOTScanResult) -> Path:
    path = _cache_path(settings, key)
    data = asdict(result)
    data.pop("from_cache", None)
    payload = {"_cached_at": time.time(), "result": data}
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def clear_cache(settings: BBOTSettings) -> int:
    cache_dir = _cache_dir(settings)
    removed = 0
    for file in cache_dir.glob("*.json"):
        try:
            file.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def last_scan_time(settings: BBOTSettings, key: str) -> float | None:
    path = _cache_path(settings, key)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload.get("_cached_at")
