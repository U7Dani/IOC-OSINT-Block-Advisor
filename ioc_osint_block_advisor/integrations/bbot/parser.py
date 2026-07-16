"""JSON event parsing for BBOT's ``--json`` stdout stream.

We never parse colored/plain-text output. Every line is expected to be one
JSON object. Unknown event types and unknown fields are preserved (the
``raw`` dict always holds the original object) rather than discarded, so
that new BBOT event types in future versions do not silently disappear.

A line that fails to parse as JSON never aborts the whole scan: it is
reported as a warning and skipped.
"""

from __future__ import annotations

import json

from .models import BBOTEvent

# Known/expected BBOT event types (FASE 8). Not exhaustive — anything else
# is still parsed and kept, just not specially classified.
KNOWN_EVENT_TYPES = {
    "DNS_NAME",
    "IP_ADDRESS",
    "IP_RANGE",
    "ASN",
    "URL",
    "URL_UNVERIFIED",
    "OPEN_TCP_PORT",
    "HTTP_RESPONSE",
    "EMAIL_ADDRESS",
    "STORAGE_BUCKET",
    "CODE_REPOSITORY",
    "TECHNOLOGY",
    "PROTOCOL",
    "VULNERABILITY",
    "FINDING",
    "SCREENSHOT",
    "FILESYSTEM",
    "MOBILE_APP",
    # Observed on a real BBOT 3.0.0 install (manual validation): scan
    # lifecycle/meta events and speculative organization stubs. Neither
    # represents discovered infrastructure by itself.
    "SCAN",
    "ORG_STUB",
}


def parse_bbot_line(line: str) -> tuple[BBOTEvent | None, str | None]:
    """Parse a single stdout line. Returns (event_or_none, warning_or_none)."""
    stripped = (line or "").strip()
    if not stripped:
        return None, None
    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError):
        preview = stripped[:200]
        return None, f"Línea no-JSON ignorada de la salida de BBOT: {preview!r}"

    if not isinstance(obj, dict):
        return None, f"Evento BBOT con forma inesperada (no es un objeto JSON): {stripped[:200]!r}"

    event_type = str(obj.get("type") or obj.get("event_type") or "UNKNOWN")
    event_id = str(obj.get("id") or obj.get("uuid") or obj.get("event_id") or "")
    parent_id = obj.get("parent") or obj.get("parent_id")
    if isinstance(parent_id, dict):
        parent_id = parent_id.get("id")
    parent_id = str(parent_id) if parent_id else None

    module = str(obj.get("module") or obj.get("module_name") or "")
    module_sequence = str(obj.get("module_sequence") or "")

    try:
        scope_distance = int(obj.get("scope_distance", -1))
    except (TypeError, ValueError):
        scope_distance = -1

    tags = obj.get("tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]
    tags = [str(t) for t in tags]

    timestamp = obj.get("timestamp")
    try:
        timestamp = float(timestamp) if timestamp is not None else None
    except (TypeError, ValueError):
        timestamp = None

    resolved_hosts = obj.get("resolved_hosts") or []
    if not isinstance(resolved_hosts, list):
        resolved_hosts = [str(resolved_hosts)]
    resolved_hosts = [str(h) for h in resolved_hosts]

    data = obj.get("data")
    # Real BBOT events carry "data_json" as its own top-level key (e.g. on
    # SCAN lifecycle events, which have no "data" key at all) - it is not
    # simply "data" when data happens to be dict-shaped, though we still
    # fall back to that for safety if a future version nests it instead.
    raw_data_json = obj.get("data_json")
    if isinstance(raw_data_json, dict):
        data_json = raw_data_json
    elif isinstance(data, dict):
        data_json = data
    else:
        data_json = None

    if not event_id:
        # Not all BBOT versions include a stable id; synthesize a
        # deterministic-enough placeholder scoped to this line only.
        event_id = f"anon:{event_type}:{hash(stripped) & 0xFFFFFFFF:x}"

    event = BBOTEvent(
        event_id=event_id,
        event_type=event_type,
        data=data,
        data_json=data_json,
        parent_id=parent_id,
        module=module,
        module_sequence=module_sequence,
        scope_distance=scope_distance,
        tags=tags,
        timestamp=timestamp,
        resolved_hosts=resolved_hosts,
        raw=obj,
    )
    return event, None


def event_display_value(event: BBOTEvent) -> str:
    """Best-effort human-readable value for an event, for the UI/report."""
    if isinstance(event.data, str):
        return event.data
    if isinstance(event.data_json, dict):
        for key in ("host", "url", "hostname", "address", "name", "value"):
            if key in event.data_json:
                return str(event.data_json[key])
        return json.dumps(event.data_json, ensure_ascii=False)[:200]
    return str(event.data) if event.data is not None else ""
