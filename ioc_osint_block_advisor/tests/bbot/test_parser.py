import json
from pathlib import Path

from integrations.bbot.parser import event_display_value, parse_bbot_line

# Real JSONL captured from `bbot -t example.com -m crt --json --no-color
# --yes` against BBOT 3.0.0 (pipx, WSL2 Ubuntu-24.04) during manual
# validation - see the validation report. example.com is IANA's reserved
# documentation/testing domain (RFC 2606); only passive DNS/CT lookups were
# performed, no active probing.
REAL_EVENTS_JSONL = (Path(__file__).parent / "fixtures" / "bbot_events_real.jsonl").read_text(encoding="utf-8")


def test_real_bbot_events_all_parse_without_warnings():
    lines = [line for line in REAL_EVENTS_JSONL.splitlines() if line.strip()]
    assert lines
    for line in lines:
        event, warning = parse_bbot_line(line)
        assert warning is None, f"unexpected warning for real event line: {warning}"
        assert event is not None


def test_real_scan_event_parent_is_self_and_data_json_is_populated():
    lines = [line for line in REAL_EVENTS_JSONL.splitlines() if line.strip()]
    scan_events = []
    for line in lines:
        event, _ = parse_bbot_line(line)
        if event.event_type == "SCAN":
            scan_events.append(event)
    assert scan_events
    first = scan_events[0]
    # Real BBOT SCAN lifecycle events self-reference (parent == id) - this
    # is not a parent/child relationship (see mapper.build_relationships's
    # explicit guard against self-loops).
    assert first.parent_id == first.event_id
    # SCAN events carry a top-level "data_json" key (scan name/target/
    # preset/status), with no "data" key at all.
    assert first.data_json is not None
    assert "target" in first.data_json


def test_real_dns_name_event_has_resolved_hosts_and_tags():
    lines = [line for line in REAL_EVENTS_JSONL.splitlines() if line.strip()]
    dns_events = []
    for line in lines:
        event, _ = parse_bbot_line(line)
        if event.event_type == "DNS_NAME" and event.data == "example.com":
            dns_events.append(event)
    assert dns_events
    root = dns_events[0]
    assert root.resolved_hosts
    assert "domain" in root.tags or "target" in root.tags


def test_parses_known_event_type():
    line = json.dumps(
        {
            "type": "DNS_NAME",
            "id": "abc123",
            "data": "sub.example.com",
            "parent": "root123",
            "module": "dnsresolve",
            "scope_distance": 1,
            "tags": ["subdomain"],
            "timestamp": 1700000000.0,
        }
    )
    event, warning = parse_bbot_line(line)
    assert warning is None
    assert event.event_type == "DNS_NAME"
    assert event.event_id == "abc123"
    assert event.parent_id == "root123"
    assert event.module == "dnsresolve"
    assert event.scope_distance == 1
    assert event.tags == ["subdomain"]
    assert event.raw["type"] == "DNS_NAME"


def test_unknown_event_type_is_kept_not_discarded():
    line = json.dumps({"type": "SOME_FUTURE_EVENT_TYPE", "data": "value"})
    event, warning = parse_bbot_line(line)
    assert warning is None
    assert event is not None
    assert event.event_type == "SOME_FUTURE_EVENT_TYPE"
    assert event.raw["data"] == "value"


def test_invalid_json_line_produces_warning_not_exception():
    event, warning = parse_bbot_line("this is not json {{{")
    assert event is None
    assert warning is not None
    assert "no-JSON" in warning or "no-json" in warning.lower()


def test_blank_line_is_ignored_silently():
    event, warning = parse_bbot_line("   ")
    assert event is None
    assert warning is None


def test_non_dict_json_produces_warning():
    event, warning = parse_bbot_line("[1, 2, 3]")
    assert event is None
    assert warning is not None


def test_missing_id_gets_synthesized_deterministically():
    line = json.dumps({"type": "IP_ADDRESS", "data": "1.2.3.4"})
    event1, _ = parse_bbot_line(line)
    event2, _ = parse_bbot_line(line)
    assert event1.event_id == event2.event_id
    assert event1.event_id


def test_event_display_value_prefers_string_data():
    line = json.dumps({"type": "DNS_NAME", "data": "example.com"})
    event, _ = parse_bbot_line(line)
    assert event_display_value(event) == "example.com"


def test_event_display_value_extracts_from_dict_data():
    line = json.dumps({"type": "URL", "data": {"url": "https://example.com/x"}})
    event, _ = parse_bbot_line(line)
    assert event_display_value(event) == "https://example.com/x"


def test_parent_id_extracted_from_nested_parent_object():
    line = json.dumps({"type": "DNS_NAME", "data": "x.example.com", "parent": {"id": "parent-1"}})
    event, _ = parse_bbot_line(line)
    assert event.parent_id == "parent-1"


def test_resolved_hosts_normalized_to_list_of_strings():
    line = json.dumps({"type": "URL", "data": "https://example.com", "resolved_hosts": "1.2.3.4"})
    event, _ = parse_bbot_line(line)
    assert event.resolved_hosts == ["1.2.3.4"]
