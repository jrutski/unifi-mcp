"""IPS event projection from v2 traffic flows and legacy /stat/ips/event records.

The flow fixture mirrors the field names Network 10.6 returns for an
INTRUSION_PREVENTION flow, with synthetic addresses and IDs.
"""

from unifi_core.network.models.ips_events import (
    MUTABLE_FIELDS,
    SOURCE_LEGACY,
    SOURCE_TRAFFIC_FLOWS,
    IpsEndpoint,
    ips_event_from_flow,
    ips_event_from_legacy,
)

IPS_FLOW = {
    "action": "allowed",
    "count": 1,
    "destination": {
        "client_fingerprint": {"has_override": False},
        "client_name": "media-server",
        "client_oui": "ExampleCo",
        "domains": [],
        "id": "aa:bb:cc:00:00:26",
        "ip": "192.0.2.26",
        "mac": "aa:bb:cc:00:00:26",
        "network_id": "net-1",
        "network_name": "Server",
        "port": 32400,
        "subnet": "192.0.2.0/24",
        "zone_id": "zone-1",
        "zone_name": "ServerZone",
    },
    "direction": "incoming",
    "flow_start_time": 1792349124680,
    "id": "flow-ips-1",
    "ips": {
        "advanced_information": (
            "IPS Alert 2: Misc Attack. Signature ET DROP Dshield Block Listed Source group 1. "
            "From: 198.51.100.253:1196, to: 192.0.2.26:32400, protocol: TCP"
        ),
        "affected_product": "",
        "alarm_category_potential_risk": "This indicates that someone may be attempting to exploit an application.",
        "category_name": "dshield",
        "description": "",
        "enhanced_detection": False,
        "relevant_cve": "",
        "session_id": 1744046964105344,
        "signature": "ET DROP Dshield Block Listed Source group 1",
        "signature_class": "",
        "signature_id": 2402000,
    },
    "next_ai": [],
    "policies": [
        {
            "internal_type": "SIGNATURE",
            "ips_category": "DSHIELD",
            "name": "DShield Block List",
            "type": "INTRUSION_PREVENTION",
        }
    ],
    "protocol": "TCP",
    "risk": "medium",
    "service": "OTHER",
    "source": {"id": "198.51.100.253", "ip": "198.51.100.253", "port": 1196, "region": "BR"},
    "time": 1792349124680,
    "traffic_data": {"bytes_rx": 0, "bytes_total": 74, "bytes_tx": 74},
}


def test_projects_ips_flow() -> None:
    event = ips_event_from_flow(IPS_FLOW)

    assert event.id == "flow-ips-1"
    assert event.time == 1792349124680
    assert event.action == "allowed"
    assert event.risk == "medium"
    assert event.direction == "incoming"
    assert event.protocol == "TCP"
    assert event.signature == "ET DROP Dshield Block Listed Source group 1"
    assert event.signature_id == 2402000
    assert event.category == "dshield"
    assert event.classification == "Misc Attack"
    assert event.rule_set == "DShield Block List"
    assert event.cve is None
    assert event.potential_risk.startswith("This indicates")
    assert event.count == 1
    assert event.source == IpsEndpoint(ip="198.51.100.253", port=1196, region="BR")
    assert event.destination == IpsEndpoint(
        ip="192.0.2.26", port=32400, name="media-server", mac="aa:bb:cc:00:00:26", network_name="Server"
    )
    assert event.record_source == SOURCE_TRAFFIC_FLOWS


def test_signature_class_wins_over_parsed_classification_and_cve_is_kept() -> None:
    flow = {
        **IPS_FLOW,
        "ips": {**IPS_FLOW["ips"], "signature_class": "Attempted Admin", "relevant_cve": "CVE-2024-0001"},
    }
    event = ips_event_from_flow(flow)
    assert event.classification == "Attempted Admin"
    assert event.cve == "CVE-2024-0001"


def test_flow_without_ips_block_or_policy_projects_what_it_has() -> None:
    event = ips_event_from_flow({"id": "f", "action": "blocked", "policies": [{"type": "FIREWALL"}], "ips": "x"})
    assert event.action == "blocked"
    assert event.signature is None
    assert event.rule_set is None
    assert event.classification is None


def test_malformed_flow_is_empty_not_an_error() -> None:
    event = ips_event_from_flow(None)
    assert event.id is None
    assert event.source == IpsEndpoint()


def test_projects_legacy_record() -> None:
    event = ips_event_from_legacy(
        {
            "_id": "legacy-1",
            "time": 1700000000000,
            "inner_alert_action": "Blocked",
            "inner_alert_signature": "ET SCAN Example",
            "inner_alert_signature_id": "2001219",
            "inner_alert_category": "Attempted Information Leak",
            "catname": "emerging-scan",
            "proto": "TCP",
            "src_ip": "198.51.100.9",
            "src_port": 4444,
            "srcipCountry": "NL",
            "dest_ip": "192.0.2.5",
            "dest_port": 22,
        }
    )
    assert event.action == "blocked"
    assert event.signature_id == 2001219
    assert event.category == "emerging-scan"
    assert event.classification == "Attempted Information Leak"
    assert event.source == IpsEndpoint(ip="198.51.100.9", port=4444, region="NL")
    assert event.destination == IpsEndpoint(ip="192.0.2.5", port=22)
    assert event.record_source == SOURCE_LEGACY


def test_read_only() -> None:
    assert MUTABLE_FIELDS == frozenset()
