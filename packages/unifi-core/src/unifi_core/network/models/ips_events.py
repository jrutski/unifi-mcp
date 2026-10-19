"""Typed IPS/IDS signature matches.

Two controller shapes project into ``IpsEvent``:

- ``ips_event_from_flow`` — a v2 ``/traffic-flows`` record whose matched
  policy is ``INTRUSION_PREVENTION``. Verified on Network 10.6, where these
  records carry an ``ips`` block (signature, signature_id, category_name,
  advanced_information, relevant_cve, alarm_category_potential_risk) and the
  legacy ``/stat/ips/event`` endpoint returns nothing.
- ``ips_event_from_legacy`` — a legacy ``/stat/ips/event`` record from
  controllers without the flows API. Field names follow the pre-10.x
  ``inner_alert_*`` shape; not verified against a live pre-10.x controller.

Read-only; MUTABLE_FIELDS = frozenset().
"""

from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field

IPS_POLICY_TYPE = "INTRUSION_PREVENTION"
SOURCE_TRAFFIC_FLOWS = "traffic_flows"
SOURCE_LEGACY = "legacy_ips_events"

# "IPS Alert 2: Misc Attack. Signature ..." -> "Misc Attack"
_CLASSIFICATION = re.compile(r"^IPS Alert \d+:\s*([^.]+)\.")


def _read_only(description: str) -> Any:
    return Field(default=None, description=description, json_schema_extra={"mutable": False})


class IpsEndpoint(BaseModel):
    """One side of an IPS match."""

    ip: Optional[str] = _read_only("IP address")
    port: Optional[int] = _read_only("Transport port")
    region: Optional[str] = _read_only("Country code (internet endpoints)")
    name: Optional[str] = _read_only("Client or host name (LAN endpoints)")
    mac: Optional[str] = _read_only("MAC address (LAN endpoints)")
    network_name: Optional[str] = _read_only("Network name (LAN endpoints)")


class IpsEvent(BaseModel):
    """A single IPS/IDS signature match."""

    id: Optional[str] = _read_only("Record ID")
    time: Optional[int] = _read_only("Match time (epoch ms)")
    action: Optional[str] = _read_only("What the gateway did: 'allowed' or 'blocked'")
    risk: Optional[str] = _read_only("Risk band (low/medium/high)")
    direction: Optional[str] = _read_only("Flow direction (incoming/outgoing)")
    protocol: Optional[str] = _read_only("Transport protocol")
    signature: Optional[str] = _read_only("Signature name, e.g. 'ET DROP Dshield Block Listed Source group 1'")
    signature_id: Optional[int] = _read_only("Signature ID (SID)")
    category: Optional[str] = _read_only(
        "Threat category code, matching the threat management enabled_categories codes (e.g. 'dshield')"
    )
    classification: Optional[str] = _read_only("Alert classification, e.g. 'Misc Attack'")
    rule_set: Optional[str] = _read_only("Matched rule set, e.g. 'DShield Block List'")
    cve: Optional[str] = _read_only("Related CVE, when the signature names one")
    potential_risk: Optional[str] = _read_only("Controller's description of what the match may indicate")
    count: Optional[int] = _read_only("Aggregated session count")
    source: IpsEndpoint = Field(default_factory=IpsEndpoint, json_schema_extra={"mutable": False})
    destination: IpsEndpoint = Field(default_factory=IpsEndpoint, json_schema_extra={"mutable": False})
    record_source: str = Field(
        default=SOURCE_TRAFFIC_FLOWS,
        description="Where the record came from: 'traffic_flows' or 'legacy_ips_events'",
        json_schema_extra={"mutable": False},
    )


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _flow_endpoint(raw: Any) -> IpsEndpoint:
    raw = _dict(raw)
    return IpsEndpoint(
        ip=_str(raw.get("ip")),
        port=_int(raw.get("port")),
        region=_str(raw.get("region")),
        name=_str(raw.get("client_name")) or _str(raw.get("host_name")),
        mac=_str(raw.get("mac")),
        network_name=_str(raw.get("network_name")),
    )


def _ips_policy(raw_flow: dict) -> dict:
    for policy in raw_flow.get("policies") or []:
        if isinstance(policy, dict) and policy.get("type") == IPS_POLICY_TYPE:
            return policy
    return {}


def ips_event_from_flow(raw: Any) -> IpsEvent:
    """Project an IPS-matched v2 traffic-flow record."""
    flow = _dict(raw)
    ips = _dict(flow.get("ips"))
    details = _str(ips.get("advanced_information"))
    match = _CLASSIFICATION.match(details or "")
    return IpsEvent(
        id=_str(flow.get("id")),
        time=_int(flow.get("time")),
        action=_str(flow.get("action")),
        risk=_str(flow.get("risk")),
        direction=_str(flow.get("direction")),
        protocol=_str(flow.get("protocol")),
        signature=_str(ips.get("signature")),
        signature_id=_int(ips.get("signature_id")),
        category=_str(ips.get("category_name")),
        classification=_str(ips.get("signature_class")) or (match.group(1).strip() if match else None),
        rule_set=_str(_ips_policy(flow).get("name")),
        cve=_str(ips.get("relevant_cve")),
        potential_risk=_str(ips.get("alarm_category_potential_risk")),
        count=_int(flow.get("count")),
        source=_flow_endpoint(flow.get("source")),
        destination=_flow_endpoint(flow.get("destination")),
        record_source=SOURCE_TRAFFIC_FLOWS,
    )


def ips_event_from_legacy(raw: Any) -> IpsEvent:
    """Project a legacy ``/stat/ips/event`` record."""
    event = _dict(raw)
    action = _str(event.get("inner_alert_action"))
    return IpsEvent(
        id=_str(event.get("_id")),
        time=_int(event.get("time")) or _int(event.get("timestamp")),
        action=action.lower() if action else None,
        protocol=_str(event.get("proto")),
        signature=_str(event.get("inner_alert_signature")),
        signature_id=_int(event.get("inner_alert_signature_id")),
        category=_str(event.get("catname")),
        classification=_str(event.get("inner_alert_category")),
        source=IpsEndpoint(
            ip=_str(event.get("src_ip")),
            port=_int(event.get("src_port")),
            region=_str(event.get("srcipCountry")),
            mac=_str(event.get("src_mac")),
        ),
        destination=IpsEndpoint(
            ip=_str(event.get("dest_ip")),
            port=_int(event.get("dest_port")),
            region=_str(event.get("dstipCountry")),
            mac=_str(event.get("dst_mac")),
        ),
        record_source=SOURCE_LEGACY,
    )


MUTABLE_FIELDS: frozenset[str] = frozenset()
READ_ONLY_FIELDS: frozenset[str] = frozenset(IpsEvent.model_fields.keys())
