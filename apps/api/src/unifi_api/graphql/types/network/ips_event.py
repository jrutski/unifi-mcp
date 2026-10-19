"""Strawberry types for network IPS/IDS signature matches.

Read shape emitted by ``StatsManager.get_ips_events()`` (LIST of
``IpsEvent.model_dump(exclude_none=True)`` dicts from ``unifi-core``). The
projection itself lives in ``unifi_core.network.models.ips_events``; these
types only re-shape its output.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import strawberry
from unifi_core.network.models.ips_events import IpsEvent as CoreIpsEvent

# REST and GraphQL read one 24-hour window and paginate it locally.
IPS_EVENTS_WINDOW_HOURS = 24
IPS_EVENTS_FETCH_LIMIT = 1000


@strawberry.type(description="One side of an IPS signature match.")
class IpsEndpoint:
    ip: str | None = None
    port: int | None = None
    region: str | None = strawberry.field(default=None, description="Country code (internet endpoints).")
    name: str | None = None
    mac: str | None = None
    network_name: str | None = None


@strawberry.type(description="An IPS/IDS signature match.")
class IpsEvent:
    id: strawberry.ID | None = None
    time: int | None = strawberry.field(default=None, description="Match time (epoch ms).")
    action: str | None = strawberry.field(default=None, description="'allowed' or 'blocked'.")
    risk: str | None = None
    direction: str | None = None
    protocol: str | None = None
    signature: str | None = None
    signature_id: int | None = strawberry.field(default=None, description="Signature ID (SID).")
    category: str | None = strawberry.field(default=None, description="Threat category code, e.g. 'dshield'.")
    classification: str | None = None
    rule_set: str | None = None
    cve: str | None = None
    potential_risk: str | None = None
    count: int | None = None
    source: IpsEndpoint = strawberry.field(default_factory=IpsEndpoint)
    destination: IpsEndpoint = strawberry.field(default_factory=IpsEndpoint)
    record_source: str | None = strawberry.field(default=None, description="'traffic_flows' or 'legacy_ips_events'.")

    @classmethod
    def render_hint(cls, kind: str) -> dict:
        return {
            "kind": kind,
            "primary_key": "id",
            "display_columns": ["time", "action", "signature", "source", "destination"],
            "sort_default": "time:desc",
        }

    @classmethod
    def from_manager_output(cls, record: Any) -> "IpsEvent":
        core = CoreIpsEvent.model_validate(record) if isinstance(record, dict) else CoreIpsEvent()
        data = core.model_dump()
        return cls(
            **{key: value for key, value in data.items() if key not in ("source", "destination")},
            source=IpsEndpoint(**data["source"]),
            destination=IpsEndpoint(**data["destination"]),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@strawberry.type(description="Paginated page of IPS signature matches.")
class IpsEventPage:
    items: list[IpsEvent]
    next_cursor: str | None = None
