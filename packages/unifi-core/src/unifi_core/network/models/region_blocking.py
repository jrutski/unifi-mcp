"""Typed CyberSecure Region Blocking (GeoIP filtering) settings.

Read shape of the ``usg_geo`` site setting (GET ``/get/setting/usg_geo``),
verified on Network 10.6, where the controller stores Region Blocking as an
``ip_filtering`` object:

    {"key": "usg_geo", "ip_filtering": {"enabled": true, "action": "allow",
     "countries": "US", "traffic_direction": "ingress"}}

Older firmware kept the same values as ``geo_ip_filtering_*`` fields on the
``usg`` setting; 10.x no longer returns them there.

Read-only; MUTABLE_FIELDS = frozenset().
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

REGION_BLOCKING_SETTING_KEY = "usg_geo"


def _read_only(description: str) -> Any:
    return Field(default=None, description=description, json_schema_extra={"mutable": False})


class RegionBlocking(BaseModel):
    """Site-wide Region Blocking configuration."""

    enabled: Optional[bool] = _read_only("Whether Region Blocking is enabled.")
    action: Optional[str] = _read_only(
        "'block' drops traffic from the listed countries; 'allow' drops traffic from every other country."
    )
    countries: list[str] = Field(
        default_factory=list,
        description="ISO 3166-1 alpha-2 country codes the action applies to.",
        json_schema_extra={"mutable": False},
    )
    traffic_direction: Optional[str] = _read_only(
        "Traffic the rule applies to: 'both', 'ingress' (incoming) or 'egress' (outgoing)."
    )


def _optional_str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _country_codes(value: Any) -> list[str]:
    """Normalize the controller's CSV (or list) of country codes."""
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = [item for item in value if isinstance(item, str)]
    else:
        return []
    return [item.strip().upper() for item in items if item.strip()]


def region_blocking_from_controller(raw: Any) -> RegionBlocking:
    """Project a raw ``usg_geo`` setting record into ``RegionBlocking``."""
    record = raw if isinstance(raw, dict) else {}
    filtering = record.get("ip_filtering")
    if not isinstance(filtering, dict):
        filtering = {}
    enabled = filtering.get("enabled")
    return RegionBlocking(
        enabled=enabled if isinstance(enabled, bool) else None,
        action=_optional_str(filtering.get("action")),
        countries=_country_codes(filtering.get("countries")),
        traffic_direction=_optional_str(filtering.get("traffic_direction")),
    )


def region_blocking_from_legacy_usg(raw: Any) -> RegionBlocking:
    """Project the pre-10.x ``geo_ip_filtering_*`` fields of the ``usg`` setting."""
    record = raw if isinstance(raw, dict) else {}
    return region_blocking_from_controller(
        {
            "ip_filtering": {
                "enabled": record.get("geo_ip_filtering_enabled"),
                "action": record.get("geo_ip_filtering_block"),
                "countries": record.get("geo_ip_filtering_countries"),
                "traffic_direction": record.get("geo_ip_filtering_traffic_direction"),
            }
        }
    )


def has_legacy_region_blocking(raw: Any) -> bool:
    """True when a ``usg`` setting record still carries GeoIP filtering fields."""
    return isinstance(raw, dict) and any(key.startswith("geo_ip_filtering_") for key in raw)


MUTABLE_FIELDS: frozenset[str] = frozenset()
READ_ONLY_FIELDS: frozenset[str] = frozenset(RegionBlocking.model_fields.keys())
