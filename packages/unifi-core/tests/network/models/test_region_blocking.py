"""Region Blocking projection from the ``usg_geo`` setting (and pre-10.x ``usg``)."""

from unifi_core.network.models.region_blocking import (
    MUTABLE_FIELDS,
    RegionBlocking,
    has_legacy_region_blocking,
    region_blocking_from_controller,
    region_blocking_from_legacy_usg,
)

# Shape returned by Network 10.6 for GET /get/setting/usg_geo (synthetic IDs).
USG_GEO = {
    "_id": "000000000000000000000001",
    "site_id": "000000000000000000000002",
    "key": "usg_geo",
    "ip_filtering": {"action": "allow", "countries": "US", "enabled": True, "traffic_direction": "ingress"},
}


def test_projects_usg_geo_record() -> None:
    assert region_blocking_from_controller(USG_GEO) == RegionBlocking(
        enabled=True, action="allow", countries=["US"], traffic_direction="ingress"
    )


def test_country_csv_is_split_trimmed_and_upper_cased() -> None:
    raw = {"ip_filtering": {"countries": " cn, RU ,,kp ", "enabled": False}}
    assert region_blocking_from_controller(raw).countries == ["CN", "RU", "KP"]


def test_country_list_is_accepted() -> None:
    raw = {"ip_filtering": {"countries": ["cn", 7, "ru"]}}
    assert region_blocking_from_controller(raw).countries == ["CN", "RU"]


def test_malformed_values_become_unknown() -> None:
    raw = {"ip_filtering": {"enabled": "yes", "action": 1, "countries": None, "traffic_direction": "  "}}
    assert region_blocking_from_controller(raw) == RegionBlocking()
    assert region_blocking_from_controller(None) == RegionBlocking()
    assert region_blocking_from_controller({"ip_filtering": "nope"}) == RegionBlocking()


def test_projection_carries_no_controller_ids() -> None:
    dumped = region_blocking_from_controller(USG_GEO).model_dump()
    assert set(dumped) == {"enabled", "action", "countries", "traffic_direction"}


def test_legacy_usg_fields() -> None:
    legacy = {
        "key": "usg",
        "geo_ip_filtering_enabled": True,
        "geo_ip_filtering_block": "block",
        "geo_ip_filtering_countries": "CN,RU",
        "geo_ip_filtering_traffic_direction": "both",
    }
    assert has_legacy_region_blocking(legacy)
    assert not has_legacy_region_blocking({"key": "usg", "syn_cookies": True})
    assert region_blocking_from_legacy_usg(legacy) == RegionBlocking(
        enabled=True, action="block", countries=["CN", "RU"], traffic_direction="both"
    )


def test_read_only() -> None:
    assert MUTABLE_FIELDS == frozenset()
