"""SystemManager.get_region_blocking: usg_geo first, pre-10.x usg fallback."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from unifi_core.network.managers.system_manager import SystemManager
from unifi_core.network.models.region_blocking import RegionBlocking

USG_GEO = {
    "key": "usg_geo",
    "ip_filtering": {"enabled": True, "action": "allow", "countries": "US", "traffic_direction": "ingress"},
}
USG_10X = {"key": "usg", "syn_cookies": True}
USG_LEGACY = {
    "key": "usg",
    "geo_ip_filtering_enabled": True,
    "geo_ip_filtering_block": "block",
    "geo_ip_filtering_countries": "CN",
    "geo_ip_filtering_traffic_direction": "both",
}


def _manager(responses: dict) -> tuple[SystemManager, MagicMock]:
    conn = MagicMock()
    conn.site = "default"
    conn.get_cached = MagicMock(return_value=None)
    conn._update_cache = MagicMock()

    async def request(api_request):
        value = responses[api_request.path]
        if isinstance(value, Exception):
            raise value
        return value

    conn.request = AsyncMock(side_effect=request)
    return SystemManager(conn), conn


def _paths(conn: MagicMock) -> list[str]:
    return [call.args[0].path for call in conn.request.call_args_list]


async def test_reads_usg_geo_setting() -> None:
    manager, conn = _manager({"/get/setting/usg_geo": [USG_GEO]})

    result = await manager.get_region_blocking()

    assert result == RegionBlocking(enabled=True, action="allow", countries=["US"], traffic_direction="ingress")
    assert _paths(conn) == ["/get/setting/usg_geo"]


async def test_falls_back_to_legacy_usg_fields() -> None:
    manager, conn = _manager({"/get/setting/usg_geo": [], "/get/setting/usg": [USG_LEGACY]})

    result = await manager.get_region_blocking()

    assert result == RegionBlocking(enabled=True, action="block", countries=["CN"], traffic_direction="both")
    assert _paths(conn) == ["/get/setting/usg_geo", "/get/setting/usg"]


async def test_not_found_when_neither_shape_is_present() -> None:
    manager, _ = _manager({"/get/setting/usg_geo": [], "/get/setting/usg": [USG_10X]})

    with pytest.raises(RuntimeError, match="not found"):
        await manager.get_region_blocking()


async def test_controller_failure_is_logged_without_message(caplog) -> None:
    manager, _ = _manager({"/get/setting/usg_geo": ConnectionError("controller said 192.0.2.10")})

    with pytest.raises(RuntimeError, match="Failed to read region blocking settings"):
        await manager.get_region_blocking()

    assert "ConnectionError" in caplog.text
    assert "192.0.2.10" not in caplog.text
