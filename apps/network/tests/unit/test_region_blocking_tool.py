"""Registration and Core delegation for the Region Blocking read tool."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_core.network.models.region_blocking import RegionBlocking


def test_tool_registered_read_only_with_session_auth():
    from unifi_network_mcp.runtime import server
    from unifi_network_mcp.tools import system  # noqa: F401 - decorator registration

    tool = server._tool_manager._tools["unifi_get_region_blocking"]
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False
    assert "REGION_BLOCKING" in tool.description


@pytest.mark.asyncio
async def test_tool_returns_projection(monkeypatch):
    from unifi_network_mcp.tools import system

    manager = MagicMock()
    manager._connection.site = "default"
    manager.get_region_blocking = AsyncMock(
        return_value=RegionBlocking(enabled=True, action="allow", countries=["US"], traffic_direction="ingress")
    )
    monkeypatch.setattr(system, "system_manager", manager)

    result = await system.get_region_blocking()

    assert result == {
        "success": True,
        "site": "default",
        "region_blocking": {"enabled": True, "action": "allow", "countries": ["US"], "traffic_direction": "ingress"},
    }


@pytest.mark.asyncio
async def test_tool_echoes_core_not_found_message(monkeypatch):
    from unifi_network_mcp.tools import system

    manager = MagicMock()
    manager.get_region_blocking = AsyncMock(
        side_effect=RuntimeError("Region Blocking settings were not found on this controller")
    )
    monkeypatch.setattr(system, "system_manager", manager)

    result = await system.get_region_blocking()

    assert result == {"success": False, "error": "Region Blocking settings were not found on this controller"}


@pytest.mark.asyncio
async def test_tool_hides_unexpected_exception_text(monkeypatch):
    from unifi_network_mcp.tools import system

    manager = MagicMock()
    manager.get_region_blocking = AsyncMock(side_effect=ConnectionError("controller said 192.0.2.10"))
    monkeypatch.setattr(system, "system_manager", manager)

    result = await system.get_region_blocking()

    assert result == {"success": False, "error": "Failed to get region blocking settings"}
