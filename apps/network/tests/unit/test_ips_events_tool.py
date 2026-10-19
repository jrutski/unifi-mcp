"""unifi_get_ips_events: parameter mapping, summary counts and error envelopes."""

from unittest.mock import AsyncMock, MagicMock

import pytest

EVENTS = [
    {"id": "a", "action": "blocked", "signature": "ET A"},
    {"id": "b", "action": "allowed", "signature": "ET B"},
]


def _manager(**kwargs) -> MagicMock:
    manager = MagicMock()
    manager._connection.site = "default"
    manager.get_ips_events = AsyncMock(**kwargs)
    return manager


def test_tool_registered_read_only():
    from unifi_network_mcp.runtime import server
    from unifi_network_mcp.tools import stats  # noqa: F401 - decorator registration

    tool = server._tool_manager._tools["unifi_get_ips_events"]
    assert tool.annotations.read_only_hint is True
    assert "action" in tool.parameters["properties"]


@pytest.mark.asyncio
async def test_tool_maps_duration_and_action_and_counts_blocked(monkeypatch):
    from unifi_network_mcp.tools import stats

    manager = _manager(return_value=EVENTS)
    monkeypatch.setattr(stats, "stats_manager", manager)

    result = await stats.get_ips_events(duration="weekly", limit=20, action="blocked")

    manager.get_ips_events.assert_awaited_once_with(duration_hours=168, limit=20, action="blocked")
    assert result["success"] is True
    assert result["count"] == 2
    assert result["blocked_count"] == 1
    assert result["events"] == EVENTS


@pytest.mark.asyncio
async def test_tool_echoes_validation_and_read_errors(monkeypatch):
    from unifi_network_mcp.tools import stats

    monkeypatch.setattr(
        stats, "stats_manager", _manager(side_effect=ValueError("action must be 'allowed' or 'blocked'"))
    )
    assert await stats.get_ips_events(action="dropped") == {
        "success": False,
        "error": "action must be 'allowed' or 'blocked'",
    }

    monkeypatch.setattr(
        stats, "stats_manager", _manager(side_effect=RuntimeError("Failed to read IPS events from traffic flows"))
    )
    assert (await stats.get_ips_events())["error"] == "Failed to read IPS events from traffic flows"


@pytest.mark.asyncio
async def test_tool_hides_unexpected_exception_text(monkeypatch):
    from unifi_network_mcp.tools import stats

    monkeypatch.setattr(stats, "stats_manager", _manager(side_effect=ConnectionError("controller said 198.51.100.9")))

    result = await stats.get_ips_events()

    assert result == {"success": False, "error": "Failed to get IPS events (ConnectionError)"}
