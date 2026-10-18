"""VPN read paths: WireGuard peers, remote-access clients and site-to-site tunnels.

Fixtures mirror the field names returned by Network 10.6.106 (v2
``wireguard/users`` and ``vpn/users``) with synthetic values.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from unifi_core.exceptions import UniFiNotFoundError
from unifi_core.network.managers.vpn_manager import VpnManager

SERVER_ID = "6938568a00b1c804e8141bc1"
OTHER_SERVER_ID = "6938568a00b1c804e8141bc2"

WG_SERVER = {"_id": SERVER_ID, "name": "WG Server", "purpose": "remote-user-vpn", "vpn_type": "wireguard-server"}
SITE_VPN = {"_id": "s2s-1", "name": "Branch", "purpose": "site-vpn", "vpn_type": "ipsec-vpn"}
LAN = {"_id": "lan-1", "name": "LAN", "purpose": "corporate"}

PEERS = [
    {"_id": "peer-1", "name": "Laptop", "network_id": SERVER_ID, "interface_ip": "192.0.2.2", "allowed_ips": []},
    {"_id": "peer-2", "name": "Branch", "network_id": OTHER_SERVER_ID, "interface_ip": "192.0.2.3", "allowed_ips": []},
]

VPN_USERS = [
    {"id": "wgsrv1:key1:1", "display_name": "Laptop", "status": "online", "network_id": SERVER_ID},
    {"id": "wgsrv1:key2:2", "display_name": "Phone", "status": "offline", "network_id": SERVER_ID},
    {"id": "wgsrv2:key3:3", "display_name": "Branch", "status": "online", "network_id": OTHER_SERVER_ID},
]


def _connection() -> MagicMock:
    conn = MagicMock()
    conn.site = "default"
    conn.request = AsyncMock()
    conn.get_cached = MagicMock(return_value=None)
    conn._update_cache = MagicMock()
    return conn


def _paths(conn: MagicMock) -> list[str]:
    return [call.args[0].path for call in conn.request.call_args_list]


async def test_get_wireguard_peers_reads_v2_collection_for_all_servers() -> None:
    conn = _connection()
    conn.request.return_value = PEERS

    peers = await VpnManager(conn).get_wireguard_peers()

    assert peers == PEERS
    assert _paths(conn) == ["/wireguard/users"]
    assert conn.request.call_args.args[0].method == "get"
    conn._update_cache.assert_called_once_with("wireguard_peers_default", PEERS)


async def test_get_wireguard_peers_filters_by_known_server_without_putting_id_in_path() -> None:
    conn = _connection()
    conn.request.side_effect = [[WG_SERVER, LAN], PEERS]

    peers = await VpnManager(conn).get_wireguard_peers(server_id=SERVER_ID)

    assert [peer["_id"] for peer in peers] == ["peer-1"]
    assert _paths(conn) == ["/rest/networkconf", "/wireguard/users"]


async def test_get_wireguard_peers_rejects_unknown_server() -> None:
    conn = _connection()
    conn.request.return_value = [WG_SERVER]

    with pytest.raises(UniFiNotFoundError):
        await VpnManager(conn).get_wireguard_peers(server_id="not-a-server")

    assert _paths(conn) == ["/rest/networkconf"]


async def test_get_wireguard_peers_uses_cache() -> None:
    conn = _connection()
    conn.get_cached.return_value = PEERS

    assert await VpnManager(conn).get_wireguard_peers() == PEERS
    conn.request.assert_not_called()


@pytest.mark.parametrize("response", [{"unexpected": "shape"}, ["not-a-dict"], None])
async def test_v2_reads_fail_closed_on_malformed_response(response) -> None:
    conn = _connection()
    conn.request.return_value = response

    with pytest.raises(RuntimeError, match="malformed"):
        await VpnManager(conn).get_wireguard_peers()
    conn._update_cache.assert_not_called()


async def test_v2_reads_accept_data_envelope() -> None:
    conn = _connection()
    conn.request.return_value = {"data": VPN_USERS}

    clients = await VpnManager(conn).get_remote_vpn_clients(include_offline=True)

    assert clients == VPN_USERS


async def test_v2_read_failure_is_logged_without_message(caplog) -> None:
    conn = _connection()
    conn.request.side_effect = ConnectionError("controller said 192.0.2.10 Laptop")

    with pytest.raises(ConnectionError):
        await VpnManager(conn).get_remote_vpn_clients()

    assert "ConnectionError" in caplog.text
    assert "192.0.2.10" not in caplog.text
    assert "Laptop" not in caplog.text


async def test_get_wireguard_peer_details_found_and_missing() -> None:
    conn = _connection()
    conn.request.return_value = PEERS
    manager = VpnManager(conn)

    assert (await manager.get_wireguard_peer_details("peer-2"))["name"] == "Branch"
    with pytest.raises(UniFiNotFoundError):
        await manager.get_wireguard_peer_details("peer-404")


async def test_get_remote_vpn_clients_defaults_to_connected_users() -> None:
    conn = _connection()
    conn.request.return_value = VPN_USERS

    clients = await VpnManager(conn).get_remote_vpn_clients()

    assert [client["display_name"] for client in clients] == ["Laptop", "Branch"]
    assert _paths(conn) == ["/vpn/users"]


async def test_get_remote_vpn_clients_include_offline_and_server_filter() -> None:
    conn = _connection()
    conn.request.side_effect = [[WG_SERVER], VPN_USERS]

    clients = await VpnManager(conn).get_remote_vpn_clients(include_offline=True, server_id=SERVER_ID)

    assert [client["display_name"] for client in clients] == ["Laptop", "Phone"]


async def test_get_remote_vpn_clients_rejects_unknown_server() -> None:
    conn = _connection()
    conn.request.return_value = [WG_SERVER]

    with pytest.raises(UniFiNotFoundError):
        await VpnManager(conn).get_remote_vpn_clients(server_id="not-a-server")


async def test_get_site_to_site_vpns_returns_only_site_vpn_records() -> None:
    conn = _connection()
    conn.request.return_value = [WG_SERVER, SITE_VPN, LAN, {**SITE_VPN, "_id": "s2s-2", "purpose": " Site-VPN "}]
    manager = VpnManager(conn)

    tunnels = await manager.get_site_to_site_vpns()

    assert [tunnel["_id"] for tunnel in tunnels] == ["s2s-1", "s2s-2"]


async def test_site_to_site_vpns_are_absent_from_client_and_server_lists() -> None:
    """Documents why a dedicated read exists: the client/server split skips site-vpn."""
    conn = _connection()
    conn.request.return_value = [WG_SERVER, SITE_VPN]
    manager = VpnManager(conn)

    assert await manager.get_vpn_clients() == []
    assert await manager.get_vpn_servers() == [WG_SERVER]


async def test_vpn_server_write_invalidates_peer_and_session_caches() -> None:
    conn = _connection()
    conn._invalidate_cache = MagicMock()
    conn.request.side_effect = [[WG_SERVER], {}, [{**WG_SERVER, "enabled": False}]]

    await VpnManager(conn).update_vpn_server_state(SERVER_ID, False)

    invalidated = {call.args[0] for call in conn._invalidate_cache.call_args_list}
    assert {"wireguard_peers_default", "remote_vpn_clients_default"} <= invalidated
