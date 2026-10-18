"""Unit tests for the Network VpnClient + VpnServer CRUD domain models."""

from __future__ import annotations

import pytest
from unifi_core.network.models.vpn import (
    VPNCLIENT_MUTABLE_FIELDS,
    VPNCLIENT_READ_ONLY_FIELDS,
    VPNSERVER_MUTABLE_FIELDS,
    VPNSERVER_READ_ONLY_FIELDS,
    RemoteVpnClient,
    SiteToSiteVpn,
    VpnClient,
    VpnServer,
    WireGuardPeer,
    from_controller,
    is_vpn_network,
    remote_vpn_client_from_controller,
    site_to_site_vpn_from_controller,
    to_controller_create,
    to_controller_update,
    vpn_server_from_controller,
    wireguard_peer_from_controller,
)


class TestVpnClassification:
    def test_recognizes_all_networkconf_vpn_purposes(self) -> None:
        for purpose in ("site-vpn", "remote-user-vpn", "vpn-client", "vpn-server"):
            assert is_vpn_network({"purpose": purpose}) is True

    def test_recognizes_vpn_type_fallbacks(self) -> None:
        assert is_vpn_network({"purpose": "corporate", "vpn_type": "wireguard-client"}) is True
        assert is_vpn_network({"purpose": "corporate", "vpn_type": "openvpn-server"}) is True

    def test_rejects_non_vpn_network(self) -> None:
        assert is_vpn_network({"purpose": "corporate"}) is False


class TestVpnClientFieldSets:
    def test_mutable_fields_contains_expected(self) -> None:
        for field in ("name", "enabled", "type", "server_address"):
            assert field in VPNCLIENT_MUTABLE_FIELDS, f"Expected {field!r} in VPNCLIENT_MUTABLE_FIELDS"

    def test_mutable_fields_excludes_id(self) -> None:
        assert "id" not in VPNCLIENT_MUTABLE_FIELDS

    def test_read_only_fields_contains_id(self) -> None:
        assert "id" in VPNCLIENT_READ_ONLY_FIELDS

    def test_mutable_and_read_only_are_disjoint(self) -> None:
        overlap = VPNCLIENT_MUTABLE_FIELDS & VPNCLIENT_READ_ONLY_FIELDS
        assert not overlap, f"Fields in both sets: {overlap}"

    def test_cover_all_model_fields(self) -> None:
        all_fields = frozenset(VpnClient.model_fields.keys())
        assert VPNCLIENT_MUTABLE_FIELDS | VPNCLIENT_READ_ONLY_FIELDS == all_fields


class TestVpnServerFieldSets:
    def test_server_has_only_alternate_address_mutable_fields(self) -> None:
        assert VPNSERVER_MUTABLE_FIELDS == frozenset({"alternate_address_enabled", "alternate_address"})

    def test_remaining_server_fields_are_read_only(self) -> None:
        all_fields = frozenset(VpnServer.model_fields.keys())
        assert VPNSERVER_READ_ONLY_FIELDS == all_fields - VPNSERVER_MUTABLE_FIELDS


class TestFromControllerVpnClient:
    def test_wireguard_client(self) -> None:
        raw = {
            "_id": "vpn-c-1",
            "name": "WireGuard Home",
            "vpn_type": "wireguard-client",
            "enabled": True,
            "wireguard_client_peer_endpoint": "vpn.example.com:51820",
        }
        client = from_controller(raw)
        assert client.id == "vpn-c-1"
        assert client.name == "WireGuard Home"
        assert client.type == "wireguard-client"
        assert client.enabled is True
        assert client.server_address == "vpn.example.com:51820"

    def test_purpose_fallback_for_type(self) -> None:
        raw = {"_id": "vpn-c-2", "purpose": "vpn-client"}
        client = from_controller(raw)
        assert client.type == "vpn-client"

    def test_openvpn_server_address(self) -> None:
        raw = {"_id": "vpn-c-3", "openvpn_remote_host": "openvpn.example.com"}
        client = from_controller(raw)
        assert client.server_address == "openvpn.example.com"

    def test_handles_empty_dict(self) -> None:
        client = from_controller({})
        assert client.id is None
        assert client.name is None
        assert client.enabled is None


class TestVpnServerFromController:
    def test_wireguard_server(self) -> None:
        raw = {
            "_id": "vpn-s-1",
            "name": "WireGuard Server",
            "vpn_type": "wireguard-server",
            "enabled": True,
            "wireguard_server_listen_port": 51820,
            "wireguard_server_subnet": "10.8.0.0/24",
        }
        server = vpn_server_from_controller(raw)
        assert server.id == "vpn-s-1"
        assert server.name == "WireGuard Server"
        assert server.type == "wireguard-server"
        assert server.enabled is True
        assert server.listen_port == 51820
        assert server.allowed_subnets == ["10.8.0.0/24"]

    def test_allowed_subnets_as_list(self) -> None:
        raw = {"_id": "vpn-s-2", "allowed_subnets": ["10.8.0.0/24", "10.9.0.0/24"]}
        server = vpn_server_from_controller(raw)
        assert server.allowed_subnets == ["10.8.0.0/24", "10.9.0.0/24"]

    def test_handles_empty_dict(self) -> None:
        server = vpn_server_from_controller({})
        assert server.id is None
        assert server.listen_port is None
        assert server.allowed_subnets is None


class TestToControllerCreate:
    def test_maps_type_to_vpn_type(self) -> None:
        model = VpnClient(name="WG Client", type="wireguard-client")
        payload = to_controller_create(model)
        assert payload["vpn_type"] == "wireguard-client"
        assert "type" not in payload

    def test_excludes_id(self) -> None:
        model = VpnClient(id="should-not-appear", name="Test")
        payload = to_controller_create(model)
        assert "id" not in payload

    def test_omits_none_fields(self) -> None:
        model = VpnClient(name="Minimal")
        payload = to_controller_create(model)
        assert "server_address" not in payload
        assert "enabled" not in payload


class TestToControllerUpdate:
    def test_filters_out_id(self) -> None:
        result = to_controller_update({"id": "ignore-me", "enabled": True})
        assert "id" not in result
        assert result["enabled"] is True

    def test_maps_type_to_vpn_type(self) -> None:
        result = to_controller_update({"type": "wireguard-client"})
        assert "vpn_type" in result
        assert result["vpn_type"] == "wireguard-client"
        assert "type" not in result

    def test_drops_none_values(self) -> None:
        result = to_controller_update({"name": None, "enabled": False})
        assert "name" not in result
        assert result["enabled"] is False

    def test_drops_unrecognised_keys(self) -> None:
        result = to_controller_update({"unknown": "value", "name": "Valid"})
        assert "unknown" not in result
        assert result["name"] == "Valid"


# ---------------------------------------------------------------------------
# WireGuard peers / remote-access clients / site-to-site projections
# ---------------------------------------------------------------------------

_RAW_PEER = {
    "_id": "peer-1",
    "name": "Laptop",
    "network_id": "server-1",
    "interface_ip": "192.0.2.4",
    "allowed_ips": ["198.51.100.0/24"],
    "public_key": "TEST_FAKE_PUBLIC_KEY_aaaaaaaaaaaaaaaaaaaaaaaaaaa=",
    "preshared_key": "TEST_FAKE_PSK_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
}

_RAW_ONLINE_USER = {
    "id": "wgsrv1:TEST_FAKE_PUBLIC_KEY_aaaaaaaaaaaaaaaaaaaaaaaaaaa=:3232237572",
    "ip": "192.0.2.4",
    "name": "TEST_FAKE_PUBLIC_KEY_aaaaaaaaaaaaaaaaaaaaaaaaaaa=",
    "display_name": "Laptop",
    "status": "online",
    "type": "VPN",
    "uptime": 80,
    "assoc_time": 1792361835,
    "last_seen": 1792361832,
    "country_code": "US",
    "network_id": "server-1",
    "network_name": "WireGuard Server 1",
    "remote_ip": "203.0.113.40",
    "remote_port": 37868,
    "rx_bytes": 946893,
    "rx_bytes-r": 185,
    "tx_bytes": 1537077,
    "tx_bytes-r": 0,
    "usage_bytes": 2483970,
    "vpn_type": "wireguard-server",
}

_RAW_OFFLINE_USER = {
    "id": "wgsrv1:key:3232237571",
    "ip": "192.0.2.3",
    "name": "key",
    "display_name": "Phone",
    "status": "offline",
    "last_seen": 1791726824,
    "network_id": "server-1",
    "rx_bytes": 0,
    "tx_bytes": 0,
    "vpn_type": "wireguard-server",
}


class TestWireGuardPeerProjection:
    def test_maps_fields_and_never_carries_preshared_key(self) -> None:
        peer = wireguard_peer_from_controller(_RAW_PEER)
        assert peer == WireGuardPeer(
            id="peer-1",
            name="Laptop",
            server_id="server-1",
            interface_ip="192.0.2.4",
            allowed_ips=["198.51.100.0/24"],
            public_key=_RAW_PEER["public_key"],
            preshared_key_enabled=True,
        )
        assert _RAW_PEER["preshared_key"] not in str(peer.model_dump())

    @pytest.mark.parametrize("extra", [{}, {"preshared_key": ""}, {"preshared_key": None}])
    def test_preshared_key_enabled_false_when_absent_or_empty(self, extra) -> None:
        raw = {key: value for key, value in _RAW_PEER.items() if key != "preshared_key"} | extra
        assert wireguard_peer_from_controller(raw).preshared_key_enabled is False

    def test_all_fields_read_only(self) -> None:
        for field in WireGuardPeer.model_fields.values():
            assert field.json_schema_extra == {"mutable": False}


class TestRemoteVpnClientProjection:
    def test_online_wireguard_user(self) -> None:
        client = remote_vpn_client_from_controller(_RAW_ONLINE_USER)
        assert client.name == "Laptop"
        assert client.public_key == _RAW_ONLINE_USER["name"]
        assert client.online is True
        assert client.tunnel_ip == "192.0.2.4"
        assert client.remote_ip == "203.0.113.40"
        assert client.remote_port == 37868
        assert client.server_id == "server-1"
        assert client.server_name == "WireGuard Server 1"
        assert client.connected_since == "2026-10-18T22:17:15+00:00"
        assert client.uptime_seconds == 80
        assert client.rx_rate_bps == 185.0
        assert client.tx_rate_bps == 0.0

    def test_offline_user_has_no_session_fields(self) -> None:
        client = remote_vpn_client_from_controller(_RAW_OFFLINE_USER)
        assert client.online is False
        assert client.connected_since is None
        assert client.uptime_seconds is None
        assert client.rx_rate_bps is None
        assert client.last_seen is not None

    def test_unknown_status_is_not_coerced(self) -> None:
        assert remote_vpn_client_from_controller({"status": "pending"}).online is None
        assert remote_vpn_client_from_controller({}).online is None

    def test_non_wireguard_user_keeps_name_and_has_no_public_key(self) -> None:
        client = remote_vpn_client_from_controller({"name": "alice", "vpn_type": "openvpn-server"})
        assert client.name == "alice"
        assert client.public_key is None

    def test_wireguard_user_without_display_name_does_not_present_key_as_name(self) -> None:
        client = remote_vpn_client_from_controller({"name": "key", "vpn_type": "wireguard-server"})
        assert client.name is None
        assert client.public_key == "key"

    def test_rejects_wrongly_typed_counters(self) -> None:
        client = remote_vpn_client_from_controller({"uptime": True, "remote_port": "1", "assoc_time": -1})
        assert client.uptime_seconds is None
        assert client.remote_port is None
        assert client.connected_since is None

    def test_all_fields_read_only(self) -> None:
        for field in RemoteVpnClient.model_fields.values():
            assert field.json_schema_extra == {"mutable": False}


class TestSiteToSiteVpnProjection:
    def test_ipsec_tunnel(self) -> None:
        tunnel = site_to_site_vpn_from_controller(
            {
                "_id": "s2s-1",
                "name": "Branch",
                "purpose": "site-vpn",
                "vpn_type": "ipsec-vpn",
                "enabled": True,
                "ipsec_peer_ip": "203.0.113.9",
                "remote_vpn_subnets": ["198.51.100.0/24"],
                "x_ipsec_pre_shared_key": "TEST_FAKE_SECRET",
            }
        )
        assert tunnel == SiteToSiteVpn(
            id="s2s-1",
            name="Branch",
            enabled=True,
            vpn_type="ipsec-vpn",
            peer_address="203.0.113.9",
            remote_subnets=["198.51.100.0/24"],
        )
        assert "TEST_FAKE_SECRET" not in str(tunnel.model_dump())

    def test_openvpn_tunnel_peer_and_missing_enabled(self) -> None:
        tunnel = site_to_site_vpn_from_controller(
            {"_id": "s2s-2", "vpn_type": "openvpn-vpn", "openvpn_remote_host": "vpn.example.test"}
        )
        assert tunnel.peer_address == "vpn.example.test"
        assert tunnel.enabled is None
        assert tunnel.remote_subnets is None
