"""Fixture e2e tests for network/vpn resolvers.

# tool: unifi_list_vpn_clients
# tool: unifi_get_vpn_client_details
# tool: unifi_list_vpn_servers
# tool: unifi_get_vpn_server_details
# tool: unifi_list_wireguard_peers
# tool: unifi_get_wireguard_peer_details
# tool: unifi_list_remote_vpn_clients
# tool: unifi_list_site_to_site_vpns
"""

from __future__ import annotations

import pytest

from tests.graphql.fixtures._helpers import (
    bootstrap,
    graphql_query,
    stub_managers,
)


@pytest.mark.asyncio
async def test_vpn_clients_list(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_vpn_clients"): [
                {"_id": "vc-1", "name": "Home-VPN"},
                {"_id": "vc-2", "name": "Work-VPN"},
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ vpnClients(controller: "{cid}", limit: 10) {{
            items {{ id name }}
        }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    items = body["data"]["network"]["vpnClients"]["items"]
    assert len(items) == 2
    names = {it["name"] for it in items}
    assert names == {"Home-VPN", "Work-VPN"}


@pytest.mark.asyncio
async def test_vpn_client_detail(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_vpn_clients"): [
                {"_id": "vc-1", "name": "Home-VPN"},
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ vpnClient(controller: "{cid}", id: "vc-1") {{
            id name
        }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    assert body["data"]["network"]["vpnClient"]["id"] == "vc-1"


@pytest.mark.asyncio
async def test_vpn_servers_list(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_vpn_servers"): [
                {"_id": "vs-1", "name": "Main-Server"},
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ vpnServers(controller: "{cid}", limit: 10) {{
            items {{ id name }}
        }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    items = body["data"]["network"]["vpnServers"]["items"]
    assert len(items) == 1
    assert items[0]["name"] == "Main-Server"


@pytest.mark.asyncio
async def test_vpn_server_detail(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_vpn_servers"): [
                {"_id": "vs-1", "name": "Main-Server"},
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ vpnServer(controller: "{cid}", id: "vs-1") {{
            id name
        }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    assert body["data"]["network"]["vpnServer"]["id"] == "vs-1"


_PEERS = [
    {"_id": "peer-1", "name": "Laptop", "network_id": "s-1", "preshared_key": "TEST_FAKE_PSK"},
    {"_id": "peer-2", "name": "Phone", "network_id": "s-1"},
]


@pytest.mark.asyncio
async def test_wireguard_peers_list_and_detail(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(monkeypatch, {("network", "vpn_manager", "get_wireguard_peers"): _PEERS})
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{
            wireguardPeers(controller: "{cid}", limit: 10) {{ items {{ id name presharedKeyEnabled }} }}
            wireguardPeer(controller: "{cid}", id: "peer-2") {{ id name }}
        }}
    }}''',
    )
    assert body.get("errors") is None, body
    items = body["data"]["network"]["wireguardPeers"]["items"]
    assert {it["name"]: it["presharedKeyEnabled"] for it in items} == {"Laptop": True, "Phone": False}
    assert body["data"]["network"]["wireguardPeer"] == {"id": "peer-2", "name": "Phone"}
    assert "TEST_FAKE_PSK" not in str(body)


@pytest.mark.asyncio
async def test_remote_vpn_clients_list(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_remote_vpn_clients"): [
                {
                    "id": "wgsrv1:k1:1",
                    "name": "k1",
                    "display_name": "Laptop",
                    "status": "online",
                    "ip": "192.0.2.4",
                    "vpn_type": "wireguard-server",
                },
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ remoteVpnClients(controller: "{cid}", includeOffline: true) {{
            items {{ name online tunnelIp publicKey }}
        }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    assert body["data"]["network"]["remoteVpnClients"]["items"] == [
        {"name": "Laptop", "online": True, "tunnelIp": "192.0.2.4", "publicKey": "k1"}
    ]


@pytest.mark.asyncio
async def test_site_to_site_vpns_list(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await bootstrap(tmp_path, product="network")
    stub_managers(
        monkeypatch,
        {
            ("network", "vpn_manager", "get_site_to_site_vpns"): [
                {"_id": "s2s-1", "name": "Branch", "vpn_type": "ipsec-vpn", "ipsec_peer_ip": "203.0.113.9"},
            ],
        },
    )
    body = await graphql_query(
        app,
        key,
        f'''{{
        network {{ siteToSiteVpns(controller: "{cid}") {{ items {{ id vpnType peerAddress }} }} }}
    }}''',
    )
    assert body.get("errors") is None, body
    assert body["data"]["network"]["siteToSiteVpns"]["items"] == [
        {"id": "s2s-1", "vpnType": "ipsec-vpn", "peerAddress": "203.0.113.9"}
    ]
