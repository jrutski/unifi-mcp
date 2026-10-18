"""
VPN configuration tools for Unifi Network MCP server.

This module provides MCP tools to interact with a Unifi Network Controller's VPN functions,
including managing VPN clients and servers.
"""

import logging
from typing import Annotated, Any, Dict, Optional

from mcp.types import ToolAnnotations
from pydantic import Field, WithJsonSchema

from unifi_core.confirmation import delete_preview, update_preview
from unifi_core.exceptions import UniFiNotFoundError
from unifi_core.network.models.vpn import (
    VpnAlternateAddressError,
    VpnAlternateAddressToolInput,
    alternate_address_view,
    remote_vpn_client_from_controller,
    site_to_site_vpn_from_controller,
    vpn_alternate_address_input_schema,
    wireguard_peer_from_controller,
)
from unifi_core.redaction import redact_sensitive_fields
from unifi_core.write_verification import format_tool_payload
from unifi_network_mcp.runtime import server, should_redact_sensitive_fields, vpn_manager

logger = logging.getLogger(__name__)


@server.tool(
    name="unifi_update_vpn_server_alternate_address",
    input_schema=vpn_alternate_address_input_schema(VpnAlternateAddressToolInput),
    description=(
        "Update the advertised alternate hostname or IPv4 address for a WireGuard VPN server. "
        "Pass only the fields you want to change — current values are automatically preserved. "
        "Requires Network session authentication and confirmation; verifies persistence after applying. "
        "MCP previews read live state; API action previews show submitted arguments only."
    ),
    permission_category="vpn_servers",
    permission_action="update",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_vpn_server_alternate_address(
    server_id: Annotated[str, Field(description="VPN server networkconf _id from unifi_list_vpn_servers")],
    update_data: Annotated[
        Dict[str, Any],
        WithJsonSchema(vpn_alternate_address_input_schema()),
    ],
    confirm: Annotated[
        bool, Field(description="Apply when true; otherwise return a live before/after preview")
    ] = False,
) -> Dict[str, Any]:
    """Preview or apply the narrow alternate-address update through the Core manager."""
    try:
        if not confirm:
            before, after = await vpn_manager.prepare_vpn_server_alternate_address(server_id, update_data)
            payload = update_preview(
                resource_type="vpn_server",
                resource_id=server_id,
                resource_name=server_id,
                current_state=before,
                updates=after,
            )
        else:
            result = await vpn_manager.update_vpn_server_alternate_address(server_id, update_data)
            payload = format_tool_payload(
                result, site=vpn_manager._connection.site, success_message="VPN server alternate address verified."
            )
        return redact_sensitive_fields(payload, redact_sensitive=should_redact_sensitive_fields())
    except VpnAlternateAddressError as exc:
        return {"success": False, "error": f"Failed to update VPN server alternate address: {exc}"}
    except Exception as exc:
        logger.error("Failed to update VPN server alternate address: %s", type(exc).__name__)
        return {
            "success": False,
            "error": "Failed to update VPN server alternate address: check the server, session authentication, "
            "and alternate_address_enabled (boolean) / alternate_address (hostname or IPv4) fields",
        }


@server.tool(
    name="unifi_list_vpn_clients",
    description=(
        "List outbound VPN client configurations: tunnels where the gateway connects out to an external VPN "
        "provider or server (WireGuard, OpenVPN). These are not people connected to your VPN server: for "
        "remote users and their live connection state use unifi_list_remote_vpn_clients, and for the peers "
        "configured on a WireGuard server use unifi_list_wireguard_peers."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_vpn_clients() -> Dict[str, Any]:
    """Implementation for listing VPN clients."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        clients = await vpn_manager.get_vpn_clients()
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "count": len(clients),
                "vpn_clients": clients,
            },
            redact_sensitive=redact_sensitive,
        )
    except Exception as e:
        logger.error("Error listing VPN clients: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list VPN clients: {e}"}


@server.tool(
    name="unifi_get_vpn_client_details",
    description=(
        "Get one outbound VPN client configuration (gateway-as-client tunnel) by ID from unifi_list_vpn_clients."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_vpn_client_details(
    client_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN client (from unifi_list_vpn_clients)")
    ],
) -> Dict[str, Any]:
    """Implementation for getting VPN client details."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        client = await vpn_manager.get_vpn_client_details(client_id)
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "client_id": client_id,
                "details": client,
            },
            redact_sensitive=redact_sensitive,
        )
    except UniFiNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error("Error getting VPN client details for %s: %s", client_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get VPN client details for {client_id}: {e}"}


@server.tool(
    name="unifi_update_vpn_client_state",
    description="Enable or disable a specific VPN client by ID. Requires confirmation.",
    permission_category="vpn_clients",
    permission_action="update",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_vpn_client_state(
    client_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN client to update (from unifi_list_vpn_clients)")
    ],
    enabled: Annotated[bool, Field(description="Set to true to enable the VPN client, false to disable it")],
    confirm: Annotated[
        bool,
        Field(description="When true, applies the state change. When false (default), returns a live-state preview"),
    ] = False,
) -> Dict[str, Any]:
    """Preview or update a VPN client's enabled state."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        current = await vpn_manager.get_vpn_client_details(client_id)
        if not confirm:
            return redact_sensitive_fields(
                update_preview(
                    resource_type="vpn_client",
                    resource_id=client_id,
                    resource_name=current.get("name", client_id),
                    current_state=current,
                    updates={"enabled": enabled},
                ),
                redact_sensitive=redact_sensitive,
            )

        write_result = await vpn_manager.update_vpn_client_state(client_id, enabled)
        payload = format_tool_payload(
            write_result,
            site=vpn_manager._connection.site,
            success_message=f"VPN client '{client_id}' {'enabled' if enabled else 'disabled'}.",
        )
        payload["client_id"] = client_id
        if not write_result.success:
            payload["error"] = f"Failed to update state for VPN client {client_id}: {write_result.error}"
        return redact_sensitive_fields(payload, redact_sensitive=redact_sensitive)
    except UniFiNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error("Error updating state for VPN client %s: %s", client_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update state for VPN client {client_id}: {e}"}


@server.tool(
    name="unifi_delete_vpn_client",
    description="Delete a VPN client configuration by ID. Requires confirmation.",
    permission_category="vpn_clients",
    permission_action="delete",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False),
)
async def delete_vpn_client(
    client_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN client to delete (from unifi_list_vpn_clients)")
    ],
    confirm: Annotated[
        bool,
        Field(description="When true, deletes the VPN client. When false (default), returns a live-state preview"),
    ] = False,
) -> Dict[str, Any]:
    """Preview or delete a VPN client configuration."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        current = await vpn_manager.get_vpn_client_details(client_id)
        if not confirm:
            return redact_sensitive_fields(
                delete_preview(
                    resource_type="vpn_client",
                    resource_id=client_id,
                    resource_data=current,
                    resource_name=current.get("name", client_id),
                    warnings=["Deleting the client removes its tunnel configuration and may interrupt routed traffic"],
                ),
                redact_sensitive=redact_sensitive,
            )

        success = await vpn_manager.delete_vpn_client(client_id)
        if success:
            return {"success": True, "client_id": client_id, "message": f"VPN client '{client_id}' deleted."}
        return {"success": False, "error": f"Failed to delete VPN client '{client_id}'."}
    except UniFiNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error("Error deleting VPN client %s: %s", client_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to delete VPN client {client_id}: {e}"}


@server.tool(
    name="unifi_list_vpn_servers",
    description="List all configured VPN servers (Wireguard, OpenVPN, L2TP, etc).",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_vpn_servers() -> Dict[str, Any]:
    """Implementation for listing VPN servers."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        servers = await vpn_manager.get_vpn_servers()
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "count": len(servers),
                "vpn_servers": [{**record, **alternate_address_view(record)} for record in servers],
            },
            redact_sensitive=redact_sensitive,
        )
    except Exception as e:
        logger.error("Error listing VPN servers: %s", e, exc_info=True)
        return {"success": False, "error": f"Failed to list VPN servers: {e}"}


@server.tool(
    name="unifi_get_vpn_server_details",
    description="Get details for a specific VPN server by ID.",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_vpn_server_details(
    server_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN server (from unifi_list_vpn_servers)")
    ],
) -> Dict[str, Any]:
    """Implementation for getting VPN server details."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        server = await vpn_manager.get_vpn_server_details(server_id)
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "server_id": server_id,
                "details": {**server, **alternate_address_view(server)},
            },
            redact_sensitive=redact_sensitive,
        )
    except UniFiNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error("Error getting VPN server details for %s: %s", server_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to get VPN server details for {server_id}: {e}"}


@server.tool(
    name="unifi_update_vpn_server_state",
    description="Enable or disable a specific VPN server by ID. Requires confirmation.",
    permission_category="vpn_servers",
    permission_action="update",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_vpn_server_state(
    server_id: Annotated[
        str, Field(description="Unique identifier (_id) of the VPN server to update (from unifi_list_vpn_servers)")
    ],
    enabled: Annotated[bool, Field(description="Set to true to enable the VPN server, false to disable it")],
    confirm: Annotated[
        bool,
        Field(description="When true, applies the state change. When false (default), returns a live-state preview"),
    ] = False,
) -> Dict[str, Any]:
    """Preview or update a VPN server's enabled state."""
    redact_sensitive = should_redact_sensitive_fields()
    try:
        current = await vpn_manager.get_vpn_server_details(server_id)
        if not confirm:
            return redact_sensitive_fields(
                update_preview(
                    resource_type="vpn_server",
                    resource_id=server_id,
                    resource_name=current.get("name", server_id),
                    current_state=current,
                    updates={"enabled": enabled},
                ),
                redact_sensitive=redact_sensitive,
            )

        write_result = await vpn_manager.update_vpn_server_state(server_id, enabled)
        payload = format_tool_payload(
            write_result,
            site=vpn_manager._connection.site,
            success_message=f"VPN server '{server_id}' {'enabled' if enabled else 'disabled'}.",
        )
        payload["server_id"] = server_id
        if not write_result.success:
            payload["error"] = f"Failed to update state for VPN server {server_id}: {write_result.error}"
        return redact_sensitive_fields(payload, redact_sensitive=redact_sensitive)
    except UniFiNotFoundError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        logger.error("Error updating state for VPN server %s: %s", server_id, e, exc_info=True)
        return {"success": False, "error": f"Failed to update state for VPN server {server_id}: {e}"}


def _read_error(operation: str, exc: Exception) -> Dict[str, Any]:
    """Error envelope for the read tools below.

    Only locally authored messages are echoed; controller exception text can
    embed client names and addresses, so other failures report their class.
    """
    if type(exc) in (UniFiNotFoundError, RuntimeError):
        return {"success": False, "error": f"Failed to {operation}: {exc}"}
    return {
        "success": False,
        "error": f"Failed to {operation} ({type(exc).__name__}); check Network session authentication",
    }


@server.tool(
    name="unifi_list_wireguard_peers",
    description=(
        "List the peers configured on WireGuard remote-access VPN servers (the Clients tab of a WireGuard VPN "
        "server in the UniFi UI). Returns id, name, server_id, interface_ip (tunnel IP), allowed_ips, public_key "
        "and preshared_key_enabled; preshared keys are never returned. Pass server_id from unifi_list_vpn_servers "
        "to filter to one server. For who is connected right now, use unifi_list_remote_vpn_clients (match on "
        "public_key). These IDs are scoped to the WireGuard peer tool family — do not pass them to other VPN "
        "client tools. Requires Network session authentication."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_wireguard_peers(
    server_id: Annotated[
        Optional[str],
        Field(description="Optional VPN server _id (from unifi_list_vpn_servers) to list only that server's peers"),
    ] = None,
) -> Dict[str, Any]:
    """List WireGuard peers through the Core manager."""
    try:
        peers = await vpn_manager.get_wireguard_peers(server_id)
        rows = [wireguard_peer_from_controller(peer).model_dump() for peer in peers]
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "server_id": server_id,
                "count": len(rows),
                "wireguard_peers": rows,
            },
            redact_sensitive=should_redact_sensitive_fields(),
        )
    except Exception as exc:
        logger.error("Error listing WireGuard peers: %s", type(exc).__name__)
        return _read_error("list WireGuard peers", exc)


@server.tool(
    name="unifi_get_wireguard_peer_details",
    description=(
        "Get one WireGuard VPN server peer by id from unifi_list_wireguard_peers: name, server_id, interface_ip, "
        "allowed_ips, public_key and preshared_key_enabled (the key itself is never returned). These IDs are "
        "scoped to the WireGuard peer tool family — do not pass them to other VPN client tools. Requires Network "
        "session authentication."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def get_wireguard_peer_details(
    peer_id: Annotated[str, Field(description="WireGuard peer id (from unifi_list_wireguard_peers)")],
) -> Dict[str, Any]:
    """Get one WireGuard peer through the Core manager."""
    try:
        peer = await vpn_manager.get_wireguard_peer_details(peer_id)
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "peer_id": peer_id,
                "details": wireguard_peer_from_controller(peer).model_dump(),
            },
            redact_sensitive=should_redact_sensitive_fields(),
        )
    except Exception as exc:
        logger.error("Error getting WireGuard peer details: %s", type(exc).__name__)
        return _read_error(f"get WireGuard peer {peer_id}", exc)


@server.tool(
    name="unifi_list_remote_vpn_clients",
    description=(
        "List remote-access VPN users and whether they are connected right now (the VPN entries in the UniFi "
        "Client Devices list). Returns name, status/online, server, tunnel_ip, the public remote_ip/remote_port "
        "and country they connected from, connected_since, last_seen, uptime_seconds, rx/tx bytes and current "
        "rates, plus public_key for WireGuard users. Connected users only by default; set include_offline=true "
        "to include configured users who are not connected. Pass server_id from unifi_list_vpn_servers to filter "
        "to one server. Session-based unifi_list_clients results do not include these users. Requires Network "
        "session authentication."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_remote_vpn_clients(
    include_offline: Annotated[
        bool, Field(description="When true, also returns configured VPN users who are not connected. Default false")
    ] = False,
    server_id: Annotated[
        Optional[str],
        Field(description="Optional VPN server _id (from unifi_list_vpn_servers) to list only that server's users"),
    ] = None,
) -> Dict[str, Any]:
    """List remote-access VPN users through the Core manager."""
    try:
        clients = await vpn_manager.get_remote_vpn_clients(include_offline=include_offline, server_id=server_id)
        rows = [remote_vpn_client_from_controller(client).model_dump() for client in clients]
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "include_offline": include_offline,
                "server_id": server_id,
                "count": len(rows),
                "online_count": sum(1 for row in rows if row["online"] is True),
                "remote_vpn_clients": rows,
            },
            redact_sensitive=should_redact_sensitive_fields(),
        )
    except Exception as exc:
        logger.error("Error listing remote-access VPN clients: %s", type(exc).__name__)
        return _read_error("list remote-access VPN clients", exc)


@server.tool(
    name="unifi_list_site_to_site_vpns",
    description=(
        "List site-to-site VPN tunnels (IPsec, OpenVPN, WireGuard and UniFi-managed site-to-site), which "
        "unifi_list_vpn_clients and unifi_list_vpn_servers do not include. Returns id, name, enabled, vpn_type, "
        "peer_address, remote_subnets and remote_site_id; keys and passwords are not returned."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_site_to_site_vpns() -> Dict[str, Any]:
    """List site-to-site VPN tunnels through the Core manager."""
    try:
        tunnels = await vpn_manager.get_site_to_site_vpns()
        rows = [site_to_site_vpn_from_controller(tunnel).model_dump() for tunnel in tunnels]
        return redact_sensitive_fields(
            {
                "success": True,
                "site": vpn_manager._connection.site,
                "count": len(rows),
                "site_to_site_vpns": rows,
            },
            redact_sensitive=should_redact_sensitive_fields(),
        )
    except Exception as exc:
        logger.error("Error listing site-to-site VPNs: %s", type(exc).__name__)
        return _read_error("list site-to-site VPNs", exc)
