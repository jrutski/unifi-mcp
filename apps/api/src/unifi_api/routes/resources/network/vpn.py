"""GET routes for VPN clients, VPN servers, WireGuard peers, remote-access
VPN clients and site-to-site VPN tunnels.

Phase 5A PR1 Cluster 3 — networks/WLANs/VPN/DNS/routing.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from unifi_core.exceptions import UniFiNotFoundError

from unifi_api.auth.middleware import require_scope
from unifi_api.auth.scopes import Scope
from unifi_api.graphql.pydantic_export import to_pydantic_model
from unifi_api.graphql.types.network.vpn import (
    RemoteVpnClient,
    SiteToSiteVpn,
    VpnClient,
    VpnServer,
    WireGuardPeer,
)
from unifi_api.routes.resources._common import (
    require_capability,
    resolve_controller,
)
from unifi_api.services.pagination import Cursor, InvalidCursor, paginate
from unifi_api.services.pydantic_models import Detail, Page

router = APIRouter()


def _id_key(obj) -> tuple:
    raw = obj if isinstance(obj, dict) else getattr(obj, "raw", {}) or {}
    return (0, raw.get("_id") or raw.get("id") or "")


def _decode_cursor(cursor: str | None) -> Cursor | None:
    if not cursor:
        return None
    try:
        return Cursor.decode(cursor)
    except InvalidCursor:
        raise HTTPException(status_code=400, detail="invalid cursor")


# ---------- VPN clients ----------


@router.get(
    "/sites/{site_id}/vpn-clients",
    response_model=Page[to_pydantic_model(VpnClient)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def list_vpn_clients(
    request: Request,
    site_id: str,
    controller=Depends(resolve_controller),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
) -> dict:
    require_capability(controller, "network")
    factory = request.app.state.manager_factory
    sm = request.app.state.sessionmaker
    async with sm() as session:
        mgr = await factory.get_domain_manager(
            session,
            controller.id,
            "network",
            "vpn_manager",
            site=site_id,
        )
        items = await mgr.get_vpn_clients()

    cursor_obj = _decode_cursor(cursor)
    page, next_cursor = paginate(
        list(items),
        limit=limit,
        cursor=cursor_obj,
        key_fn=_id_key,
    )
    type_registry = request.app.state.type_registry
    tool_type = type_registry.lookup_tool("unifi_list_vpn_clients")
    if tool_type is not None:
        type_class, kind = tool_type
        rows = [type_class.from_manager_output(i).to_dict() for i in page]
        hint = type_class.render_hint(kind)
    else:
        registry = request.app.state.serializer_registry
        serializer = registry.serializer_for_tool("unifi_list_vpn_clients")
        rows = [serializer.serialize(i) for i in page]
        hint = registry.render_hint_for_tool("unifi_list_vpn_clients")
    return {
        "items": rows,
        "next_cursor": next_cursor.encode() if next_cursor else None,
        "render_hint": hint,
    }


@router.get(
    "/sites/{site_id}/vpn-clients/{client_id}",
    response_model=Detail[to_pydantic_model(VpnClient)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def get_vpn_client_details(
    request: Request,
    site_id: str,
    client_id: str,
    controller=Depends(resolve_controller),
) -> dict:
    require_capability(controller, "network")
    factory = request.app.state.manager_factory
    sm = request.app.state.sessionmaker
    try:
        async with sm() as session:
            mgr = await factory.get_domain_manager(
                session,
                controller.id,
                "network",
                "vpn_manager",
                site=site_id,
            )
            item = await mgr.get_vpn_client_details(client_id)
    except UniFiNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if item is None:
        raise HTTPException(
            status_code=404,
            detail=f"vpn client {client_id} not found",
        )
    type_registry = request.app.state.type_registry
    tool_type = type_registry.lookup_tool("unifi_get_vpn_client_details")
    if tool_type is not None:
        type_class, kind = tool_type
        data = type_class.from_manager_output(item).to_dict()
        hint = type_class.render_hint(kind)
    else:
        registry = request.app.state.serializer_registry
        serializer = registry.serializer_for_tool("unifi_get_vpn_client_details")
        data = serializer.serialize(item)
        hint = registry.render_hint_for_tool("unifi_get_vpn_client_details")
    return {"data": data, "render_hint": hint}


# ---------- VPN servers ----------


@router.get(
    "/sites/{site_id}/vpn-servers",
    response_model=Page[to_pydantic_model(VpnServer)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def list_vpn_servers(
    request: Request,
    site_id: str,
    controller=Depends(resolve_controller),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
) -> dict:
    require_capability(controller, "network")
    factory = request.app.state.manager_factory
    sm = request.app.state.sessionmaker
    async with sm() as session:
        mgr = await factory.get_domain_manager(
            session,
            controller.id,
            "network",
            "vpn_manager",
            site=site_id,
        )
        items = await mgr.get_vpn_servers()

    cursor_obj = _decode_cursor(cursor)
    page, next_cursor = paginate(
        list(items),
        limit=limit,
        cursor=cursor_obj,
        key_fn=_id_key,
    )
    type_registry = request.app.state.type_registry
    tool_type = type_registry.lookup_tool("unifi_list_vpn_servers")
    if tool_type is not None:
        type_class, kind = tool_type
        rows = [type_class.from_manager_output(i).to_dict() for i in page]
        hint = type_class.render_hint(kind)
    else:
        registry = request.app.state.serializer_registry
        serializer = registry.serializer_for_tool("unifi_list_vpn_servers")
        rows = [serializer.serialize(i) for i in page]
        hint = registry.render_hint_for_tool("unifi_list_vpn_servers")
    return {
        "items": rows,
        "next_cursor": next_cursor.encode() if next_cursor else None,
        "render_hint": hint,
    }


@router.get(
    "/sites/{site_id}/vpn-servers/{server_id}",
    response_model=Detail[to_pydantic_model(VpnServer)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def get_vpn_server_details(
    request: Request,
    site_id: str,
    server_id: str,
    controller=Depends(resolve_controller),
) -> dict:
    require_capability(controller, "network")
    factory = request.app.state.manager_factory
    sm = request.app.state.sessionmaker
    try:
        async with sm() as session:
            mgr = await factory.get_domain_manager(
                session,
                controller.id,
                "network",
                "vpn_manager",
                site=site_id,
            )
            item = await mgr.get_vpn_server_details(server_id)
    except UniFiNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if item is None:
        raise HTTPException(
            status_code=404,
            detail=f"vpn server {server_id} not found",
        )
    type_registry = request.app.state.type_registry
    tool_type = type_registry.lookup_tool("unifi_get_vpn_server_details")
    if tool_type is not None:
        type_class, kind = tool_type
        data = type_class.from_manager_output(item).to_dict()
        hint = type_class.render_hint(kind)
    else:
        registry = request.app.state.serializer_registry
        serializer = registry.serializer_for_tool("unifi_get_vpn_server_details")
        data = serializer.serialize(item)
        hint = registry.render_hint_for_tool("unifi_get_vpn_server_details")
    return {"data": data, "render_hint": hint}


# ---------- WireGuard peers, remote-access clients, site-to-site ----------


async def _call_vpn_manager(request: Request, controller, site_id: str, method: str, **kwargs):
    factory = request.app.state.manager_factory
    try:
        async with request.app.state.sessionmaker() as session:
            mgr = await factory.get_domain_manager(
                session,
                controller.id,
                "network",
                "vpn_manager",
                site=site_id,
            )
            return await getattr(mgr, method)(**kwargs)
    except UniFiNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


def _redact_sensitive(request: Request) -> bool:
    return request.app.state.config.policy.response.redact_sensitive_fields


def _typed_page(request: Request, tool_name: str, items, limit: int, cursor: str | None, **projection) -> dict:
    page, next_cursor = paginate(list(items), limit=limit, cursor=_decode_cursor(cursor), key_fn=_id_key)
    type_class, kind = request.app.state.type_registry.lookup_tool(tool_name)
    return {
        "items": [type_class.from_manager_output(i, **projection).to_dict() for i in page],
        "next_cursor": next_cursor.encode() if next_cursor else None,
        "render_hint": type_class.render_hint(kind),
    }


@router.get(
    "/sites/{site_id}/wireguard-peers",
    response_model=Page[to_pydantic_model(WireGuardPeer)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def list_wireguard_peers(
    request: Request,
    site_id: str,
    controller=Depends(resolve_controller),
    server_id: str | None = Query(None, description="Only peers of this VPN server (_id)"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
) -> dict:
    require_capability(controller, "network")
    items = await _call_vpn_manager(request, controller, site_id, "get_wireguard_peers", server_id=server_id)
    return _typed_page(
        request,
        "unifi_list_wireguard_peers",
        items,
        limit,
        cursor,
        redact_sensitive=_redact_sensitive(request),
    )


@router.get(
    "/sites/{site_id}/wireguard-peers/{peer_id}",
    response_model=Detail[to_pydantic_model(WireGuardPeer)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def get_wireguard_peer_details(
    request: Request,
    site_id: str,
    peer_id: str,
    controller=Depends(resolve_controller),
) -> dict:
    require_capability(controller, "network")
    item = await _call_vpn_manager(request, controller, site_id, "get_wireguard_peer_details", peer_id=peer_id)
    type_class, kind = request.app.state.type_registry.lookup_tool("unifi_get_wireguard_peer_details")
    data = type_class.from_manager_output(item, redact_sensitive=_redact_sensitive(request)).to_dict()
    return {"data": data, "render_hint": type_class.render_hint(kind)}


@router.get(
    "/sites/{site_id}/remote-vpn-clients",
    response_model=Page[to_pydantic_model(RemoteVpnClient)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def list_remote_vpn_clients(
    request: Request,
    site_id: str,
    controller=Depends(resolve_controller),
    include_offline: bool = Query(False, description="Also return configured users who are not connected"),
    server_id: str | None = Query(None, description="Only users of this VPN server (_id)"),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
) -> dict:
    require_capability(controller, "network")
    items = await _call_vpn_manager(
        request,
        controller,
        site_id,
        "get_remote_vpn_clients",
        include_offline=include_offline,
        server_id=server_id,
    )
    return _typed_page(request, "unifi_list_remote_vpn_clients", items, limit, cursor)


@router.get(
    "/sites/{site_id}/site-to-site-vpns",
    response_model=Page[to_pydantic_model(SiteToSiteVpn)],
    dependencies=[Depends(require_scope(Scope.READ))],
    tags=["network/vpn"],
)
async def list_site_to_site_vpns(
    request: Request,
    site_id: str,
    controller=Depends(resolve_controller),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
) -> dict:
    require_capability(controller, "network")
    items = await _call_vpn_manager(request, controller, site_id, "get_site_to_site_vpns")
    return _typed_page(request, "unifi_list_site_to_site_vpns", items, limit, cursor)
