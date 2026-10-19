import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from aiounifi.errors import RequestError
from aiounifi.models.api import ApiRequest, ApiRequestV2
from aiounifi.models.dpi_restriction_app import DPIRestrictionApp  # Import DPIApp model
from aiounifi.models.dpi_restriction_group import (
    DPIRestrictionGroup,
)  # Import DPIGroup model

from unifi_core.mac import mac_equal, normalize_mac
from unifi_core.network.managers.client_manager import ClientManager  # Needed for get_top_clients
from unifi_core.network.managers.connection_manager import ConnectionManager, response_status
from unifi_core.network.managers.device_manager import DeviceManager
from unifi_core.network.managers.traffic_flow_manager import build_traffic_flow_body
from unifi_core.network.models.ips_events import IPS_POLICY_TYPE, ips_event_from_flow, ips_event_from_legacy
from unifi_core.network.models.traffic_flows import TrafficFlowQuery

logger = logging.getLogger("unifi-network-mcp")

# Cache prefixes
CACHE_PREFIX_STATS_NETWORK = "stats_network"
CACHE_PREFIX_STATS_CLIENT = "stats_client"
CACHE_PREFIX_STATS_DEVICE = "stats_device"
CACHE_PREFIX_STATS_DPI = "stats_dpi"
CACHE_PREFIX_STATS_ALERTS = "stats_alerts"
CACHE_PREFIX_STATS_GATEWAY = "stats_gateway"
CACHE_PREFIX_STATS_SPEEDTEST = "stats_speedtest"
CACHE_PREFIX_STATS_SITE_DPI = "stats_site_dpi"
CACHE_PREFIX_STATS_CLIENT_DPI = "stats_client_dpi"
CACHE_PREFIX_STATS_IPS = "stats_ips"
CACHE_PREFIX_STATS_SESSIONS = "stats_sessions"
CACHE_PREFIX_STATS_DASHBOARD = "stats_dashboard"
CACHE_PREFIX_STATS_ANOMALIES = "stats_anomalies"
CACHE_PREFIX_STATS_CLIENT_WIFI = "stats_client_wifi"

# IPS events
_IPS_ACTIONS = ("allowed", "blocked")
_IPS_MAX_LIMIT = 1000  # one traffic-flows page

# Granularity validation
VALID_GRANULARITIES = {"5minutes", "hourly", "daily", "monthly"}


def _resolve_granularity(granularity: str) -> str:
    """Validate and return the granularity string.

    Args:
        granularity: One of 5minutes, hourly, daily, monthly.

    Returns:
        The validated granularity string.

    Raises:
        ValueError: If the granularity is not valid.
    """
    if granularity not in VALID_GRANULARITIES:
        raise ValueError(
            f"Invalid granularity '{granularity}'. Must be one of: {', '.join(sorted(VALID_GRANULARITIES))}"
        )
    return granularity


class StatsManager:
    """Manages statistics retrieval from the Unifi Controller."""

    def __init__(self, connection_manager: ConnectionManager, client_manager: ClientManager):
        """Initialize the Stats Manager.

        Args:
            connection_manager: The shared ConnectionManager instance.
            client_manager: The ClientManager instance (needed for some stats methods).
        """
        self._connection = connection_manager
        self._client_manager = client_manager

    async def get_network_stats(self, duration_hours: int = 1, granularity: str = "hourly") -> List[Dict[str, Any]]:
        """Get network statistics (e.g., hourly site stats)."""
        granularity = _resolve_granularity(granularity)
        cache_key = f"{CACHE_PREFIX_STATS_NETWORK}_{duration_hours}_{granularity}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = f"/stat/report/{granularity}.site"
            # Use non-rate attributes commonly available on report endpoints
            payload = {
                "attrs": [
                    "bytes",  # total bytes (if provided by controller)
                    "rx_bytes",  # some controllers provide rx/tx at site level
                    "tx_bytes",
                    "num_user",
                    "num_sta",
                    "num_active_user",
                    "wan-rx_bytes",
                    "wan-tx_bytes",
                    "wlan-num_sta",
                    "lan-num_sta",
                ],
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting network stats: %s", e)
            raise

    async def get_client_stats(
        self, client_mac: str, duration_hours: int = 1, granularity: str = "hourly"
    ) -> List[Dict[str, Any]]:
        """Get statistics for a specific client."""
        client_mac = normalize_mac(client_mac) or client_mac
        granularity = _resolve_granularity(granularity)
        cache_key = f"{CACHE_PREFIX_STATS_CLIENT}_{client_mac}_{duration_hours}_{granularity}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = f"/stat/report/{granularity}.user"
            payload = {
                "attrs": [
                    "rx_bytes",
                    "tx_bytes",
                    "bytes",
                    "signal",
                    "satisfaction",
                    "tx_retries",
                    "tx_rate",
                    "rx_rate",
                    "wifi_tx_attempts",
                ],
                "mac": client_mac,
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting stats for client %s: %s", client_mac, e)
            raise

    async def get_client_stats_for_identifier(
        self,
        client_id: str,
        duration_hours: int = 1,
        granularity: str = "hourly",
    ) -> List[Dict[str, Any]]:
        """Resolve a public MAC-or-id client identifier before fetching stats."""
        client = await self._client_manager.get_client_details(client_id, existence_only=True)
        raw = client.raw if hasattr(client, "raw") else client
        client_mac = raw.get("mac", client_id)
        return await self.get_client_stats(
            client_mac,
            duration_hours=duration_hours,
            granularity=granularity,
        )

    async def get_device_stats(
        self,
        device_mac: str,
        duration_hours: int = 1,
        granularity: str = "hourly",
        device_type: str = "dev",
    ) -> List[Dict[str, Any]]:
        """Get statistics for a specific device.

        Args:
            device_mac: MAC address of the device.
            duration_hours: Number of hours to look back.
            granularity: Report granularity (5minutes, hourly, daily, monthly).
            device_type: Device type for endpoint routing (ap, gw, or dev).
        """
        device_mac = normalize_mac(device_mac) or device_mac
        granularity = _resolve_granularity(granularity)
        cache_key = (
            f"{CACHE_PREFIX_STATS_DEVICE}_{device_mac}_{duration_hours}_{granularity}"
            f"_{device_type}_{self._connection.site}"
        )
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            # Route endpoint and attrs based on device_type
            if device_type == "ap":
                endpoint = f"/stat/report/{granularity}.ap"
                attrs = [
                    "num_sta",
                    "ng-num_sta",
                    "na-num_sta",
                    "satisfaction",
                    "tx_retries",
                    "wifi_tx_attempts",
                    "wifi_tx_dropped",
                    "ng-tx_bytes",
                    "na-tx_bytes",
                    "ng-rx_bytes",
                    "na-rx_bytes",
                ]
            elif device_type == "gw":
                endpoint = f"/stat/report/{granularity}.gw"
                attrs = [
                    "wan-rx_bytes",
                    "wan-tx_bytes",
                    "lan-rx_bytes",
                    "lan-tx_bytes",
                    "cpu",
                    "mem",
                    "loadavg_5",
                ]
            else:
                endpoint = f"/stat/report/{granularity}.dev"
                attrs = [
                    "rx_bytes",
                    "tx_bytes",
                    "bytes",
                    "num_sta",
                ]

            payload = {
                "attrs": attrs,
                "mac": device_mac,
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting stats for device %s: %s", device_mac, e)
            raise

    async def get_device_stats_for_identifier(
        self,
        device_id: str,
        duration_hours: int = 1,
        granularity: str = "hourly",
    ) -> List[Dict[str, Any]]:
        """Resolve a public MAC-or-id device identifier and select its report family."""
        device = await DeviceManager(self._connection).get_device_details(device_id)
        raw = device.raw if hasattr(device, "raw") else device
        device_mac = raw.get("mac", device_id)
        device_type = raw.get("type", "unknown")
        report_type = {"uap": "ap", "ugw": "gw", "udm": "gw"}.get(device_type, "dev")
        return await self.get_device_stats(
            device_mac,
            duration_hours=duration_hours,
            granularity=granularity,
            device_type=report_type,
        )

    async def get_top_clients(self, duration_hours: int = 24, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top clients by usage.

        Fallback approach: derive usage from current client objects when report
        endpoints return no data. Values are cumulative since association and
        are sufficient for ranking purposes.
        """
        online_clients = await self._client_manager.get_clients()
        if not online_clients:
            return []

        clients_raw = [c.raw if hasattr(c, "raw") else c for c in online_clients]

        aggregated_stats: List[Dict[str, Any]] = []

        def _safe_int(value: Any) -> int:
            try:
                if value is None:
                    return 0
                if isinstance(value, bool):
                    return int(value)
                return int(str(value))
            except Exception:
                return 0

        for client in clients_raw:
            mac = client.get("mac")
            if not mac:
                continue

            # Prefer explicit total if present, otherwise sum rx/tx (wifi + wired)
            rx = _safe_int(client.get("rx_bytes")) + _safe_int(
                client.get("wired_rx_bytes") or client.get("wired-rx_bytes")
            )
            tx = _safe_int(client.get("tx_bytes")) + _safe_int(
                client.get("wired_tx_bytes") or client.get("wired-tx_bytes")
            )
            total = _safe_int(client.get("bytes")) or (rx + tx)

            aggregated_stats.append(
                {
                    "mac": mac,
                    "name": client.get("name") or client.get("hostname", mac),
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                    "total_bytes": total,
                }
            )

        # Sort by total bytes descending and return top N
        sorted_clients = sorted(aggregated_stats, key=lambda x: x["total_bytes"], reverse=True)
        return sorted_clients[:limit]

    async def get_dpi_stats(
        self,
    ) -> Dict[str, List[Any]]:  # Return List[DPIRestrictionApp/Group]
        """Get Deep Packet Inspection (DPI) statistics."""
        cache_key = f"{CACHE_PREFIX_STATS_DPI}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=900)  # 15 minute cache
        if cached_data is not None:
            return cached_data

        if not await self._connection.ensure_connected() or not self._connection.controller:
            raise ConnectionError("Not connected to controller")

        try:
            await self._connection.refresh_handler("dpi_apps")
            await self._connection.refresh_handler("dpi_groups")

            dpi_apps: List[DPIRestrictionApp] = list(self._connection.controller.dpi_apps.values())
            dpi_groups: List[DPIRestrictionGroup] = list(self._connection.controller.dpi_groups.values())
            result = {"applications": dpi_apps, "categories": dpi_groups}
            self._connection._update_cache(cache_key, result, timeout=900)
            return result
        except Exception as e:
            logger.error("Error getting DPI stats: %s", type(e).__name__)
            # REST/GraphQL call this manager directly and may log tracebacks.
            # Keep the original controller text out of every caller surface.
            raise RequestError(f"DPI stats refresh failed ({type(e).__name__}).") from None

    async def get_alerts(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        """Get alerts from the controller."""
        cache_key = f"{CACHE_PREFIX_STATS_ALERTS}_{include_archived}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=60)  # 1 minute cache
        if cached_data is not None:
            return cached_data

        if not await self._connection.ensure_connected() or not self._connection.controller:
            raise ConnectionError("Not connected to controller")
        try:
            alerts = await self._get_alerts_v2()
        except Exception as v2_error:
            logger.debug("V2 alert lookup failed, falling back to legacy alarms: %s", v2_error)
            try:
                alerts = await self._get_alerts_legacy(include_archived)
            except Exception as legacy_error:
                # Report both. Current controllers have removed /stat/alarm, so the
                # legacy error is usually a 404 that says nothing about the real
                # problem — which is whatever made the v2 lookup fail.
                raise RuntimeError(
                    f"/stat/alarm failed ({legacy_error}) after the v2 system-log lookup failed "
                    f"({v2_error}). On current UniFi Network versions the legacy endpoint no longer "
                    "exists, so the v2 failure is the one to act on."
                ) from legacy_error

        if not include_archived:
            alerts = [a for a in alerts if not a.get("archived", False)]
        self._connection._update_cache(cache_key, alerts, timeout=60)
        return alerts

    async def _get_alerts_v2(self) -> List[Dict[str, Any]]:
        """Get alerts from the v2 system-log critical endpoint."""
        now_ms = int(datetime.now().timestamp() * 1000)
        from_ms = int((datetime.now() - timedelta(days=30)).timestamp() * 1000)
        api_request = ApiRequestV2(
            method="post",
            path="/system-log/critical",
            data={
                "timestampFrom": from_ms,
                "timestampTo": now_ms,
                "severities": ["HIGH", "VERY_HIGH"],
                "categories": [
                    "CLIENT_DEVICES",
                    "INTERNET_AND_WAN",
                    "POWER",
                    "SECURITY",
                    "UNIFI_DEVICES",
                    "SOFTWARE_UPDATES",
                    "UNIFI_ETHERNET_PORTS",
                    "VPN",
                ],
                "type": "GENERAL",
                "pageNumber": 0,
                "pageSize": 100,
                "searchText": "",
            },
        )
        response = await self._connection.request(api_request)
        if isinstance(response, list) and response and isinstance(response[0], dict) and "data" in response[0]:
            return response[0]["data"]
        if isinstance(response, dict):
            data = response.get("data", response.get("logs", []))
            return data if isinstance(data, list) else []
        if isinstance(response, list):
            return response
        return []

    async def _get_alerts_legacy(self, include_archived: bool) -> List[Dict[str, Any]]:
        """Get alerts from the legacy alarm endpoint."""
        path = "/stat/alarm?archived=true" if include_archived else "/stat/alarm"
        api_request = ApiRequest(method="get", path=path)
        response = await self._connection.request(api_request)
        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            data = response.get("data", [])
            return data if isinstance(data, list) else []
        return []

    async def get_gateway_stats(self, duration_hours: int = 24, granularity: str = "hourly") -> List[Dict[str, Any]]:
        """Get gateway statistics."""
        granularity = _resolve_granularity(granularity)
        cache_key = f"{CACHE_PREFIX_STATS_GATEWAY}_{duration_hours}_{granularity}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = f"/stat/report/{granularity}.gw"
            payload = {
                "attrs": [
                    "wan-rx_bytes",
                    "wan-tx_bytes",
                    "lan-rx_bytes",
                    "lan-tx_bytes",
                    "cpu",
                    "mem",
                    "loadavg_5",
                    "wan-rx_packets",
                    "wan-tx_packets",
                ],
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting gateway stats: %s", e)
            raise

    async def get_speedtest_results(self, duration_hours: int = 24) -> List[Dict[str, Any]]:
        """Get speed test results from the controller archive."""
        cache_key = f"{CACHE_PREFIX_STATS_SPEEDTEST}_{duration_hours}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = "/stat/report/archive.speedtest"
            payload = {
                "attrs": [
                    "xput_download",
                    "xput_upload",
                    "latency",
                    "time",
                ],
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting speedtest results: %s", e)
            raise

    async def get_site_dpi_traffic(self, by: str = "by_app") -> List[Dict[str, Any]]:
        """Get site-level DPI traffic statistics.

        Args:
            by: Grouping type, e.g. 'by_app' or 'by_cat'.
        """
        cache_key = f"{CACHE_PREFIX_STATS_SITE_DPI}_{by}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=900)  # 15 minute cache
        if cached_data is not None:
            return cached_data

        try:
            endpoint = "/stat/sitedpi"
            payload = {"type": by}
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=900)
            return result
        except Exception as e:
            logger.error("Error getting site DPI traffic: %s", e)
            raise

    async def get_client_dpi_traffic(self, client_mac: str, by: str = "by_app") -> List[Dict[str, Any]]:
        """Get DPI traffic statistics for a specific client.

        Args:
            client_mac: MAC address of the client.
            by: Grouping type, e.g. 'by_app' or 'by_cat'.
        """
        client_mac = normalize_mac(client_mac) or client_mac
        cache_key = f"{CACHE_PREFIX_STATS_CLIENT_DPI}_{client_mac}_{by}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=900)  # 15 minute cache
        if cached_data is not None:
            return cached_data

        try:
            endpoint = "/stat/stadpi"
            payload = {"type": by, "macs": [client_mac]}
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=900)
            return result
        except Exception as e:
            logger.error("Client DPI traffic read failed: %s", type(e).__name__)
            raise RequestError(f"Client DPI traffic read failed ({type(e).__name__}).") from None

    async def get_ips_events(
        self, duration_hours: int = 24, limit: int = 50, action: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get IPS/IDS signature matches, newest first.

        Reads v2 traffic flows whose matched policy is INTRUSION_PREVENTION;
        Network 10.x records every signature match there, with the signature,
        category and endpoints, and leaves the legacy ``/stat/ips/event``
        endpoint empty. Only a controller that answers the flows API with 404
        falls back to that legacy endpoint; any other flow failure raises, so a
        failed read is never reported as "no events".

        Args:
            duration_hours: Number of hours to look back.
            limit: Maximum number of events to return (at most 1000).
            action: Optional filter, 'allowed' or 'blocked'.
        """
        action = action.strip().lower() if isinstance(action, str) and action.strip() else None
        if action not in (None, *_IPS_ACTIONS):
            raise ValueError("action must be 'allowed' or 'blocked'")
        limit = min(int(limit), _IPS_MAX_LIMIT)
        if limit <= 0:
            return []

        cache_key = f"{CACHE_PREFIX_STATS_IPS}_{duration_hours}_{limit}_{action}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        end_time = int(datetime.now().timestamp() * 1000)
        start_time = end_time - int(duration_hours * 3600 * 1000)
        try:
            flows = await self._get_ips_flows(start_time, end_time, limit, action)
            events = [ips_event_from_flow(flow) for flow in flows]
        except Exception as flow_error:
            if response_status(flow_error) != 404:
                # Network 10.x serves flows and answers the legacy endpoint with an
                # empty list, so falling back here would report a failed read as
                # "no threats".
                logger.error("Error getting IPS events from traffic flows: %s", type(flow_error).__name__)
                raise RuntimeError("Failed to read IPS events from traffic flows") from None
            logger.debug("Controller has no traffic-flows API; reading legacy /stat/ips/event")
            try:
                legacy = await self._get_legacy_ips_events(start_time, end_time, limit)
            except Exception as legacy_error:
                logger.error("Error getting legacy IPS events: %s", type(legacy_error).__name__)
                raise RuntimeError("Failed to read IPS events from the legacy endpoint") from None
            events = [ips_event_from_legacy(event) for event in legacy]
            if action:
                events = [event for event in events if event.action == action]

        result = [event.model_dump(exclude_none=True) for event in events[:limit]]
        self._connection._update_cache(cache_key, result, timeout=300)
        return result

    async def _get_ips_flows(self, start_time: int, end_time: int, limit: int, action: Optional[str]) -> List[Dict]:
        """One page of IPS-matched traffic flows (raises when the flows API is unavailable)."""
        query = TrafficFlowQuery(
            time_from=start_time,
            time_to=end_time,
            page_size=limit,
            policy_type=[IPS_POLICY_TYPE],
            action=[action] if action else None,
        )
        response = await self._connection.request(
            ApiRequestV2(method="post", path="/traffic-flows", data=build_traffic_flow_body(query))
        )
        # ApiRequestV2.decode list-wraps the envelope; see TrafficFlowManager.
        if isinstance(response, list):
            response = response[0] if response else {}
        records = response.get("data") if isinstance(response, dict) else None
        if not isinstance(records, list):
            raise RuntimeError("Unexpected traffic-flows response")
        return [record for record in records if isinstance(record, dict)]

    async def _get_legacy_ips_events(self, start_time: int, end_time: int, limit: int) -> List[Dict]:
        """Legacy ``/stat/ips/event`` records for controllers without the flows API."""
        response = await self._connection.request(
            ApiRequest(
                method="post",
                path="/stat/ips/event",
                data={"start": start_time, "end": end_time, "_limit": limit},
            )
        )
        return [event for event in response if isinstance(event, dict)] if isinstance(response, list) else []

    async def get_client_sessions(
        self,
        client_mac: Optional[str] = None,
        duration_hours: int = 24,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get client session history.

        Args:
            client_mac: Optional MAC address to filter sessions for a specific client.
            duration_hours: Number of hours to look back.
            limit: Maximum number of sessions to return.
        """
        client_mac = normalize_mac(client_mac) or client_mac
        mac_part = client_mac or "all"
        cache_key = f"{CACHE_PREFIX_STATS_SESSIONS}_{mac_part}_{duration_hours}_{limit}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = "/stat/session"
            payload: Dict[str, Any] = {
                "type": "all",
                "start": start_time,
                "end": end_time,
                "_limit": limit,
            }
            if client_mac:
                payload["mac"] = client_mac

            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Client sessions read failed: %s", type(e).__name__)
            raise RequestError(f"Client sessions read failed ({type(e).__name__}).") from None

    async def get_dashboard(self, history_seconds: int = 86400) -> List[Dict[str, Any]]:
        """Get the site dashboard aggregate (health, WiFi standards, ISP metrics).

        Hits the V2 ``/aggregated-dashboard`` endpoint that the UniFi UI uses
        to render its dashboard view. The response is a list of one or more
        dashboard payloads (typically one per controller-managed site rollup).
        Each payload contains nested blocks like ``wifi`` (per-standard
        connection counts and traffic), ``isp_metrics`` (per-WAN history),
        and other UI-visible aggregates.

        Args:
            history_seconds: How far back to roll up history. Defaults to
                86400 (24h), matching the UI default. The endpoint requires
                this query parameter.
        """
        cache_key = f"{CACHE_PREFIX_STATS_DASHBOARD}_{history_seconds}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            api_request = ApiRequestV2(
                method="get",
                path=f"/aggregated-dashboard?historySeconds={int(history_seconds)}",
            )
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting dashboard: %s", e)
            raise

    async def get_anomalies(self, duration_hours: int = 24) -> List[Dict[str, Any]]:
        """Get detected anomalies.

        Args:
            duration_hours: Number of hours to look back.
        """
        cache_key = f"{CACHE_PREFIX_STATS_ANOMALIES}_{duration_hours}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            start_time = int((datetime.now() - timedelta(hours=duration_hours)).timestamp() * 1000)
            end_time = int(datetime.now().timestamp() * 1000)

            endpoint = "/stat/anomalies"
            payload = {
                "start": start_time,
                "end": end_time,
            }
            api_request = ApiRequest(method="post", path=endpoint, data=payload)
            response = await self._connection.request(api_request)
            result = response if isinstance(response, list) else []
            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Error getting anomalies: %s", e)
            raise

    async def get_client_wifi_details(self, client_mac: str) -> Optional[Dict[str, Any]]:
        """Get detailed WiFi information for a specific client.

        Args:
            client_mac: MAC address of the client.

        Returns:
            Dict with WiFi detail fields, or None if client not found.
        """
        client_mac = normalize_mac(client_mac) or client_mac
        cache_key = f"{CACHE_PREFIX_STATS_CLIENT_WIFI}_{client_mac}_{self._connection.site}"
        cached_data = self._connection.get_cached(cache_key, timeout=300)  # 5 minute cache
        if cached_data is not None:
            return cached_data

        try:
            # /stat/sta is a collection endpoint: it returns all currently-
            # connected wireless clients and ignores any MAC filter in the body.
            # Fetch the full list, then filter for the requested MAC ourselves.
            api_request = ApiRequest(method="get", path="/stat/sta")
            response = await self._connection.request(api_request)

            clients = response if isinstance(response, list) else []
            raw = next(
                (c for c in clients if isinstance(c, dict) and mac_equal(c.get("mac"), client_mac)),
                None,
            )
            if raw is None:
                return None

            wifi_fields = [
                "signal",
                "noise",
                "satisfaction",
                "tx_rate",
                "rx_rate",
                "tx_retries",
                "wifi_tx_attempts",
                "roam_count",
                "os_name",
                "dev_vendor",
                "dev_cat",
                "dev_family",
                "channel",
                "radio",
                "essid",
                "bssid",
                "nss",
                "is_11r",
            ]
            result: Dict[str, Any] = {"mac": raw.get("mac", client_mac)}
            for field in wifi_fields:
                if field in raw:
                    result[field] = raw[field]

            self._connection._update_cache(cache_key, result, timeout=300)
            return result
        except Exception as e:
            logger.error("Client WiFi details read failed: %s", type(e).__name__)
            raise RequestError(f"Client WiFi details read failed ({type(e).__name__}).") from None
