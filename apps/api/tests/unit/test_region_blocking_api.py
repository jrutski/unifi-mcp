"""Region Blocking API projection, REST route and GraphQL field; flow filter translation."""

from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from tests.routes.resources.test_network_misc import _bootstrap, _stub_connection
from unifi_api.graphql.types.network.threat_management import RegionBlocking as ApiRegionBlocking
from unifi_api.services.dispatch_overrides import DISPATCH_ARG_TRANSLATORS
from unifi_core.network.managers.system_manager import SystemManager
from unifi_core.network.models.region_blocking import RegionBlocking

MODEL = RegionBlocking(enabled=True, action="allow", countries=["US"], traffic_direction="ingress")
EXPECTED = {"enabled": True, "action": "allow", "countries": ["US"], "traffic_direction": "ingress"}


def test_projection_from_core_model_and_raw_setting():
    assert ApiRegionBlocking.from_manager_output(MODEL).to_dict() == EXPECTED
    raw = {
        "_id": "000000000000000000000001",
        "key": "usg_geo",
        "ip_filtering": {"enabled": True, "action": "allow", "countries": "us", "traffic_direction": "ingress"},
    }
    assert ApiRegionBlocking.from_manager_output(raw).to_dict() == EXPECTED
    assert ApiRegionBlocking.from_manager_output(None).to_dict() == {
        "enabled": None,
        "action": None,
        "countries": [],
        "traffic_direction": None,
    }


@pytest.mark.asyncio
async def test_rest_and_graphql_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, cid = await _bootstrap(tmp_path)
    _stub_connection(app, cid)
    monkeypatch.setattr(SystemManager, "get_region_blocking", AsyncMock(return_value=MODEL))

    headers = {"Authorization": f"Bearer {key}"}
    query = f'{{ network {{ regionBlocking(controller: "{cid}") {{ enabled action countries trafficDirection }} }} }}'
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        rest = await client.get(f"/v1/sites/default/region-blocking?controller={cid}", headers=headers)
        gql = await client.post("/v1/graphql", headers=headers, json={"query": query})

    assert rest.status_code == 200
    assert rest.json() == {"data": EXPECTED, "render_hint": {"kind": "detail"}}
    assert gql.status_code == 200
    assert "errors" not in gql.json()
    assert gql.json()["data"]["network"]["regionBlocking"] == {
        "enabled": True,
        "action": "allow",
        "countries": ["US"],
        "trafficDirection": "ingress",
    }


def test_traffic_flow_translator_builds_policy_region_and_port_filters():
    translate = DISPATCH_ARG_TRANSLATORS["unifi_get_traffic_flows"]
    args, kwargs = translate(
        {
            "time_from": 1,
            "time_to": 2,
            "policy_internal_type": "region_blocking",
            "source_region": "br",
            "destination_port": "32400",
        }
    )
    query = kwargs["query"]
    assert args == ()
    assert [p.model_dump() for p in query.policy] == [{"internal_type": "REGION_BLOCKING"}]
    assert query.source_region == ["BR"]
    assert query.destination_port == [32400]


def test_traffic_flow_translator_leaves_policy_unset_without_policy_fields():
    _, kwargs = DISPATCH_ARG_TRANSLATORS["unifi_get_traffic_flows"](
        {"time_from": 1, "time_to": 2, "policy_type": "FIREWALL"}
    )
    assert kwargs["query"].policy is None
    assert kwargs["query"].policy_type == ["FIREWALL"]
