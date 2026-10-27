import time

import httpx
import pytest
import respx

from app.fortigate.client import (ClientConfig, FortiGateAuthError, FortiGateClient, FortiGateNotSupported,
                                  FortiGateUnreachable, TokenBucket)
from app.fortigate.client import test_connection as run_test_connection

BASE = "https://fgt.test.local:443"
STATUS = {"http_method": "GET", "results": {"model_name": "FortiGate", "model_number": "60F", "hostname": "FGT-TEST"},
          "vdom": "root", "serial": "FGTEST0000000001", "version": "v7.4.4", "build": 2662, "status": "success"}


def client(**kw):
    cfg = ClientConfig(host="fgt.test.local", token="test-token-123456", backoff_base=0.01, backoff_max=0.05, rps=1000, **kw)
    return FortiGateClient(cfg)


@respx.mock
async def test_auth_header_and_identity():
    route = respx.get(f"{BASE}/api/v2/monitor/system/status").mock(return_value=httpx.Response(200, json=STATUS))
    async with client() as c:
        ident = await c.system_status()
    req = route.calls[0].request
    assert req.headers["authorization"] == "Bearer test-token-123456"
    assert "access_token" not in str(req.url)  # token never in URL
    assert req.url.params["vdom"] == "root"
    assert ident == {"serial": "FGTEST0000000001", "version": "v7.4.4", "build": 2662, "hostname": "FGT-TEST",
                     "model": "FortiGate", "model_number": "60F", "vdom": "root"}


@respx.mock
async def test_401_is_auth_error_without_retry():
    route = respx.get(f"{BASE}/api/v2/monitor/system/status").mock(return_value=httpx.Response(401))
    async with client() as c:
        with pytest.raises(FortiGateAuthError) as e:
            await c.system_status()
    assert e.value.status == 401 and route.call_count == 1


@respx.mock
async def test_403_and_404_mapping():
    respx.get(f"{BASE}/api/v2/monitor/a").mock(return_value=httpx.Response(403))
    respx.get(f"{BASE}/api/v2/monitor/b").mock(return_value=httpx.Response(404))
    async with client() as c:
        with pytest.raises(FortiGateAuthError):
            await c.get("/api/v2/monitor/a")
        with pytest.raises(FortiGateNotSupported):
            await c.get("/api/v2/monitor/b")


@respx.mock
async def test_error_status_in_body():
    respx.get(f"{BASE}/api/v2/monitor/x").mock(return_value=httpx.Response(200, json={"status": "error", "http_status": 404}))
    async with client() as c:
        with pytest.raises(FortiGateNotSupported):
            await c.get("/api/v2/monitor/x")


@respx.mock
async def test_retry_with_backoff_then_success():
    route = respx.get(f"{BASE}/api/v2/monitor/system/status").mock(
        side_effect=[httpx.Response(503), httpx.ConnectTimeout("t"), httpx.Response(200, json=STATUS)])
    async with client() as c:
        assert (await c.system_status())["serial"] == "FGTEST0000000001"
    assert route.call_count == 3


@respx.mock
async def test_retries_exhausted():
    route = respx.get(f"{BASE}/api/v2/monitor/system/status").mock(side_effect=httpx.ConnectError("down"))
    async with client(max_retries=2) as c:
        with pytest.raises(FortiGateUnreachable):
            await c.system_status()
    assert route.call_count == 3


@respx.mock
async def test_non_json_response():
    respx.get(f"{BASE}/api/v2/monitor/x").mock(return_value=httpx.Response(200, text="<html>login</html>"))
    async with client() as c:
        with pytest.raises(Exception, match="non-JSON"):
            await c.get("/api/v2/monitor/x")


async def test_token_bucket_rate_limit():
    b = TokenBucket(rate=20, burst=1)
    t = time.monotonic()
    for _ in range(5):
        await b.acquire()
    assert time.monotonic() - t >= 0.18  # 4 waits at 20/s


@respx.mock
async def test_log_pagination_and_not_ready():
    pages = [
        httpx.Response(200, json={"results": [], "ready": False, "session_id": 77}),
        httpx.Response(200, json={"results": [{"eventtime": str(i)} for i in range(3)], "session_id": 77, "completed": 100}),
        httpx.Response(200, json={"results": [{"eventtime": "9"}], "session_id": 77}),
    ]
    route = respx.get(f"{BASE}/api/v2/log/disk/traffic/forward").mock(side_effect=pages)
    async with client() as c:
        got = [p async for p in c.iter_logs("disk", "traffic", "forward", rows=3)]
    assert [len(p) for p in got] == [3, 1]
    second = route.calls[2].request.url.params
    assert second["start"] == "3" and second["session_id"] == "77"


@respx.mock
async def test_unsupported_version_response_is_reported_not_faked():
    respx.get(f"{BASE}/api/v2/monitor/system/status").mock(return_value=httpx.Response(200, json=STATUS))
    respx.get(url__regex=r".*/api/v2/log/.*").mock(return_value=httpx.Response(404))
    respx.get(f"{BASE}/api/v2/monitor/system/resource/usage").mock(return_value=httpx.Response(200, json={"results": {}}))
    respx.get(f"{BASE}/api/v2/monitor/system/interface").mock(return_value=httpx.Response(403))
    respx.get(f"{BASE}/api/v2/cmdb/firewall/policy").mock(return_value=httpx.Response(200, json={"results": []}))
    respx.get(f"{BASE}/api/v2/monitor/firewall/session").mock(return_value=httpx.Response(424))
    async with client() as c:
        r = await run_test_connection(c)
    assert r["ok"] and r["auth"] == "ok" and r["identity"]["version"] == "v7.4.4"
    assert r["endpoints"]["interfaces"] == "forbidden" and r["endpoints"]["log_traffic_forward"] == "not_found"
    assert r["endpoints"]["sessions_current"] == "not_found"
    assert any("syslog" in w for w in r["warnings"])


@respx.mock
async def test_connection_auth_failure():
    respx.get(f"{BASE}/api/v2/monitor/system/status").mock(return_value=httpx.Response(401))
    async with client() as c:
        r = await run_test_connection(c)
    assert not r["ok"] and r["auth"] == "failed"
