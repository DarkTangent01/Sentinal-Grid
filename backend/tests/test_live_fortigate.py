"""Live integration test. Runs ONLY when FGT_TEST_HOST and FGT_TEST_TOKEN are explicitly set.
Optional: FGT_TEST_PORT, FGT_TEST_VDOM, FGT_TEST_CA_BUNDLE. Read-only GET requests only."""
import os

import pytest

from app.fortigate.client import ClientConfig, FortiGateClient
from app.fortigate.client import test_connection as run_test_connection

pytestmark = [pytest.mark.live, pytest.mark.skipif(not (os.environ.get("FGT_TEST_HOST") and os.environ.get("FGT_TEST_TOKEN")),
                                                   reason="no live FortiGate configured")]


async def test_live_connection():
    cfg = ClientConfig(host=os.environ["FGT_TEST_HOST"], token=os.environ["FGT_TEST_TOKEN"],
                       port=int(os.environ.get("FGT_TEST_PORT", "443")), vdom=os.environ.get("FGT_TEST_VDOM", "root"),
                       ca_bundle=os.environ.get("FGT_TEST_CA_BUNDLE") or None)
    async with FortiGateClient(cfg) as c:
        r = await run_test_connection(c)
    print(r)
    assert r["ok"], r
    assert r["identity"]["serial"]
