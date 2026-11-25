"""Threat-intelligence connectors (STIX, TAXII, MISP, OTX), indicator normalization and dedupe, matching of the new
indicator types, false-positive verdicts that survive a refresh, and that API keys never leave the server."""
import json
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.db.models import TiFeed, TiIndicator
from app.enrich import connectors as C
from app.enrich.enricher import Enricher
from app.enrich.feeds import fetch_feed
from app.platform.geoip import GeoResolver
from app.enrich.ti import IndicatorSet
from app.security import TokenCipher

from .test_api import api, login  # noqa: F401  (fixture)

STIX = {"type": "bundle", "objects": [
    {"type": "indicator", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '93.184.216.7']", "confidence": 85, "indicator_types": ["malicious-activity"],
     "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"},
    {"type": "indicator", "pattern": "[domain-name:value = 'Evil.Example.NET'] OR [url:value = 'https://evil.example.net/gate.php']", "labels": ["c2"]},
    {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855']"},
    {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.5']"},                       # private: refused
    {"type": "indicator", "pattern": "[ipv4-addr:value = '93.184.216.7']", "confidence": 40},   # duplicate: highest confidence wins
    {"type": "indicator", "revoked": True, "pattern": "[ipv4-addr:value = '93.184.216.99']"},
    {"type": "indicator", "pattern_type": "yara", "pattern": "rule x {}"},
    {"type": "malware", "name": "not an indicator"}]}


def test_normalize_types_and_refusals():
    n = C.normalize
    assert n("93.184.216.7") == ("93.184.216.7", "ip") and n("93.184.216.0/24") == ("93.184.216.0/24", "cidr") and n("2606:4700:4700::1111")[1] == "ip"
    assert n("https://Evil.example.net/a/") == ("Evil.example.net/a", "url") and n("AS64500") == ("64500", "asn") and n("Bad@Example.com") == ("bad@example.com", "email")
    assert n("d41d8cd98f00b204e9800998ecf8427e")[1] == "md5" and n("da39a3ee5e6b4b0d3255bfef95601890afd80709")[1] == "sha1"
    assert n("Sub.Example.org.") == ("sub.example.org", "domain")
    for bad in ("10.1.2.3", "127.0.0.1", "192.168.0.0/16", "0.0.0.0/0", "not an indicator", "", "localhost", "999.1.1.1"):
        assert n(bad) is None, bad


def test_stix_misp_otx_parsers():
    rows = {r["indicator"]: r for r in C.parse_stix(STIX)}
    assert set(rows) == {"93.184.216.7", "evil.example.net", "evil.example.net/gate.php", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    ip = rows["93.184.216.7"]
    assert ip["confidence"] == 85 and ip["threat"] == "malicious-activity" and ip["expires_at"] == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert rows["evil.example.net"]["confidence"] is None and rows["evil.example.net"]["threat"] == "c2"      # nothing invented
    misp = C.parse_misp({"response": {"Attribute": [
        {"type": "ip-dst", "value": "93.184.216.8", "to_ids": True, "category": "Network activity", "timestamp": "1794000000", "Event": {"threat_level_id": "1", "info": "APT"}},
        {"type": "ip-dst|port", "value": "93.184.216.9|8443", "to_ids": True, "Event": {"threat_level_id": "4"}},
        {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "to_ids": False},
        {"type": "email-src", "value": "phish@example.com", "to_ids": True}]}})
    by = {r["indicator"]: r for r in misp}
    assert set(by) == {"93.184.216.8", "93.184.216.9", "phish@example.com"} and by["93.184.216.8"]["confidence"] == 90 and by["93.184.216.9"]["confidence"] is None
    otx = C.parse_otx({"results": [{"name": "Campaign", "tags": ["stealer"], "modified": "2026-11-01T00:00:00", "indicators": [
        {"indicator": "bad.example.org", "type": "domain", "created": "2026-10-20T00:00:00", "expiration": "2026-12-01T00:00:00"},
        {"indicator": "http://bad.example.org/x", "type": "URL"}, {"indicator": "93.184.216.10", "type": "IPv4", "is_active": 0}]}]})
    assert {r["indicator"] for r in otx} == {"bad.example.org", "bad.example.org/x"} and otx[0]["threat"] == "stealer"


def test_matching_of_new_types_and_event_fields():
    s = IndicatorSet([("evil.example.net/gate.php", "url", "f", "c2"), ("phish@example.com", "email", "f", "phishing"), ("64500", "asn", "f", "bulletproof"),
                      ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256", "f", "malware")])
    assert len(s) == 4
    assert s.match_event({"url": "https://EVIL.example.net/gate.php?id=1"}).category == "c2"
    assert s.match_event({"user": "Phish@Example.com"}).category == "phishing" and s.match_event({"dst_asn": 64500}).category == "bulletproof"
    assert s.match_event({"url": "evil.example.net/other", "user": "alice", "dst_asn": 64501}) is None


async def _feed(db, **kw):
    f = TiFeed(name=kw.pop("name", "conn"), enabled=True, builtin=False, **kw)
    db.add(f)
    await db.commit()
    return f


async def test_taxii_fetch_pages_sends_the_key_and_keeps_false_positives(db):
    key = "secret-taxii-token"
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((str(req.url), req.headers.get("authorization"), req.headers.get("accept")))
        if "next=p2" in str(req.url):
            return httpx.Response(200, json={"objects": [STIX["objects"][1]]})
        return httpx.Response(200, json={"more": True, "next": "p2", "objects": [STIX["objects"][0]]})
    f = await _feed(db, url="https://taxii.example.com/api/collections/abc", kind="taxii", auth_header="Authorization",
                    auth_ciphertext=TokenCipher().encrypt(key), default_confidence=60, expire_days=30)
    status = await fetch_feed(db, f, transport=httpx.MockTransport(handler))
    assert status == "ok: 3 indicators", status
    assert len(seen) == 2 and all(a == key and "taxii+json" in acc for _, a, acc in seen) and "/objects/" in seen[0][0]
    assert key not in f.last_status
    rows = {r.indicator: r for r in (await db.execute(select(TiIndicator))).scalars()}
    assert rows["93.184.216.7"].confidence == 85 and rows["evil.example.net"].confidence is None
    assert rows["evil.example.net"].expires_at is not None                                   # the feed's 30-day expiry
    # analyst marks one a false positive; the next refresh keeps the verdict and the original added_at
    rows["93.184.216.7"].false_positive, rows["93.184.216.7"].fp_by = True, "analyst1"
    first_added = rows["93.184.216.7"].added_at
    await db.commit()
    await fetch_feed(db, f, transport=httpx.MockTransport(handler))
    r = (await db.execute(select(TiIndicator).where(TiIndicator.indicator == "93.184.216.7"))).scalar_one()
    assert r.false_positive and r.fp_by == "analyst1" and r.added_at == first_added
    # the enricher does not match false positives or expired indicators
    other = (await db.execute(select(TiIndicator).where(TiIndicator.indicator == "evil.example.net"))).scalar_one()
    e = Enricher(geo=GeoResolver("/nonexistent"))
    await e.refresh_ti(force=True)
    assert e.ti.match_ip("93.184.216.7") is None and e.ti.match_domain("x.evil.example.net") is not None
    other.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db.commit()
    await e.refresh_ti(force=True)
    assert e.ti.match_domain("x.evil.example.net") is None


async def test_connector_errors_keep_previous_indicators_and_never_follow_foreign_links(db):
    f = await _feed(db, url="https://otx.example.com", kind="otx", auth_header="X-OTX-API-KEY", auth_ciphertext=TokenCipher().encrypt("k"))
    calls = []

    def ok(req):
        calls.append(str(req.url))
        return httpx.Response(200, json={"next": "https://attacker.example.net/steal", "results": [{"name": "p", "indicators": [{"indicator": "bad.example.org", "type": "domain"}]}]})
    assert (await fetch_feed(db, f, transport=httpx.MockTransport(ok))).startswith("ok: 1")
    assert calls == ["https://otx.example.com/api/v1/pulses/subscribed?limit=50"]             # the foreign "next" link was not followed
    assert (await fetch_feed(db, f, transport=httpx.MockTransport(lambda r: httpx.Response(500)))).startswith("error")
    assert (await fetch_feed(db, f, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": []})))).startswith("error")
    assert len((await db.execute(select(TiIndicator))).scalars().all()) == 1                  # previous indicators kept


async def test_api_never_returns_the_key_and_indicator_verdicts(api, db):  # noqa: F811
    h = await login(api, "admin1")
    r = await api.post("/api/ti/feeds", headers=h, json={"name": "misp-lab", "url": "https://misp.example.com", "kind": "misp", "auth_value": "MISPKEY123"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_auth"] and body["auth_header"] == "Authorization" and "MISPKEY123" not in json.dumps(body)
    assert "MISPKEY123" not in (await api.get("/api/ti/feeds")).text
    feed = (await db.execute(select(TiFeed).where(TiFeed.name == "misp-lab"))).scalar_one()
    assert feed.auth_ciphertext and "MISPKEY123" not in feed.auth_ciphertext and TokenCipher().decrypt(feed.auth_ciphertext) == "MISPKEY123"
    from app.enrich.feeds import ensure_default_feeds
    await ensure_default_feeds(db)
    add = await api.post("/api/ti/manual", headers=h, json={"indicators": "93.184.216.50 evil.example.org https://evil.example.org/x d41d8cd98f00b204e9800998ecf8427e"})
    assert add.status_code == 200 and add.json()["added"] == 4, add.text[:300]
    lst = (await api.get("/api/ti/indicators?type=url")).json()
    assert lst["total"] == 1 and lst["items"][0]["indicator"] == "evil.example.org/x" and not lst["items"][0]["confidence_from_source"]
    iid = lst["items"][0]["id"]
    await api.post("/api/auth/logout", headers=h)
    ha = await login(api, "analyst1")
    assert (await api.patch(f"/api/ti/indicators/{iid}", headers=ha, json={"false_positive": True, "note": "CDN"})).status_code == 200
    st = (await api.get("/api/ti/stats")).json()
    assert st["false_positives"] == 1 and {x["type"] for x in st["by_type"]} == {"ip", "domain", "url", "md5"}
    assert (await api.get("/api/ti/indicators?false_positive=true")).json()["items"][0]["fp_by"] == "analyst1"
