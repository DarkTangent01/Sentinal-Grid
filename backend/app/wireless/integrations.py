"""Wireless controller and cloud integrations: Ruckus SmartZone / vSZ, Ruckus One, Juniper Mist and Aruba Central.

Each integration reads APs, radios, WLANs and clients from the vendor's public REST API (read-only GET / query calls)
and hands them to the same persistence the SNMP wireless collector uses (wireless.store.persist). APs, radios,
clients, sessions, roaming, history rollups, events and alerts therefore work exactly as for a Catalyst 9800. The data
is stored under a virtual controller row in the inventory (monitoring "external": never SNMP-polled, never reachable
through the access gateway).

Where requests may go (SSRF control):
  smartzone      https://<IP literal inside an authorised management network>:8443 (or 7443 / 443)
  mist           https://api*.mist.com (any Mist cloud region)
  ruckus_one     https://*.ruckus.cloud
  aruba_central  https://*.central.arubanetworks.com
Anything else is refused when the integration is saved and again before every sync.

Validation status: the request and field mapping follow each vendor's published API documentation and are tested
against recorded-shape fixtures (tests/test_wireless_integrations.py), not against a live controller or tenant.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db.models import DeviceSshCredential, Switch, SwitchNetwork, WirelessIntegration
from ..security import TokenCipher

log = logging.getLogger("wireless.integrations")
KINDS = {"smartzone": "Ruckus SmartZone / vSZ", "ruckus_one": "Ruckus One", "mist": "Juniper Mist", "aruba_central": "Aruba Central"}
VENDOR = {"smartzone": "ruckus", "ruckus_one": "ruckus", "mist": "juniper", "aruba_central": "aruba"}
CLOUD_SUFFIX = {"mist": (".mist.com",), "ruckus_one": (".ruckus.cloud",), "aruba_central": (".central.arubanetworks.com",)}
RAN = {"wireless_ap", "wireless_radio", "wireless_radio_rf", "wireless_wlan", "wireless_client"}
MAX_PAGES = 200


class IntegrationError(Exception):
    pass


def validate_base_url(kind: str, url: str, networks: list[SwitchNetwork]) -> str:
    if kind not in KINDS:
        raise IntegrationError(f"unknown integration kind '{kind}'")
    u = urlsplit((url or "").strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password or (u.path not in ("", "/")) or u.query or u.fragment:
        raise IntegrationError("the base URL must be https://host[:port] with nothing after the host")
    host = u.hostname.lower()
    if kind == "smartzone":
        from ..switches.poller import validate_address
        try:
            validate_address(host, networks)
        except ValueError as e:
            raise IntegrationError(f"SmartZone address: {e}")
        if (u.port or 443) not in (443, 7443, 8443):
            raise IntegrationError("SmartZone API port must be 8443, 7443 or 443")
    else:
        try:
            ipaddress.ip_address(host)
            raise IntegrationError("cloud integrations take the vendor's API host name, not an address")
        except ValueError:
            pass
        if not any(host.endswith(sfx) for sfx in CLOUD_SUFFIX[kind]) or (u.port or 443) != 443:
            raise IntegrationError(f"{KINDS[kind]} API host must end with {' or '.join(CLOUD_SUFFIX[kind])} (port 443)")
    return f"https://{host}{f':{u.port}' if u.port and u.port != 443 else ''}"


def secret_of(cred: DeviceSshCredential | None) -> dict:
    if cred is None or not cred.secret_ciphertext:
        return {}
    return json.loads(TokenCipher().decrypt(cred.secret_ciphertext))


def mac(v) -> str:
    h = "".join(c for c in str(v or "").lower() if c in "0123456789abcdef")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def band(v) -> str:
    s = str(v or "").lower().replace("ghz", "").replace("g", "").strip()
    return {"2.4": "2.4", "24": "2.4", "2": "2.4", "band_24": "2.4", "5": "5", "band_5": "5", "6": "6", "band_6": "6", "11ng": "2.4", "11na": "5",
            "11ac": "5", "11ax-5": "5", "11ax-2.4": "2.4"}.get(s, "")


def num(v):
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def wlan_id(ssid: str) -> int:
    return zlib.crc32(ssid.encode()) % 2_000_000_000          # stable small id per SSID (the vendors' ids are strings)


def empty() -> dict:
    return {"wireless_aps": {}, "wireless_ap_table_ok": True, "wireless_radios": {}, "wireless_rf": {}, "wireless_wlans": {},
            "wireless_radio_wlans": {}, "wireless_clients": {}, "wireless_client_table_ok": True}


def add_client(d: dict, m: str, *, ap_mac: str, ssid: str, ip="", vlan=None, band_="", channel=None, rssi=None, snr=None, rx=None, tx=None,
               session_s=None, username="", source: str) -> None:
    if not m:
        return
    d["wireless_clients"][m] = {"ip": ip or "", "ap_mac": ap_mac, "ssid": ssid or "", "vlan": int(vlan) if str(vlan or "").isdigit() else None,
                                "band": band_, "channel": int(channel) if num(channel) is not None else None, "status": "associated",
                                "rssi_dbm": num(rssi), "snr_db": num(snr), "rx_bytes": int(rx) if num(rx) is not None else None,
                                "tx_bytes": int(tx) if num(tx) is not None else None, "session_s": int(session_s) if num(session_s) is not None else None,
                                "username": username or "", "sources": [source]}
    if ssid:
        w = d["wireless_wlans"].setdefault(wlan_id(ssid), {"profile": ssid, "ssid": ssid, "enabled": True, "security": "", "max_clients": None, "clients": 0})
        w["clients"] = (w["clients"] or 0) + 1


def add_ap(d: dict, m: str, *, name: str, ip="", model="", serial="", software="", location="", uptime_s=None, clients=None, online=True, source: str) -> None:
    if not m or not online:          # an AP the controller lists as offline is treated like one missing from the AP table
        return
    d["wireless_aps"][m] = {"name": name or m, "ip": ip or "", "model": model or "", "serial": serial or "", "software": software or "",
                            "location": location or "", "uptime_s": int(uptime_s) if num(uptime_s) is not None else None,
                            "clients": int(clients) if num(clients) is not None else None, "oper_status": "associated", "admin_enabled": True,
                            "sources": [source]}


def add_radio(d: dict, ap_m: str, slot: int, *, band_: str, channel=None, width=None, util=None, clients=None, noise=None, up=True) -> None:
    if ap_m not in d["wireless_aps"]:
        return
    key = f"{ap_m}/{slot}"
    d["wireless_radios"][key] = {"ap_mac": ap_m, "slot": slot, "band": band_, "radio_type": f"{band_} GHz" if band_ else "", "channel": int(channel) if num(channel) is not None else None,
                                 "channel_width_mhz": int(num(width)) if num(width) is not None else None, "channel_util_pct": num(util),
                                 "clients": int(clients) if num(clients) is not None else None, "admin_enabled": True, "oper_up": up}
    if num(noise) is not None:
        d["wireless_rf"][key] = {"noise_dbm": num(noise)}


# ------------------------------------------------------------------ vendor clients
class Client:
    def __init__(self, integ: WirelessIntegration, secret: dict, username: str, transport=None):
        st = get_settings()
        self.i, self.secret, self.username = integ, secret, username
        self.base = integ.base_url.rstrip("/")
        self.http = httpx.AsyncClient(timeout=st.wireless_integration_timeout_seconds, verify=integ.verify_tls, transport=transport, follow_redirects=False)
        self.max_clients = st.wireless_integration_max_clients
        self.new_secret: dict | None = None             # Aruba Central: rotated refresh token to store back in the vault

    async def close(self):
        await self.http.aclose()

    async def _json(self, method: str, url: str, **kw):
        r = await self.http.request(method, url, **kw)
        if r.status_code in (401, 403):
            raise IntegrationError(f"{KINDS[self.i.kind]} rejected the credential (HTTP {r.status_code})")
        if r.status_code >= 400:
            raise IntegrationError(f"{KINDS[self.i.kind]} API error HTTP {r.status_code} on {urlsplit(url).path}")
        if len(r.content) > 64 << 20:
            raise IntegrationError("API response larger than 64 MB")
        return r.json()


class SmartZone(Client):
    """SmartZone public API: serviceTicket login, POST query/ap and query/client with paging."""
    async def fetch(self) -> dict:
        v = self.i.api_version or "v9_1"
        api = f"{self.base}/wsg/api/public/{v}"
        tk = (await self._json("POST", f"{api}/serviceTicket", json={"username": self.username, "password": self.secret.get("password", "")})).get("serviceTicket")
        if not tk:
            raise IntegrationError("SmartZone did not return a service ticket")
        d = empty()
        zones = set(self.i.site_filter or [])
        flt = {"filters": [{"type": "ZONE", "value": z} for z in zones]} if zones else {}

        async def query(kind: str, cap: int):
            rows, page = [], 1
            while page <= MAX_PAGES and len(rows) < cap:
                j = await self._json("POST", f"{api}/query/{kind}", params={"serviceTicket": tk}, json={**flt, "page": page, "limit": 1000})
                rows += j.get("list") or []
                if not j.get("hasMore"):
                    break
                page += 1
            return rows
        for a in await query("ap", 20000):
            m = mac(a.get("apMac"))
            add_ap(d, m, name=a.get("deviceName"), ip=a.get("ip"), model=a.get("model"), serial=a.get("serial"), software=a.get("firmwareVersion"),
                   location=a.get("location") or a.get("zoneName"), uptime_s=a.get("uptime"), clients=a.get("numClients"),
                   online=str(a.get("status") or "").lower() in ("online", "connect", "connected"), source="smartzone")
            for slot, (b, chk, utk, nk, ck) in enumerate((("2.4", "channel24G", "airtime24G", "noise24G", "numClients24G"),
                                                           ("5", "channel5G", "airtime5G", "noise5G", "numClients5G"),
                                                           ("6", "channel6G", "airtime6G", "noise6G", "numClients6G"))):
                if a.get(chk) not in (None, "", "N/A"):
                    add_radio(d, m, slot, band_=b, channel=str(a.get(chk)).split(" ")[0], util=a.get(utk), noise=a.get(nk), clients=a.get(ck))
        clients = await query("client", self.max_clients)
        d["wireless_client_truncated"] = len(clients) >= self.max_clients
        for c in clients:
            add_client(d, mac(c.get("clientMac")), ap_mac=mac(c.get("apMac")), ssid=c.get("ssid") or "", ip=c.get("ipAddress") or c.get("clientIP") or "",
                       vlan=c.get("vlan"), band_=band(c.get("radioType") or c.get("band")), channel=c.get("channel"), rssi=c.get("rssi"), snr=c.get("snr"),
                       rx=c.get("rxBytes"), tx=c.get("txBytes"), session_s=c.get("sessionDuration"), username=c.get("userName") or "", source="smartzone")
        return d


class Mist(Client):
    """Mist: Authorization: Token; /orgs/{org}/sites, /sites/{site}/stats/devices?type=ap, /sites/{site}/stats/clients."""
    async def fetch(self) -> dict:
        h = {"Authorization": f"Token {self.secret.get('token', '')}"}
        api = f"{self.base}/api/v1"
        sites = await self._json("GET", f"{api}/orgs/{self.i.org_id}/sites", headers=h)
        want = set(self.i.site_filter or [])
        d = empty()
        n = 0
        for site in sites:
            if want and site.get("id") not in want and site.get("name") not in want:
                continue
            for a in await self._json("GET", f"{api}/sites/{site['id']}/stats/devices", headers=h, params={"type": "ap", "limit": 1000}):
                m = mac(a.get("mac"))
                add_ap(d, m, name=a.get("name"), ip=a.get("ip"), model=a.get("model"), serial=a.get("serial"), software=a.get("version"),
                       location=site.get("name"), uptime_s=a.get("uptime"), clients=a.get("num_clients"),
                       online=str(a.get("status") or "").lower() == "connected", source="mist")
                for slot, (key, b) in enumerate((("band_24", "2.4"), ("band_5", "5"), ("band_6", "6"))):
                    r = (a.get("radio_stat") or {}).get(key)
                    if r and not r.get("disabled"):
                        add_radio(d, m, slot, band_=b, channel=r.get("channel"), width=r.get("bandwidth"), util=r.get("util_all"),
                                  clients=r.get("num_clients"), noise=r.get("noise_floor"))
            clients = await self._json("GET", f"{api}/sites/{site['id']}/stats/clients", headers=h, params={"limit": 1000})
            for c in clients:
                if n >= self.max_clients:
                    d["wireless_client_truncated"] = True
                    break
                add_client(d, mac(c.get("mac")), ap_mac=mac(c.get("ap_mac")), ssid=c.get("ssid") or "", ip=c.get("ip") or "", vlan=c.get("vlan_id"),
                           band_=band(c.get("band")), channel=c.get("channel"), rssi=c.get("rssi"), snr=c.get("snr"), rx=c.get("rx_bytes"),
                           tx=c.get("tx_bytes"), session_s=c.get("uptime"), username=c.get("username") or "", source="mist")
                n += 1
        return d


class RuckusOne(Client):
    """Ruckus One: OAuth2 client credentials per tenant, then POST /venues/aps/query and /venues/aps/clients/query."""
    async def fetch(self) -> dict:
        tok = await self._json("POST", f"{self.base}/oauth2/token/{self.i.org_id}",
                               data={"grant_type": "client_credentials", "client_id": self.username, "client_secret": self.secret.get("token", "")})
        h = {"Authorization": f"Bearer {tok.get('access_token', '')}"}
        venues = list(self.i.site_filter or [])
        flt = {"filters": {"venueId": venues}} if venues else {}
        d = empty()

        async def query(path: str, cap: int):
            rows, page = [], 1
            while page <= MAX_PAGES and len(rows) < cap:
                j = await self._json("POST", f"{self.base}{path}", headers=h, json={**flt, "page": page, "pageSize": 500})
                data = j.get("data") or []
                rows += data
                if len(rows) >= int(j.get("totalCount") or 0) or not data:
                    break
                page += 1
            return rows
        for a in await query("/venues/aps/query", 20000):
            m = mac(a.get("apMac") or a.get("macAddress"))
            st = str(a.get("status") or a.get("deviceStatus") or "").lower()
            add_ap(d, m, name=a.get("name"), ip=a.get("IP") or a.get("ip"), model=a.get("model"), serial=a.get("serialNumber"),
                   software=a.get("fwVersion") or a.get("firmware"), location=a.get("venueName"), clients=a.get("clients"),
                   online=st.startswith("2") or "operational" in st or st == "online", source="ruckus_one")
            for slot, r in enumerate(a.get("radios") or []):
                add_radio(d, m, slot, band_=band(r.get("band") or r.get("radioBand")), channel=r.get("channel"), width=r.get("channelBandwidth"),
                          util=r.get("channelUtilization"), clients=r.get("clients"), noise=r.get("noiseFloor"))
        clients = await query("/venues/aps/clients/query", self.max_clients)
        d["wireless_client_truncated"] = len(clients) >= self.max_clients
        for c in clients:
            add_client(d, mac(c.get("clientMac") or c.get("macAddress")), ap_mac=mac(c.get("apMac")), ssid=c.get("ssid") or c.get("networkName") or "",
                       ip=c.get("ipAddress") or "", vlan=c.get("vlan"), band_=band(c.get("radioBand") or c.get("band")), channel=c.get("channel"),
                       rssi=c.get("rssi") or c.get("receiveSignalStrength"), snr=c.get("snr"), rx=c.get("rxBytes"), tx=c.get("txBytes"),
                       session_s=c.get("sessionDuration"), username=c.get("username") or "", source="ruckus_one")
        return d


class ArubaCentral(Client):
    """Aruba Central API gateway: Bearer access token (refreshed with client id / secret / refresh token when it
    expires), GET /monitoring/v2/aps and /monitoring/v1/clients/wireless with offset paging."""
    async def _token(self) -> str:
        return self.secret.get("access_token") or self.secret.get("token", "")

    async def _refresh(self) -> str:
        s = self.secret
        if not (s.get("client_id") and s.get("client_secret") and s.get("refresh_token")):
            raise IntegrationError("Aruba Central token expired and no refresh credentials are stored")
        j = await self._json("POST", f"{self.base}/oauth2/token", params={"client_id": s["client_id"], "client_secret": s["client_secret"],
                                                                          "grant_type": "refresh_token", "refresh_token": s["refresh_token"]})
        self.secret = {**s, "access_token": j.get("access_token", ""), "refresh_token": j.get("refresh_token", s["refresh_token"])}
        self.new_secret = self.secret
        return self.secret["access_token"]

    async def _get(self, path: str, params: dict):
        tok = await self._token()
        for attempt in (0, 1):
            r = await self.http.get(f"{self.base}{path}", headers={"Authorization": f"Bearer {tok}"}, params=params)
            if r.status_code == 401 and attempt == 0:
                tok = await self._refresh()
                continue
            if r.status_code >= 400:
                raise IntegrationError(f"Aruba Central API error HTTP {r.status_code} on {path}")
            return r.json()
        raise IntegrationError("Aruba Central rejected the refreshed token")

    async def fetch(self) -> dict:
        d = empty()
        sites = set(self.i.site_filter or [])

        async def paged(path: str, key: str, cap: int):
            rows, off = [], 0
            while len(rows) < cap and off // 1000 < MAX_PAGES:
                j = await self._get(path, {"limit": 1000, "offset": off, "calculate_total": "true"})
                part = j.get(key) or []
                rows += part
                off += len(part)
                if not part or off >= int(j.get("total") or j.get("count") or 0):
                    break
            return rows
        for a in await paged("/monitoring/v2/aps", "aps", 20000):
            if sites and a.get("site") not in sites:
                continue
            m = mac(a.get("macaddr"))
            add_ap(d, m, name=a.get("name"), ip=a.get("ip_address"), model=a.get("model"), serial=a.get("serial"), software=a.get("firmware_version"),
                   location=a.get("site"), clients=a.get("client_count"), online=str(a.get("status") or "").lower() == "up", source="aruba_central")
            for r in a.get("radios") or []:
                add_radio(d, m, int(r.get("index") or 0), band_=band(r.get("band")), channel=str(r.get("channel") or "").rstrip("+-E"),
                          util=r.get("utilization"), up=str(r.get("status") or "up").lower() == "up")
        clients = await paged("/monitoring/v1/clients/wireless", "clients", self.max_clients)
        d["wireless_client_truncated"] = len(clients) >= self.max_clients
        for c in clients:
            if sites and c.get("site") not in sites:
                continue
            add_client(d, mac(c.get("macaddr")), ap_mac=mac(c.get("associated_device_mac")), ssid=c.get("network") or "", ip=c.get("ip_address") or "",
                       vlan=c.get("vlan"), band_=band(c.get("band")), channel=c.get("channel"), rssi=c.get("signal_db"), snr=c.get("snr"),
                       username=c.get("username") or "", source="aruba_central")
        return d


CLIENTS = {"smartzone": SmartZone, "mist": Mist, "ruckus_one": RuckusOne, "aruba_central": ArubaCentral}


# ------------------------------------------------------------------ sync
async def controller_row(s: AsyncSession, integ: WirelessIntegration) -> Switch:
    sw = await s.get(Switch, integ.switch_id) if integ.switch_id else None
    if sw is None:
        sw = Switch(name=f"{KINDS[integ.kind]}: {integ.name}"[:128], address=f"integration:{integ.kind}:{integ.id}", vendor=VENDOR[integ.kind],
                    family=KINDS[integ.kind], product_line=KINDS[integ.kind], device_type="wlc", role="wlc", monitoring="external", state="unknown",
                    capabilities={}, group_state={}, health={}, thresholds={}, created_by="integration")
        s.add(sw)
        await s.flush()
        integ.switch_id = sw.id
    return sw


async def sync(s: AsyncSession, ch, integ: WirelessIntegration, *, transport=None, now: datetime | None = None) -> dict:
    from .store import persist
    now = now or datetime.now(timezone.utc)
    iid = integ.id
    integ.last_sync_at = now
    try:
        nets = (await s.execute(select(SwitchNetwork))).scalars().all()
        validate_base_url(integ.kind, integ.base_url, nets)
        cred = await s.get(DeviceSshCredential, integ.credential_id) if integ.credential_id else None
        if cred is None:
            raise IntegrationError("no credential assigned (Credential Vault: https for SmartZone, api_token for the clouds)")
        cl = CLIENTS[integ.kind](integ, secret_of(cred), cred.username, transport=transport)
        try:
            data = await cl.fetch()
        except httpx.HTTPError as e:
            raise IntegrationError(f"{KINDS[integ.kind]} request failed: {type(e).__name__}")
        finally:
            await cl.close()
        if cl.new_secret is not None:            # Aruba Central rotated its refresh token: keep the new one, encrypted
            cred.secret_ciphertext = TokenCipher().encrypt(json.dumps(cl.new_secret))
        sw = await controller_row(s, integ)
        res = await persist(s, ch, sw, data, set(RAN), now, {})
        sw.state, sw.last_poll_at, sw.last_success_at, sw.last_error = "up", now, now, ""
        integ.last_ok_at, integ.last_error = now, ""
        integ.stats = {"aps": len(data["wireless_aps"]), "radios": len(data["wireless_radios"]), "clients": len(data["wireless_clients"]),
                       "wlans": len(data["wireless_wlans"]), "truncated": bool(data.get("wireless_client_truncated"))}
        await s.commit()
        return {"ok": True, **integ.stats, "events": res.get("events") if isinstance(res, dict) else None}
    except IntegrationError as e:
        await s.rollback()
        integ = await s.get(WirelessIntegration, iid)
        integ.last_sync_at, integ.last_error = now, str(e)[:2000]
        if integ.switch_id:
            sw = await s.get(Switch, integ.switch_id)
            if sw is not None:
                sw.state, sw.last_poll_at, sw.last_error = "down", now, str(e)[:500]
        await s.commit()
        return {"ok": False, "error": str(e)}


async def run_due(ch, s: AsyncSession, now: datetime | None = None, transport=None) -> dict:
    """Worker loop: sync integrations whose interval has passed (a lease keeps two workers from syncing the same one)."""
    now = now or datetime.now(timezone.utc)
    ids = [i.id for i in (await s.execute(select(WirelessIntegration).where(WirelessIntegration.enabled.is_(True)))).scalars()
           if (i.last_sync_at is None or (i.last_sync_at if i.last_sync_at.tzinfo else i.last_sync_at.replace(tzinfo=timezone.utc))
               <= now - timedelta(seconds=max(60, i.interval_seconds)))
           and (i.lease_until is None or (i.lease_until if i.lease_until.tzinfo else i.lease_until.replace(tzinfo=timezone.utc)) < now)]
    done = 0
    for iid in ids:
        r = await s.execute(update(WirelessIntegration).where(WirelessIntegration.id == iid).values(lease_until=now + timedelta(minutes=10)))
        await s.commit()
        if r.rowcount != 1:
            continue
        integ = await s.get(WirelessIntegration, iid)
        try:
            await sync(s, ch, integ, transport=transport, now=now)
            done += 1
        except Exception:
            log.exception("wireless integration %s failed", iid)
            await s.rollback()
        finally:
            await s.execute(update(WirelessIntegration).where(WirelessIntegration.id == iid).values(lease_until=None))
            await s.commit()
    return {"synced": done, "due": len(ids)}
