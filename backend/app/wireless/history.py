"""Wireless client history: association sessions, association-change events and the 30-minute client rollup.

What the controller tells us (Cisco 9800 / AireOS over SNMP, polled; no event stream is received):
  * the client table on every client poll (wireless_client group), with each client's AP, SSID, band, VLAN, IP and
    cldcClientUpTime = seconds since the client associated;
  * nothing about a client that has already left, and no authentication-failure records.

From that:
  * a session (WirelessClientSession, PostgreSQL) = one association. It starts at the controller's association time
    (now − cldcClientUpTime, start_source "controller") or, when the controller does not report it, at the first poll
    that listed the client ("observed"). It ends when the client is no longer listed (ended_at = the last poll that
    listed it), when the controller reports a newer association than the one we track (a reconnect between two polls),
    or when the client moves to another SSID (a new association).
  * an event row (ClickHouse wireless_client_events) per detected change: connect, disconnect, roam, band_change,
    ssid_change. Roams and band changes are detected between polls, so their time is the poll time.
  * concurrency and unique clients come from the per-poll client snapshots (wireless_client_samples), rolled up per
    30-minute slot by aggregate(): unique MACs per slot and the client count per 5-minute bucket.

Nothing here fabricates a session from a snapshot: a client seen in one poll is one observed client, and a session is
counted once per association that the controller's table showed.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.models import Switch, WirelessClient, WirelessClientSession

log = logging.getLogger("wireless.history")

EVENT_COLS = ["ts", "wlc_id", "mac", "kind", "session_id", "ssid", "ap_id", "from_ap_id", "band", "from_band", "from_ssid", "vlan",
              "reason", "precision"]
SLOT_S = 1800                 # rollup grain: whole slots per day in every whole- and half-hour timezone
BUCKET_S = 300                # concurrency resolution (the controller's client table is polled every 300 s by default)
RECONNECT_MARGIN_S = 60       # the client table is walked over up to a minute: tolerance on the reported association time
MAX_SESSION_APS = 50
EXPIRE_AFTER = timedelta(days=1)


def _aware(v):
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def _ev(kind: str, ts: datetime, sw: Switch, mac: str, sid: int | None, *, ssid="", ap_id=None, from_ap_id=None, band="", from_band="",
        from_ssid="", vlan=None, reason="", precision="poll") -> dict:
    return {"ts": ts, "wlc_id": sw.id, "mac": mac, "kind": kind, "session_id": sid or 0, "ssid": ssid or "", "ap_id": ap_id or 0,
            "from_ap_id": from_ap_id or 0, "band": band or "", "from_band": from_band or "", "from_ssid": from_ssid or "",
            "vlan": vlan or 0, "reason": reason or "", "precision": precision}


def snapshot(clients: dict[str, WirelessClient]) -> dict[str, dict]:
    """State of the stored clients before this poll changes them (track() compares against it)."""
    return {m: {"present": bool(c.present), "ap_mac": c.ap_mac or "", "ap_id": c.ap_id, "band": c.band or "", "ssid": c.ssid or "",
                "last_seen": _aware(c.last_seen), "session_id": c.session_id, "reason": c.reason or ""} for m, c in clients.items()}


async def track(s: AsyncSession, sw: Switch, now: datetime, cur: dict[str, dict], before: dict[str, dict], rows: dict[str, WirelessClient],
                ap_ids: dict[str, int], complete: bool, stored: dict[str, WirelessClient] | None = None) -> list[dict]:
    """Update sessions for one client poll and return the ClickHouse event rows.

    cur: the controller's client table (mac → normalised row); before: snapshot() of the stored clients; rows: the
    WirelessClient row of every client in cur; complete: the table was read whole (not empty by error, not truncated),
    so a client missing from it has left. Without a complete table nothing is closed. stored: the stored client rows
    (those missing from cur lose their open-session pointer when their session closes)."""
    events: list[dict] = []
    load_ids: set[int] = set()
    plans: list[tuple] = []
    for m, d in cur.items():
        b = before.get(m)
        sid = b["session_id"] if b else None
        ap_id = ap_ids.get(d.get("ap_mac") or "")
        up = d.get("session_s")
        assoc = now - timedelta(seconds=up) if isinstance(up, (int, float)) and up >= 0 else None
        if sid is None or not b["present"]:
            plans.append(("new", m, d, b, sid, ap_id, assoc))
            if sid is not None:
                load_ids.add(sid)          # a session left open while the client was absent: close it first
            continue
        last = b["last_seen"]
        elapsed = (now - last).total_seconds() if last else None
        moved = bool(b["ap_mac"] and d.get("ap_mac") and b["ap_mac"] != d["ap_mac"])
        ssid_change = bool(b["ssid"] and d.get("ssid") and b["ssid"] != d["ssid"])
        # the controller reports an association that began after the poll that last listed the client: it left and
        # came back in between. When it changed AP at the same time, the controller may restart the timer on a roam,
        # so that case stays one session (a roam), not a new connection.
        reassoc = up is not None and elapsed is not None and up + RECONNECT_MARGIN_S < elapsed
        if ssid_change or (reassoc and not moved):
            plans.append(("reconnect", m, d, b, sid, ap_id, assoc, "ssid_change" if ssid_change else "reconnected"))
            load_ids.add(sid)
        elif moved or (b["band"] and d.get("band") and b["band"] != d["band"]):
            plans.append(("change", m, d, b, sid, ap_id, moved))
            load_ids.add(sid)
    gone = [m for m, b in before.items() if b["present"] and b["session_id"] and m not in cur] if complete else []
    load_ids.update(before[m]["session_id"] for m in gone)
    sessions: dict[int, WirelessClientSession] = {}
    ids = sorted(load_ids)
    for i in range(0, len(ids), 5000):
        for x in (await s.execute(select(WirelessClientSession).where(WirelessClientSession.id.in_(ids[i:i + 5000])))).scalars():
            sessions[x.id] = x

    def close(x: WirelessClientSession | None, b: dict, reason: str):
        if x is None or x.ended_at is not None:
            return
        x.ended_at = b["last_seen"] or now
        x.end_reason = reason
        x.disconnect_reason = (b.get("reason") or "")[:64]
        events.append(_ev("disconnect", x.ended_at, sw, x.mac, x.id, ssid=x.ssid, ap_id=x.last_ap_id, band=x.band, vlan=x.vlan,
                          reason=x.disconnect_reason or reason, precision="last_listed"))

    opened: list[tuple[WirelessClientSession, str, dict]] = []

    def open_(m: str, d: dict, ap_id, assoc, b: dict | None):
        start = assoc or now
        x = WirelessClientSession(wlc_id=sw.id, mac=m, ip=d.get("ip") or "", ssid=(d.get("ssid") or "")[:64], vlan=d.get("vlan"),
                                  band=d.get("band") or "", first_ap_id=ap_id, last_ap_id=ap_id, site=sw.site or "", started_at=start,
                                  start_source="controller" if assoc else "observed", roams=0, band_changes=0,
                                  aps=[ap_id] if ap_id else [])
        s.add(x)
        opened.append((x, m, d))

    for p in plans:
        kind, m, d, b, sid, ap_id = p[:6]
        if kind == "new":
            if sid is not None and b:
                close(sessions.get(sid), b, "not_listed")
            open_(m, d, ap_id, p[6], b)
        elif kind == "reconnect":
            close(sessions.get(sid), b, p[7])
            if p[7] == "ssid_change":
                events.append(_ev("ssid_change", now, sw, m, sid, ssid=d.get("ssid"), from_ssid=b["ssid"], ap_id=ap_id, band=d.get("band")))
            open_(m, d, ap_id, p[6], b)
        else:
            x = sessions.get(sid)
            if x is None:
                continue
            if p[6]:
                x.roams = (x.roams or 0) + 1
                x.aps = (list(x.aps or []) + [ap_id])[-MAX_SESSION_APS:] if ap_id else list(x.aps or [])
                events.append(_ev("roam", now, sw, m, sid, ssid=d.get("ssid"), ap_id=ap_id, from_ap_id=b["ap_id"], band=d.get("band"),
                                  from_band=b["band"], vlan=d.get("vlan")))
            if b["band"] and d.get("band") and b["band"] != d["band"]:
                x.band_changes = (x.band_changes or 0) + 1
                events.append(_ev("band_change", now, sw, m, sid, ssid=d.get("ssid"), ap_id=ap_id, band=d.get("band"), from_band=b["band"]))
            x.last_ap_id, x.band = ap_id or x.last_ap_id, d.get("band") or x.band
            x.ip, x.vlan = d.get("ip") or x.ip, d.get("vlan") if d.get("vlan") is not None else x.vlan
    stored = stored or {}
    for m in gone:
        close(sessions.get(before[m]["session_id"]), before[m], "not_listed")
        c = rows.get(m) or stored.get(m)
        if c is not None:
            c.session_id = None
    if opened:
        await s.flush()             # session ids for the event rows and the client rows
    for x, m, d in opened:
        rows[m].session_id = x.id
        events.append(_ev("connect", x.started_at, sw, m, x.id, ssid=x.ssid, ap_id=x.first_ap_id, band=x.band, vlan=x.vlan,
                          precision="controller" if x.start_source == "controller" else "first_listed"))
    return events


async def expire(s: AsyncSession, now: datetime | None = None) -> int:
    """Close sessions whose client has not been listed for a day (controller removed or no longer polled): ended at the
    last poll that listed the client. A controller that comes back with the client still associated continues it."""
    now = now or datetime.now(timezone.utc)
    rows = (await s.execute(select(WirelessClientSession, WirelessClient.last_seen).join(
        WirelessClient, (WirelessClient.session_id == WirelessClientSession.id), isouter=True).where(
        WirelessClientSession.ended_at.is_(None)))).all()
    n = 0
    for x, seen in rows:
        seen = _aware(seen)
        if seen is None or seen < now - EXPIRE_AFTER:
            x.ended_at, x.end_reason = seen or _aware(x.started_at), "expired"
            n += 1
    if n:
        await s.execute(update(WirelessClient).where(WirelessClient.session_id.in_([x.id for x, _ in rows if x.end_reason == "expired"]))
                        .values(session_id=None))
    return n


# ------------------------------------------------------------------ rollup
SLOT_INSERT = """
INSERT INTO wireless_client_slots (slot, wlc_id, ssid, ap_id, band, clients, conc, version)
SELECT toDateTime(toStartOfInterval(b, INTERVAL 30 MINUTE), 'UTC') AS slot, wlc_id, ssid, ap_id, band,
       uniqExactArrayState(macs), sumMapState([b], [n]), {v:UInt64}
FROM (
    SELECT b, wlc_id, ssid, ap_id, band, groupArray(mac) AS macs, toUInt64(count()) AS n
    FROM (
        SELECT toDateTime(toStartOfFiveMinutes(ts), 'UTC') AS b, wlc_id, mac,
               argMax(ssid, ts) AS ssid, argMax(ap_id, ts) AS ap_id, argMax(band, ts) AS band
        FROM wireless_client_samples
        WHERE ts >= {a:DateTime64(3)} AND ts < {z:DateTime64(3)}
        GROUP BY b, wlc_id, mac
    )
    GROUP BY b, wlc_id, ssid, ap_id, band
)
GROUP BY slot, wlc_id, ssid, ap_id, band
"""


def _floor(t: datetime, step: int) -> datetime:
    e = int(t.timestamp())
    return datetime.fromtimestamp(e - e % step, tz=timezone.utc)


async def aggregate(ch, now: datetime | None = None, redo_slots: int = 3) -> dict:
    """Roll client snapshots up into wireless_client_slots, incrementally.

    Rebuilds the last `redo_slots` slots (a slot still filling, and samples from a wireless poll that ran long) plus
    everything after the newest stored slot; the first run backfills every snapshot still kept (14 days), one day per
    statement. Slots are rebuilt whole, so a rebuilt slot replaces the previous row (ReplacingMergeTree version)."""
    now = now or datetime.now(timezone.utc)
    last = (await ch.aquery("SELECT max(slot) AS m, count() AS n FROM wireless_client_slots"))[0]
    if int(last["n"]) == 0:
        first = (await ch.aquery("SELECT min(ts) AS m, count() AS n FROM wireless_client_samples"))[0]
        if int(first["n"]) == 0:
            return {"slots_from": None, "statements": 0}
        start = _floor(_as_dt(first["m"]), SLOT_S)
    else:
        start = _floor(_as_dt(last["m"]), SLOT_S) - timedelta(seconds=SLOT_S * (redo_slots - 1))
    start = min(start, _floor(now, SLOT_S) - timedelta(seconds=SLOT_S * (redo_slots - 1)))
    end = _floor(now, SLOT_S) + timedelta(seconds=SLOT_S)
    v = int(time.time() * 1000)
    a, n = start, 0
    while a < end:
        z = min(end, a + timedelta(days=1))
        await ch.acommand(SLOT_INSERT, {"a": a, "z": z, "v": v})
        a, n = z, n + 1
    return {"slots_from": start.isoformat(), "statements": n}


def _as_dt(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v)).replace(tzinfo=timezone.utc)


async def run_aggregation(ch, s: AsyncSession) -> dict:
    """Worker loop body: rollup, then close sessions of clients not listed for a day."""
    res = await aggregate(ch)
    res["expired_sessions"] = await expire(s)
    await s.commit()
    return res


async def housekeeping(s: AsyncSession, now: datetime, retention_days: int) -> None:
    from sqlalchemy import delete
    await s.execute(delete(WirelessClientSession).where(WirelessClientSession.ended_at.is_not(None),
                                                        WirelessClientSession.ended_at < now - timedelta(days=retention_days)))
