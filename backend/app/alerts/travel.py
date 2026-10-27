"""Impossible-travel detection for VPN logins (pure functions)."""
from __future__ import annotations

import math
from datetime import datetime, timezone

# Approximate country centroids (lat, lon) used only when GeoIP coordinates are unavailable.
CENTROIDS = {
    "India": (22.0, 79.0), "United States": (39.8, -98.6), "United Kingdom": (54.0, -2.0), "Germany": (51.2, 10.4),
    "France": (46.6, 2.4), "Netherlands": (52.2, 5.3), "Singapore": (1.35, 103.8), "Japan": (36.2, 138.3),
    "China": (35.0, 103.0), "Russian Federation": (61.5, 105.3), "Russia": (61.5, 105.3), "Brazil": (-14.2, -51.9),
    "Canada": (56.1, -106.3), "Australia": (-25.3, 133.8), "United Arab Emirates": (23.4, 53.8), "Saudi Arabia": (23.9, 45.1),
    "South Africa": (-30.6, 22.9), "Nigeria": (9.1, 8.7), "Indonesia": (-0.8, 113.9), "Vietnam": (14.1, 108.3),
    "Viet Nam": (14.1, 108.3), "Thailand": (15.9, 100.9), "Malaysia": (4.2, 101.9), "Philippines": (12.9, 121.8),
    "Bangladesh": (23.7, 90.4), "Pakistan": (30.4, 69.3), "Sri Lanka": (7.9, 80.8), "Nepal": (28.4, 84.1),
    "Hong Kong": (22.3, 114.2), "Taiwan": (23.7, 121.0), "Korea, Republic of": (35.9, 127.8), "South Korea": (35.9, 127.8),
    "Ireland": (53.4, -8.2), "Spain": (40.5, -3.7), "Italy": (41.9, 12.6), "Poland": (51.9, 19.1), "Sweden": (60.1, 18.6),
    "Switzerland": (46.8, 8.2), "Turkey": (38.9, 35.2), "Ukraine": (48.4, 31.2), "Israel": (31.0, 34.9), "Egypt": (26.8, 30.8),
    "Mexico": (23.6, -102.6), "Argentina": (-38.4, -63.6), "Kenya": (-0.02, 37.9), "Qatar": (25.4, 51.2), "Iran": (32.4, 53.7),
}


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def _t(v) -> datetime:
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(v).replace(" ", "T").replace("Z", "+00:00")).astimezone(timezone.utc) \
        if "+" in str(v) or "Z" in str(v) else datetime.fromisoformat(str(v).replace(" ", "T")).replace(tzinfo=timezone.utc)


def _loc(r: dict) -> tuple[tuple[float, float] | None, bool, str]:
    if r.get("src_lat") is not None and r.get("src_lon") is not None:
        return (float(r["src_lat"]), float(r["src_lon"])), False, r.get("src_country") or f"{r['src_lat']:.1f},{r['src_lon']:.1f}"
    c = r.get("src_country") or ""
    if c in CENTROIDS:
        return CENTROIDS[c], True, c
    return None, True, c or "unknown"


def find_impossible_travel(rows: list[dict], *, max_kmh: float = 900, min_km: float = 500) -> list[dict]:
    """rows: VPN logins with user, event_time, src_ip, src_country, src_lat, src_lon, firewall_id — sorted by user, time."""
    out, prev = [], {}
    for r in rows:
        user = r["user"]
        loc, approx, place = _loc(r)
        cur = {"time": _t(r["event_time"]).isoformat(), "ip": r["src_ip"], "place": place, "loc": loc, "approx": approx,
               "fw": r.get("firewall_id", 0)}
        p = prev.get(user)
        if p and loc and p["loc"] and p["ip"] != cur["ip"]:
            km = haversine_km(p["loc"], loc)
            hours = max((_t(cur["time"]) - _t(p["time"])).total_seconds() / 3600, 1 / 60)
            if km >= min_km and km / hours > max_kmh:
                out.append({"user": user, "km": round(km), "minutes": round(hours * 60, 1), "kmh": round(km / hours),
                            "approximate": p["approx"] or approx,
                            "from": {k: p[k] for k in ("time", "ip", "place", "fw")}, "to": {k: cur[k] for k in ("time", "ip", "place", "fw")}})
        if loc:
            prev[user] = cur
    return out
