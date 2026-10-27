"""Optional GeoIP/ASN enrichment from MaxMind GeoLite2 or DB-IP Lite .mmdb files.

Place files in GEOIP_DIR (default /geoip): any *City*.mmdb or *Country*.mmdb, and *ASN*.mmdb.
FortiGate's own srccountry/dstcountry fields are used first; the database fills gaps, ASN and coordinates."""
from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("geo")


class GeoResolver:
    def __init__(self, directory: str | None):
        self.city = self.country = self.asn = None
        self.files: list[str] = []
        self.lookup = lru_cache(maxsize=200_000)(self._lookup)  # per-instance cache (no global reference to self)
        if not directory or not Path(directory).is_dir():
            return
        import maxminddb
        for f in sorted(Path(directory).glob("*.mmdb")):
            name = f.name.lower()
            try:
                reader = maxminddb.open_database(str(f))
            except Exception as e:  # corrupt/partial download
                log.warning("cannot open %s: %s", f, e)
                continue
            if "asn" in name and not self.asn:
                self.asn = reader
            elif "city" in name and not self.city:
                self.city = reader
            elif "country" in name and not self.country:
                self.country = reader
            else:
                continue
            self.files.append(f.name)
        log.info("geoip databases: %s", self.files or "none")

    @property
    def available(self) -> bool:
        return bool(self.city or self.country or self.asn)

    @staticmethod
    def _public(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.is_global

    def _lookup(self, ip: str) -> dict:
        out = {"country": "", "lat": None, "lon": None, "asn": 0, "as_org": ""}
        if not ip or not self._public(ip):
            return out
        db = self.city or self.country
        if db:
            try:
                r = db.get(ip) or {}
                out["country"] = ((r.get("country") or r.get("registered_country") or {}).get("names") or {}).get("en", "")
                loc = r.get("location") or {}
                if "latitude" in loc:
                    out["lat"], out["lon"] = float(loc["latitude"]), float(loc["longitude"])
            except (ValueError, TypeError):
                pass
        if self.asn:
            try:
                r = self.asn.get(ip) or {}
                out["asn"] = int(r.get("autonomous_system_number") or 0)
                out["as_org"] = r.get("autonomous_system_organization") or ""
            except (ValueError, TypeError):
                pass
        return out
