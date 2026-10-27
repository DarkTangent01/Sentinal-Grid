"""Applies GeoIP and threat-intel enrichment to normalized events inside the ingest pipeline."""
from __future__ import annotations

import logging
import time

from sqlalchemy import func, select

from ..config import get_settings
from .geo import GeoResolver
from .ti import IndicatorSet

log = logging.getLogger("enrich")


class Enricher:
    def __init__(self, geo: GeoResolver | None = None, ti: IndicatorSet | None = None):
        self.geo = geo if geo is not None else GeoResolver(get_settings().geoip_dir)
        self.ti = ti or IndicatorSet()
        self._ti_version = None
        self._last_refresh = 0.0
        self.counters = {"ti_hits": 0, "geo_lookups": 0}

    async def refresh_ti(self, force: bool = False) -> None:
        if not force and time.monotonic() - self._last_refresh < 300:
            return
        self._last_refresh = time.monotonic()
        from ..db.models import TiFeed, TiIndicator
        from ..db.pg import session_factory
        async with session_factory()() as s:
            # two independent scalar subqueries (a joined select would be a cartesian product)
            version = (await s.execute(select(select(func.count(TiIndicator.id)).scalar_subquery(),
                                              select(func.max(TiFeed.last_success)).scalar_subquery(),
                                              select(func.count(TiFeed.id)).where(TiFeed.enabled.is_(True)).scalar_subquery()))).one()
            version = tuple(str(x) for x in version)
            if version == self._ti_version and not force:
                return
            rows = (await s.execute(select(TiIndicator.indicator, TiIndicator.type, TiFeed.name, TiFeed.category)
                                    .join(TiFeed, TiFeed.id == TiIndicator.feed_id).where(TiFeed.enabled.is_(True)))).all()
        self.ti = IndicatorSet([tuple(r) for r in rows])
        self._ti_version = version
        log.info("threat intel loaded: %d indicators", len(self.ti))

    def apply(self, ev: dict) -> dict:
        if self.geo.available:
            if ev["dst_ip"]:
                g = self.geo.lookup(ev["dst_ip"])
                ev["dst_country"] = ev["dst_country"] or g["country"]
                ev["dst_asn"], ev["dst_as_org"] = g["asn"], g["as_org"]
            if ev["src_ip"]:
                g = self.geo.lookup(ev["src_ip"])
                ev["src_country"] = ev["src_country"] or g["country"]
                ev["src_lat"], ev["src_lon"] = g["lat"], g["lon"]
            self.counters["geo_lookups"] += 1
        if len(self.ti):
            h = self.ti.match_event(ev)
            if h:
                ev["ti_match"], ev["ti_source"], ev["ti_category"] = h.indicator, h.source, h.category
                self.counters["ti_hits"] += 1
        return ev
