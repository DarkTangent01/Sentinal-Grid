"""Standard-MIB health for devices that are not network gear: UPS (UPS-MIB, RFC 1628) and printers (Printer-MIB,
RFC 3805 + HOST-RESOURCES hrPrinterTable). Read-only GET / GETBULK like every collector; a value the device does not
return is reported as unsupported (missing), never 0.

Groups (registry.GROUPS): "ups" and "printer", run only for devices classified as that type (detected or set by the
administrator) unless a monitoring template enables them.
"""
from __future__ import annotations

from .collect import Ctx, _cols, num, text

UPS = "1.3.6.1.2.1.33.1"
UPS_BATTERY_STATUS = {1: "unknown", 2: "normal", 3: "low", 4: "depleted"}
UPS_OUTPUT_SOURCE = {1: "other", 2: "none", 3: "normal", 4: "bypass", 5: "battery", 6: "booster", 7: "reducer"}
PRT_SUPPLIES = "1.3.6.1.2.1.43.11.1.1"       # prtMarkerSuppliesTable
PRT_LIFE = "1.3.6.1.2.1.43.10.2.1.4"          # prtMarkerLifeCount (pages / impressions)
HR_PRINTER = "1.3.6.1.2.1.25.3.5.1"           # hrPrinterStatus (.1), hrPrinterDetectedErrorState (.2)
PRINTER_STATUS = {1: "other", 2: "unknown", 3: "idle", 4: "printing", 5: "warmup"}
# hrPrinterDetectedErrorState bits (first octet, most significant bit first)
PRINTER_ERRORS = ["low paper", "no paper", "low toner", "no toner", "door open", "jammed", "offline", "service requested"]


async def collect_ups(ctx: Ctx) -> dict:
    o = ctx.outcome
    r = await ctx.client.get([f"{UPS}.1.1.0", f"{UPS}.1.2.0", f"{UPS}.2.1.0", f"{UPS}.2.2.0", f"{UPS}.2.3.0", f"{UPS}.2.4.0", f"{UPS}.2.7.0",
                              f"{UPS}.4.1.0", f"{UPS}.6.1.0"])
    g = lambda k: r.get(f"{UPS}.{k}")  # noqa: E731
    status, charge, minutes = num(g("2.1.0")), num(g("2.4.0")), num(g("2.3.0"))
    if status is None and charge is None and minutes is None:
        for k in ("device_ups_battery_charge_percent", "device_ups_runtime_minutes", "device_ups_load_percent", "device_ups_on_battery"):
            o.missing(k)
        return {"ups": None}
    out_rows = await _cols(ctx, f"{UPS}.4.4.1", {"voltage": 2, "load": 5})
    in_rows = await _cols(ctx, f"{UPS}.3.3.1", {"voltage": 3})
    loads = [num(x.get("load")) for x in out_rows.values() if num(x.get("load")) is not None]
    source = UPS_OUTPUT_SOURCE.get(num(g("4.1.0")) or 0, "")
    (o.ok if charge is not None else o.missing)("device_ups_battery_charge_percent")
    (o.ok if minutes is not None else o.missing)("device_ups_runtime_minutes")
    (o.ok if loads else o.missing)("device_ups_load_percent")
    (o.ok if source else o.missing)("device_ups_on_battery")
    return {"ups": {
        "manufacturer": text(g("1.1.0")), "model": text(g("1.2.0")),
        "battery_status": UPS_BATTERY_STATUS.get(status or 0, "unknown") if status is not None else None,
        "seconds_on_battery": num(g("2.2.0")), "runtime_minutes": minutes, "charge_pct": charge,
        "battery_celsius": num(g("2.7.0")), "output_source": source or None, "on_battery": source == "battery" if source else None,
        "load_pct": max(loads) if loads else None, "alarms": num(g("6.1.0")),
        "output_voltage": [num(x.get("voltage")) for x in out_rows.values()], "input_voltage": [num(x.get("voltage")) for x in in_rows.values()],
    }}


def _printer_errors(v) -> list[str]:
    b = v[0] if isinstance(v, bytes) and v else 0
    return [n for i, n in enumerate(PRINTER_ERRORS) if b & (0x80 >> i)]


async def collect_printer(ctx: Ctx) -> dict:
    o = ctx.outcome
    sup = await _cols(ctx, PRT_SUPPLIES, {"descr": 6, "unit": 7, "max": 8, "level": 9})
    hr = await _cols(ctx, HR_PRINTER, {"status": 1, "errors": 2})
    life = await _cols(ctx, PRT_LIFE.rsplit(".", 1)[0], {"count": 4})
    supplies = []
    for idx, x in sorted(sup.items()):
        mx, lv = num(x.get("max")), num(x.get("level"))
        # level -1 other, -2 unknown, -3 "some remaining"; max -1/-2 likewise: no percentage then
        pct = round(100.0 * lv / mx, 1) if mx and mx > 0 and lv is not None and lv >= 0 else None
        supplies.append({"id": idx, "name": text(x.get("descr")) or f"supply {idx}", "pct": pct,
                         "state": "some remaining" if lv == -3 else "unknown" if pct is None else None})
    (o.ok if supplies else o.missing)("device_printer_supply_percent", len(supplies) or 1)
    first = next(iter(hr.values()), {})
    st = num(first.get("status"))
    (o.ok if st is not None else o.missing)("device_printer_status")
    pages = [num(x.get("count")) for x in life.values() if num(x.get("count")) is not None]
    if not supplies and st is None:
        return {"printer": None}
    return {"printer": {"status": PRINTER_STATUS.get(st or 0) if st is not None else None, "errors": _printer_errors(first.get("errors")),
                        "supplies": supplies, "page_count": max(pages) if pages else None}}
