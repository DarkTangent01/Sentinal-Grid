"""Channel ↔ frequency conversion for 802.11 radios (vendor-neutral).

Each band has its own channel table; there is no single formula:

  2.4 GHz  channels 1-13: 2407 + 5·ch MHz;  channel 14 (Japan, 802.11b only): 2484 MHz
  5 GHz    channels 32-177: 5000 + 5·ch MHz; channels 183-196 (Japan 4.9 GHz): 4000 + 5·ch MHz
  6 GHz    channels 1-233 (ch ≡ 1 mod 4): 5950 + 5·ch MHz;  channel 2: 5935 MHz

Bonded channels (40/80/160 MHz) occupy a fixed block; the *center* frequency is the block's center channel, not the
primary channel the controller reports. 5 GHz blocks follow the IEEE 802.11 channelisation tables below; 6 GHz blocks
are aligned from channel 1. A 2.4 GHz 40 MHz channel's center depends on whether the secondary channel is above or below,
which the controller does not report here, so it is left unknown. 80+80 MHz has two segments and no single center.

DFS: 5 GHz channels 52-64 (U-NII-2A) and 100-144 (U-NII-2C) require radar detection in the major regulatory domains
(FCC, ETSI, MIC). Local rules vary (e.g. channel 144 is not permitted everywhere); the radio's country code is shown with
the flag. A bonded channel whose block touches a DFS channel is a DFS channel.
"""
from __future__ import annotations

CH_24 = tuple(range(1, 15))
CH_5 = (32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165,
        169, 173, 177, 183, 184, 185, 187, 188, 189, 192, 196)
CH_6 = tuple([2] + list(range(1, 234, 4)))
# 5 GHz bonded blocks: (first, last) 20 MHz channels → center channel
BLOCKS_5 = {
    40: [(36, 40, 38), (44, 48, 46), (52, 56, 54), (60, 64, 62), (100, 104, 102), (108, 112, 110), (116, 120, 118), (124, 128, 126),
         (132, 136, 134), (140, 144, 142), (149, 153, 151), (157, 161, 159), (165, 169, 167), (173, 177, 175)],
    80: [(36, 48, 42), (52, 64, 58), (100, 112, 106), (116, 128, 122), (132, 144, 138), (149, 161, 155), (165, 177, 171)],
    160: [(36, 64, 50), (100, 128, 114), (149, 177, 163)],
}
DFS_5 = set(range(52, 65, 4)) | set(range(100, 145, 4))


def normalize_band(band: str | None) -> str:
    b = (band or "").strip().lower().replace("ghz", "").strip()
    return {"2.4": "2.4", "2": "2.4", "24": "2.4", "5": "5", "6": "6", "5/6": "5/6"}.get(b, "")


def valid_channel(band: str, ch: int | None) -> bool:
    if ch is None:
        return False
    b = normalize_band(band)
    return ch in {"2.4": CH_24, "5": CH_5, "6": CH_6}.get(b, ())


def channel_freq(band: str, ch: int | None) -> int | None:
    """Center frequency (MHz) of the 20 MHz channel `ch` in `band`; None when the channel is not valid for the band."""
    b = normalize_band(band)
    if not valid_channel(b, ch):
        return None
    if b == "2.4":
        return 2484 if ch == 14 else 2407 + 5 * ch
    if b == "5":
        return 4000 + 5 * ch if ch >= 183 else 5000 + 5 * ch
    if b == "6":
        return 5935 if ch == 2 else 5950 + 5 * ch
    return None


def center_channel(band: str, ch: int | None, width: int | None) -> int | None:
    """Center channel of the block that contains primary channel `ch` at `width` MHz; None when it cannot be determined."""
    b = normalize_band(band)
    if not valid_channel(b, ch):
        return None
    if not width or width <= 20:
        return ch
    if b == "5":
        for lo, hi, c in BLOCKS_5.get(width, []):
            if lo <= ch <= hi:
                return c
        return None
    if b == "6" and ch != 2 and width in (40, 80, 160, 320):
        span = 4 * (width // 20)
        start = ((ch - 1) // span) * span + 1
        return start + 2 * (width // 20 - 1)
    return None                       # 2.4 GHz bonding direction unknown; 80+80 has two segments


def center_freq(band: str, ch: int | None, width: int | None) -> int | None:
    c = center_channel(band, ch, width)
    if c is None:
        return None
    b = normalize_band(band)
    if b == "5":
        return 4000 + 5 * c if c >= 183 else 5000 + 5 * c
    if b == "6":
        return 5950 + 5 * c
    return channel_freq(b, c)


def span_mhz(band: str, ch: int | None, width: int | None) -> tuple[int, int] | None:
    """(low, high) MHz occupied by the radio's channel; None when the center is unknown."""
    f = center_freq(band, ch, width or 20)
    if f is None:
        return None
    w = width or 20
    if normalize_band(band) == "2.4" and w == 20:
        w = 22                        # 2.4 GHz DSSS/OFDM masks spread ~22 MHz: adjacent channels 1-4 apart overlap
    return f - w // 2, f + w // 2


def is_dfs(band: str, ch: int | None, width: int | None = None) -> bool | None:
    b = normalize_band(band)
    if not valid_channel(b, ch):
        return None
    if b != "5":
        return False
    if ch in DFS_5:
        return True
    if width and width > 20:
        for lo, hi, _ in BLOCKS_5.get(width, []):
            if lo <= ch <= hi:
                return any(lo <= x <= hi for x in DFS_5)
    return False


def overlap_mhz(a: tuple[int, int] | None, b: tuple[int, int] | None) -> int:
    if not a or not b:
        return 0
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def describe(band: str, ch: int | None, width: int | None) -> dict:
    """Everything the UI and analytics need about one radio's channel; unknown parts stay None (never guessed)."""
    b = normalize_band(band)
    ok = valid_channel(b, ch)
    return {"band": b, "channel": ch, "width_mhz": width, "channel_valid": ok if ch is not None else None,
            "frequency_mhz": channel_freq(b, ch), "center_channel": center_channel(b, ch, width),
            "center_frequency_mhz": center_freq(b, ch, width), "dfs": is_dfs(b, ch, width)}
