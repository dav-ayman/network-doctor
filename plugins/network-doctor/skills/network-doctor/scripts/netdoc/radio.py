"""Signal-quality labels for cellular (LTE/NR) and Wi-Fi, and number parsing for router strings like "-95dBm"."""
from __future__ import annotations

import re
from typing import Optional

_NUM = re.compile(r"-?\d+(?:\.\d+)?")


def num(v) -> Optional[float]:
    """Parse "-95dBm", "12.5dB", ">=-44dBm", 7, "" into a float (or None)."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    m = _NUM.search(str(v))
    return float(m.group(0)) if m else None


def rsrp_label(v) -> str:
    x = num(v)
    if x is None:
        return ""
    if x >= -80:
        return "excellent"
    if x >= -90:
        return "good"
    if x >= -100:
        return "fair"
    if x >= -110:
        return "poor"
    return "very poor"


def rsrq_label(v) -> str:
    x = num(v)
    if x is None:
        return ""
    if x >= -10:
        return "excellent"
    if x >= -15:
        return "good"
    if x >= -20:
        return "fair"
    return "poor"


def sinr_label(v) -> str:
    x = num(v)
    if x is None:
        return ""
    if x >= 20:
        return "excellent"
    if x >= 13:
        return "good"
    if x >= 5:
        return "fair"
    if x >= 0:
        return "poor"
    return "very poor"


def wifi_rssi_label(v) -> str:
    x = num(v)
    if x is None:
        return ""
    if x >= -55:
        return "excellent"
    if x >= -65:
        return "good"
    if x >= -72:
        return "fair"
    if x >= -80:
        return "poor"
    return "very poor"


def channel_band(ch) -> str:
    c = int(num(ch) or 0)
    if 1 <= c <= 14:
        return "2.4GHz"
    if 32 <= c <= 177:
        return "5GHz"
    return ""


def overlaps_24(a: int, b: int) -> bool:
    """2.4 GHz 20 MHz channels overlap unless they are 5+ apart (1/6/11 plan)."""
    return abs(a - b) < 5
