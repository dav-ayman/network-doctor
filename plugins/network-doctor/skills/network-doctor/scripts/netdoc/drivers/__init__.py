"""Router driver registry. Add a new family by writing a Driver subclass and listing it in DRIVERS."""
from __future__ import annotations

import importlib
from typing import List, Tuple, Type

from .base import Driver, Fingerprint

# module name -> class name. Imported lazily so one broken driver never breaks the others.
_REGISTRY = [
    ("huawei_hilink", "HuaweiHiLink"),
    ("zte_goform", "ZTEGoform"),
    ("zte_zxhn", "ZTEZXHN"),
    ("huawei_ember", "HuaweiEmber"),
    ("openwrt", "OpenWrt"),
    ("mikrotik", "MikroTik"),
    ("fritzbox", "FritzBox"),
    ("asuswrt", "AsusWrt"),
    ("tplink", "TPLinkWeb"),
    ("tplink_mr", "TPLinkMR"),
    ("tplink_legacy", "TPLinkLegacy"),
]


def all_drivers() -> List[Type[Driver]]:
    out = []
    for mod, cls in _REGISTRY:
        try:
            m = importlib.import_module(f"{__name__}.{mod}")
            out.append(getattr(m, cls))
        except (ImportError, AttributeError):
            continue
    return out


def by_family(family: str) -> Type[Driver]:
    for d in all_drivers():
        if d.family == family:
            return d
    raise KeyError(f"unknown driver {family!r}; known: {', '.join(d.family for d in all_drivers())}")


def rank(fp: Fingerprint) -> List[Tuple[int, Type[Driver]]]:
    scored = []
    for d in all_drivers():
        try:
            s = d.detect(fp)
        except Exception:
            s = 0
        if s > 0:
            scored.append((s, d))
    return sorted(scored, key=lambda x: -x[0])
