"""Identify the router behind the gateway IP using unauthenticated, read-only GETs, and capture its API
surface (masked) so new drivers can be written without the hardware."""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from . import drivers
from .drivers.base import STATE_DIR, Driver, Fingerprint
from .web import first_reachable
from .mask import mask


def fingerprint(host: str) -> Fingerprint:
    base, root = first_reachable(host)
    return Fingerprint(host, base, root)


def page_title(body: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>([^<]{0,120})</title>", body, re.I)
    return m.group(1).strip() if m else None


def identify(host: str) -> Dict[str, Any]:
    fp = fingerprint(host)
    if not fp.base:
        return {"host": host, "reachable": False,
                "hint": "no web UI on http/https; is this really the router? (VPN, bridge mode or a mesh node?)"}
    ranked = drivers.rank(fp)
    return {
        "host": host, "reachable": True, "base_url": fp.base, "http_status": fp.root.status if fp.root else None,
        "server": fp.server or None, "title": page_title(fp.body),
        "candidates": [{"driver": d.family, "name": d.name, "tier": d.tier, "score": s} for s, d in ranked],
        "best": ranked[0][1].family if ranked and ranked[0][0] >= 50 else None,
    }


def pick_driver(host: str, family: Optional[str] = None) -> Driver:
    fp = fingerprint(host)
    if not fp.base:
        raise RuntimeError(f"{host} has no reachable web UI")
    if family:
        return drivers.by_family(family)(fp.base)
    ranked = drivers.rank(fp)
    if not ranked or ranked[0][0] < 50:
        raise RuntimeError(
            f"no driver recognises {host} (title {page_title(fp.body)!r}). Run `netdoc.py capture` and open an "
            "'Add my router' issue, or pass --driver if you know the family.")
    return ranked[0][1](fp.base)


def surface(fp: Fingerprint, max_js: int = 25) -> Dict[str, Any]:
    """API-looking paths referenced by the login page and its scripts. Paths only, never script contents."""
    body = fp.body
    scripts = sorted(set(re.findall(r"""<script[^>]+src=["']([^"'?#]+)""", body)))[:max_js]
    paths = set(re.findall(r"""["'](/(?:api|cgi-bin|goform|cgi|rest|ubus|webpages|userRpm|getpage|data)[A-Za-z0-9_./?=&-]*)""", body))
    for js in scripts:
        t = fp.text(js if js.startswith(("/", "http")) else "/" + js)
        paths |= set(re.findall(r"""["'](/(?:api|cgi-bin|goform|cgi|rest|ubus|webpages|userRpm|getpage|data)[A-Za-z0-9_./?=&-]*)""", t))
        paths |= {f"_tag={x}" for x in re.findall(r"_tag=([A-Za-z0-9_.]+)", t)}
    hdr = {k: v for k, v in (fp.root.headers.items() if fp.root else []) if k.lower() in ("server", "www-authenticate", "x-frame-options", "content-type")}
    return {"title": page_title(body), "headers": hdr, "scripts": scripts, "api_paths": sorted(paths)[:400],
            "meta": sorted(set(re.findall(r'<meta name="([A-Za-z_-]+)"', body)))}


def capture(host: str, family: Optional[str] = None, targets: Optional[List[str]] = None,
            login: bool = False) -> Dict[str, Any]:
    """Masked snapshot for a bug report / new-driver issue. Logs in only if login=True and a driver matches."""
    fp = fingerprint(host)
    out: Dict[str, Any] = {"netdoc_capture": 1, "time": time.strftime("%Y-%m-%d"), "identify": identify(host)}
    if fp.base:
        out["surface"] = surface(fp)
    best = family or out["identify"].get("best")
    if best and login:
        d = drivers.by_family(best)(fp.base)
        with d:
            out["status"] = d.status()
            for t in targets or []:
                try:
                    out.setdefault("raw", {})[t] = d.raw_get(t)
                except Exception as e:
                    out.setdefault("raw", {})[t] = f"error: {e}"
    out = mask(out, identifiers=True)
    os.makedirs(os.path.join(STATE_DIR, "captures"), exist_ok=True)
    path = os.path.join(STATE_DIR, "captures", f"{best or 'unknown'}-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    out["saved_to"] = path
    return out
