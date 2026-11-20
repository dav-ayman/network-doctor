"""MikroTik RouterOS 7 REST API (hAP, cAP, Chateau LTE/5G, LtAP, wAP LTE, RB/CCR with www or www-ssl enabled).

Tier: experimental. Written from MikroTik's REST API documentation (help.mikrotik.com, "REST API");
covered by fixture tests, not yet confirmed on hardware by a maintainer.

Protocol: HTTP basic auth on every request to /rest/<menu path>; GET lists, PATCH /rest/<path>/<.id>
updates, POST /rest/<path>/<command> runs commands (e.g. interface/lte/monitor with once).
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

from ..radio import num
from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported


class MikroTik(Driver):
    family = "mikrotik"
    name = "MikroTik RouterOS 7 (REST API)"
    vendor = "MikroTik"
    tier = "experimental"
    models = "RouterOS 7.1+ with the www or www-ssl service: hAP ax/ac, Chateau LTE/5G, LtAP, wAP LTE, RB/CCR"
    lockout = "RouterOS does not lock accounts by default; failed logins are logged (watch for firewall rules that ban)"
    can_write = True
    can_revert = True
    write_targets = "'<menu path>/<.id>' e.g. interface/wifi/*1; fields are properties (PATCH)"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self._auth: Optional[str] = None

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        score = 0
        if "RouterOS" in fp.body or "mikrotik" in fp.body.lower() or "RouterOS" in fp.server:
            score += 60
        if "webfig" in fp.body.lower():
            score += 20
        r = fp.get("/rest/system/resource")
        if r is not None and r.status == 401 and "basic" in (r.header("WWW-Authenticate") or "").lower():
            score += 30
        return min(score, 100)

    def _req(self, method: str, path: str, body: Any = None) -> Any:
        h = {"Authorization": self._auth or "", "Content-Type": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        r = self.s.request(method, "/rest/" + path.lstrip("/"), data=data, headers=h)
        if r.status == 401:
            raise LoginRejected("RouterOS rejected the user/password (HTTP 401)")
        if r.status >= 400:
            try:
                msg = r.json().get("detail") or r.json().get("message")
            except ValueError:
                msg = r.text[:120]
            if r.status in (400, 404):
                raise NotSupported(f"{path}: {msg}")
            raise LoginError(f"{path}: HTTP {r.status} {msg}")
        return r.json() if r.body else {}

    def _login(self, password: str) -> None:
        self._auth = "Basic " + base64.b64encode(f"{self.user}:{password}".encode()).decode()
        self._req("GET", "system/resource")

    def logout(self) -> None:
        self._auth = None
        self.logged_in = False

    def get(self, path: str) -> Any:
        self.login()
        return self._req("GET", path)

    def _try(self, path: str) -> Any:
        try:
            return self.get(path)
        except NotSupported:
            return None

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        r = self.get("system/resource")
        rb = self._try("system/routerboard") or {}
        return {k: v for k, v in {"vendor": "MikroTik", "model": rb.get("model") or r.get("board-name"),
                                  "firmware": r.get("version"), "hardware": r.get("architecture-name"),
                                  "uptime": r.get("uptime"), "cpu_load_pct": num(r.get("cpu-load"))}.items() if v not in (None, "")}

    def cellular(self) -> Optional[Dict[str, Any]]:
        lte = self._try("interface/lte")
        if not lte:
            return None
        name = lte[0].get("name", "lte1")
        self.login()
        try:
            m = self._req("POST", "interface/lte/monitor", {"numbers": name, "once": ""})
        except NotSupported:
            return {"connected": lte[0].get("running") == "true"}
        m = m[0] if isinstance(m, list) and m else m
        tech = str(m.get("access-technology", ""))
        gen = "5G" if "NR" in tech or "5G" in tech else ("4G+" if m.get("ca-band") else "4G") if "LTE" in tech \
            else ("3G" if any(x in tech for x in ("WCDMA", "HSPA", "UMTS")) else tech or None)
        out = {"operator": m.get("current-operator"), "connected": lte[0].get("running") == "true",
               "generation": gen, "rsrp": num(m.get("rsrp")), "rsrq": num(m.get("rsrq")), "sinr": num(m.get("sinr")),
               "rssi": num(m.get("rssi")), "band": m.get("primary-band"), "ca_band": m.get("ca-band"),
               "cell_id": None, "pci": m.get("phy-cellid")}
        if m.get("nr-rsrp"):
            out["nr"] = {"rsrp": num(m.get("nr-rsrp")), "rsrq": num(m.get("nr-rsrq")), "sinr": num(m.get("nr-sinr")),
                         "band": m.get("nr-band")}
        return {k: v for k, v in out.items() if v not in (None, "")}

    def wan(self) -> Dict[str, Any]:
        addrs = self._try("ip/address") or []
        dns = self._try("ip/dns") or {}
        dyn = [a for a in addrs if a.get("dynamic") == "true"] or addrs
        return {k: v for k, v in {"ip": dyn[0].get("address") if dyn else None, "interface": dyn[0].get("interface") if dyn else None,
                                  "dns": [x for x in str(dns.get("servers", "") + "," + dns.get("dynamic-servers", "")).split(",") if x]
                                  or None}.items() if v}

    def wifi(self) -> List[Dict[str, Any]]:
        out = []
        for path in ("interface/wifi", "interface/wireless"):
            for w in self._try(path) or []:
                out.append({k: v for k, v in {
                    "radio": w.get("name"), "ssid": w.get("configuration.ssid") or w.get("ssid"),
                    "enabled": w.get("disabled") != "true", "channel": w.get("channel") or w.get("frequency"),
                    "band": w.get("channel.band") or w.get("band"), "width": w.get("channel.width") or w.get("channel-width"),
                    "security": w.get("security.authentication-types") or w.get("security-profile"),
                    "running": w.get("running") == "true"}.items() if v not in (None, "")})
            if out:
                break
        return out

    def clients(self) -> List[Dict[str, Any]]:
        leases = {l.get("mac-address", "").upper(): l for l in (self._try("ip/dhcp-server/lease") or [])}
        out = []
        for path in ("interface/wifi/registration-table", "interface/wireless/registration-table"):
            for c in self._try(path) or []:
                mac = c.get("mac-address", "").upper()
                l = leases.get(mac, {})
                out.append({k: v for k, v in {"name": l.get("host-name"), "ip": l.get("address"), "mac": mac,
                                              "interface": c.get("interface"), "rssi": num(c.get("signal") or c.get("signal-strength")),
                                              "rate": c.get("tx-rate")}.items() if v not in (None, "")})
            if out:
                break
        if not out:
            out = [{k: v for k, v in {"name": l.get("host-name"), "ip": l.get("address"), "mac": m}.items() if v}
                   for m, l in leases.items() if l.get("status") == "bound"]
        return out

    def extras(self) -> Dict[str, Any]:
        q = self._try("queue/tree") or []
        s = self._try("queue/simple") or []
        cake = [x.get("name") for x in q + s if "cake" in str(x.get("queue", "")) or "fq-codel" in str(x.get("queue", ""))]
        return {"queues": len(q) + len(s), "sqm_like_queues": cake or "none (no cake/fq-codel queue found)"}

    # ---- low level ---------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        return self.get(target)

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        item = self.get(target)
        if isinstance(item, list):
            raise NotSupported("target must be a single item: '<menu path>/<.id>'")
        return {k: item.get(k, "") for k in flds}

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        self.login()
        return self._req("PATCH", target, {k: str(v) for k, v in flds.items()}) or "OK"
