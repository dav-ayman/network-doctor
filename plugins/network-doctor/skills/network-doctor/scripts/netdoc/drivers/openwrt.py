"""OpenWrt (and LuCI-based forks such as GL.iNet stock firmware's advanced UI, Turris, ImmortalWrt) via ubus JSON-RPC.

Tier: experimental. Written from the OpenWrt ubus / rpcd / uhttpd-mod-ubus documentation; covered by
fixture tests, not yet confirmed on hardware by a maintainer.

Protocol: POST /ubus with JSON-RPC 2.0 {"method":"call","params":[sid, object, method, args]}.
Login is `session login` with the null sid; the answer carries `ubus_rpc_session`. rpcd ACLs decide what
a user may read; root sees everything. Results are [status, data] where status 0 = OK, 6 = permission denied.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported

NULL_SID = "0" * 32
UBUS_STATUS = {0: "ok", 1: "invalid command", 2: "invalid argument", 3: "method not found", 4: "not found",
               5: "no data", 6: "permission denied", 7: "timeout", 8: "not supported", 9: "unknown error",
               10: "connection failed"}


class OpenWrt(Driver):
    family = "openwrt"
    name = "OpenWrt / LuCI (ubus JSON-RPC)"
    vendor = "OpenWrt"
    tier = "experimental"
    models = "OpenWrt 19.07+ with uhttpd-mod-ubus/rpcd (default in LuCI builds), ImmortalWrt, Turris OS, GL.iNet advanced UI"
    default_user = "root"
    lockout = "rpcd does not lock accounts; failed logins are only logged"
    can_write = True
    can_revert = True
    write_targets = "'config.section' (UCI), e.g. wireless.radio0; fields are UCI options; commits the config"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.sid = NULL_SID
        self._id = 0

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        score = 0
        b = fp.body
        if "LuCI" in b or "luci-static" in b or "OpenWrt" in b:
            score += 60
        if "/cgi-bin/luci" in b:
            score += 20
        r = fp.get("/ubus")
        if r is not None and r.status in (200, 400, 405) and ("jsonrpc" in r.text or r.text.strip() == ""):
            score += 20
        return min(score, 100)

    # ---- transport ---------------------------------------------------------------------------
    def call(self, obj: str, method: str, args: Optional[Dict[str, Any]] = None, sid: Optional[str] = None) -> Any:
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": "call",
               "params": [sid or self.sid, obj, method, args or {}]}
        r = self.s.post_json("/ubus", req)
        try:
            d = r.json()
        except ValueError:
            raise LoginError(f"/ubus answered HTTP {r.status} without JSON (is uhttpd-mod-ubus installed?)")
        if "error" in d:
            code = d["error"].get("code")
            if code == -32002:  # access denied: session expired or ACL
                raise LoginError(f"ubus {obj}.{method}: access denied")
            raise LoginError(f"ubus {obj}.{method}: {d['error'].get('message')}")
        res = d.get("result") or []
        status = res[0] if res else 9
        if status != 0:
            if status == 6:
                raise LoginError(f"ubus {obj}.{method}: permission denied")
            raise NotSupported(f"ubus {obj}.{method}: {UBUS_STATUS.get(status, status)}")
        return res[1] if len(res) > 1 else {}

    def _login(self, password: str) -> None:
        try:
            d = self.call("session", "login", {"username": self.user, "password": password}, sid=NULL_SID)
        except (LoginError, NotSupported) as e:
            # rpcd answers [6] (permission denied) for a wrong user or password.
            raise LoginRejected(f"rpcd rejected the login for {self.user}: {e}")
        sid = d.get("ubus_rpc_session") if isinstance(d, dict) else None
        if not sid:
            raise LoginRejected("rpcd did not return a session")
        self.sid = sid

    def logout(self) -> None:
        try:
            if self.sid != NULL_SID:
                self.call("session", "destroy", {"ubus_rpc_session": self.sid})
        except Exception:
            pass
        finally:
            self.sid = NULL_SID
            self.logged_in = False

    def _c(self, obj: str, method: str, args: Optional[Dict[str, Any]] = None) -> Any:
        self.login()
        return self.call(obj, method, args)

    def _try(self, obj: str, method: str, args: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return self._c(obj, method, args)
        except NotSupported:
            return None

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        b = self._c("system", "board")
        i = self._try("system", "info") or {}
        rel = b.get("release") or {}
        return {k: v for k, v in {"vendor": "OpenWrt", "model": b.get("model") or b.get("board_name"),
                                  "firmware": rel.get("description") or rel.get("version"), "hardware": b.get("system"),
                                  "uptime_s": i.get("uptime"),
                                  "load": [round(x / 65536, 2) for x in i.get("load", [])] or None}.items() if v}

    def wan(self) -> Dict[str, Any]:
        w = self._try("network.interface.wan", "status") or self._try("network.interface.wwan", "status") or {}
        if not w:
            return {}
        ip4 = (w.get("ipv4-address") or [{}])[0].get("address")
        return {k: v for k, v in {"type": w.get("proto"), "connected": w.get("up"), "ip": ip4,
                                  "dns": w.get("dns-server") or None, "uptime_s": w.get("uptime"),
                                  "device": w.get("l3_device") or w.get("device")}.items() if v not in (None, "", [])}

    def _wifi_devices(self) -> List[str]:
        st = self._try("network.wireless", "status") or {}
        devs = []
        for radio in st.values():
            for iface in radio.get("interfaces", []):
                if iface.get("ifname"):
                    devs.append(iface["ifname"])
        return devs

    def wifi(self) -> List[Dict[str, Any]]:
        out = []
        for dev in self._wifi_devices():
            i = self._try("iwinfo", "info", {"device": dev}) or {}
            if not i:
                continue
            enc = i.get("encryption") or {}
            out.append({k: v for k, v in {
                "radio": dev, "ssid": i.get("ssid"), "enabled": True, "channel": i.get("channel"),
                "band": "2.4GHz" if (i.get("frequency") or 0) < 3000 else ("5GHz" if (i.get("frequency") or 0) < 5925 else "6GHz"),
                "width": f"{i['htmode']}" if i.get("htmode") else None, "standard": ",".join(i.get("hwmodes") or []) or None,
                "security": enc.get("description"), "tx_power": i.get("txpower"), "noise_dbm": i.get("noise"),
                "quality": i.get("quality"),
            }.items() if v not in (None, "")})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        hints = self._try("luci-rpc", "getHostHints") or {}
        out = []
        for dev in self._wifi_devices():
            a = self._try("iwinfo", "assoclist", {"device": dev}) or {}
            for c in a.get("results", []):
                mac = c.get("mac", "")
                h = hints.get(mac.upper()) or hints.get(mac.lower()) or {}
                out.append({k: v for k, v in {"name": h.get("name"), "ip": (h.get("ipaddrs") or [None])[0], "mac": mac,
                                              "interface": dev, "rssi": c.get("signal"),
                                              "rate": (c.get("rx") or {}).get("rate")}.items() if v not in (None, "")})
        return out

    def extras(self) -> Dict[str, Any]:
        sqm = self._try("uci", "get", {"config": "sqm"})
        if sqm and sqm.get("values"):
            q = [{k: v.get(k) for k in ("interface", "enabled", "download", "upload", "qdisc", "script")}
                 for v in sqm["values"].values() if v.get(".type") == "queue"]
            return {"sqm": q}
        return {"sqm": "not installed (opkg install luci-app-sqm)"}

    # ---- low level ---------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        """'object method' optionally followed by JSON args, e.g. 'iwinfo info {"device":"wlan0"}'."""
        parts = target.split(" ", 2)
        if len(parts) < 2:
            raise NotSupported("target must be 'object method [json-args]'")
        args = json.loads(parts[2]) if len(parts) > 2 else {}
        return self._c(parts[0], parts[1], args)

    def _section(self, target: str):
        if "." not in target:
            raise NotSupported("UCI target must be 'config.section'")
        return target.split(".", 1)

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        cfg, sec = self._section(target)
        v = self._c("uci", "get", {"config": cfg, "section": sec}).get("values", {})
        return {k: v.get(k, "") for k in flds}  # "" = option not set; revert sets it back to empty

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        cfg, sec = self._section(target)
        self._c("uci", "set", {"config": cfg, "section": sec, "values": {k: str(v) for k, v in flds.items()}})
        self._c("uci", "commit", {"config": cfg})
        return "OK (committed; services reload via procd triggers)"

    def explore(self) -> Dict[str, Any]:
        self.login()
        self._id += 1
        r = self.s.post_json("/ubus", {"jsonrpc": "2.0", "id": self._id, "method": "list", "params": [self.sid, "*"]})
        try:
            objs = r.json().get("result", {})
        except ValueError:
            objs = {}
        return {"objects": {o: sorted(m) for o, m in objs.items()}}
