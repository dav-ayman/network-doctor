"""ASUS routers on ASUSWRT / Asuswrt-Merlin (RT-AX/RT-AC, ROG Rapture, ZenWiFi, TUF, GT).

Tier: experimental. Written from the publicly described behaviour of the ASUSWRT web UI (login.cgi,
appGet.cgi hooks, applyapp.cgi) and the Asuswrt-Merlin wiki; fixture tests only.

Protocol: POST /login.cgi with login_authorization=base64("user:password") -> {"asus_token": ...} which
becomes the asus_token cookie. Reads: POST /appGet.cgi with hook=nvram_get(x);wanlink();get_clientlist()...
Writes: POST /applyapp.cgi with action_mode=apply, rc_service=<service> and nvram key=value pairs.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List

from ..radio import num
from .base import Driver, Fingerprint, LoginBusy, LoginError, LoginRejected, NotSupported

UA = "asusrouter-Android-DUTUtil-1.0.0.3.58-163"  # ASUS only answers its own app UAs on appGet/applyapp
LOGIN_ERRORS = {
    "1": "wrong user or password",
    "2": "another user is logged in",
    "3": "wrong user or password",
    "5": "too many failed logins: locked for a few minutes",
    "7": "too many failed logins: locked",
    "8": "login blocked (captcha or remote-access rule)",
    "9": "wrong user or password (captcha required next)",
    "10": "captcha required",
}


def parse_hooks(text: str) -> Dict[str, Any]:
    """appGet.cgi returns a JS-ish object: {"productid":"RT-AX88U", "wanlink_status": ... }. Be lenient."""
    t = text.strip()
    try:
        return json.loads(t)
    except ValueError:
        pass
    out: Dict[str, Any] = {}
    for k, v in re.findall(r'"([\w\-()]+)"\s*:\s*("(?:[^"\\]|\\.)*"|\[[^\]]*\]|[\w.\-]+)', t):
        try:
            out[k] = json.loads(v)
        except ValueError:
            out[k] = v
    return out


def parse_wanlink(text: str) -> Dict[str, str]:
    """wanlink() returns lines like: function wanlink_status() { return 1;} function wanlink_ipaddr() { return '1.2.3.4';}"""
    return {k: v.strip("'\"") for k, v in re.findall(r"function wanlink_(\w+)\(\)\s*\{\s*return\s*([^;]*);", text)}


class AsusWrt(Driver):
    family = "asuswrt"
    name = "ASUS router (ASUSWRT / Merlin)"
    vendor = "ASUS"
    tier = "experimental"
    models = "RT-AX/RT-AC/RT-BE, ROG Rapture GT-*, ZenWiFi XT/XD/ET, TUF-AX on ASUSWRT 3.0.0.4.38x+ or Asuswrt-Merlin"
    lockout = "locks login for a few minutes after about 5 wrong passwords (error_status 5/7)"
    can_write = True
    can_revert = True
    write_targets = "an rc_service such as restart_wireless; fields are nvram keys (e.g. wl0_chanspec=6)"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.s.headers.update({"User-Agent": UA, "Referer": self.base + "/Main_Login.asp"})

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        b = fp.body
        score = 0
        if "Main_Login.asp" in b or "Main_Login.asp" in (fp.root.header("Location") or "" if fp.root else ""):
            score += 50
        if "ASUS" in b or "asus" in b.lower():
            score += 30
        if "httpd/2.0" in fp.server.lower() or "httpd" == fp.server.lower():
            score += 10
        if "/login.cgi" in b:
            score += 10
        return min(score, 100)

    def _login(self, password: str) -> None:
        auth = base64.b64encode(f"{self.user}:{password}".encode()).decode()
        r = self.s.post("/login.cgi", {"login_authorization": auth})
        try:
            d = r.json()
        except ValueError:
            d = parse_hooks(r.text)
        tok = d.get("asus_token") or self.s.cookie("asus_token")
        if tok:
            self.s.set_cookie("asus_token", tok)
            return
        code = str(d.get("error_status", ""))
        msg = LOGIN_ERRORS.get(code, f"unexpected answer (HTTP {r.status})")
        if code == "2":
            raise LoginBusy(f"router refused login: {msg}")
        raise LoginRejected(f"router refused login: {msg}")

    def logout(self) -> None:
        try:
            self.s.get("/Logout.asp")
        finally:
            self.logged_in = False

    def hooks(self, hook: str) -> Dict[str, Any]:
        self.login()
        r = self.s.post("/appGet.cgi", {"hook": hook})
        if r.status in (401, 403) or "Main_Login.asp" in r.text[:500]:
            raise LoginError("session not accepted for appGet.cgi")
        return parse_hooks(r.text)

    def nvram(self, keys: List[str]) -> Dict[str, Any]:
        return self.hooks(";".join(f"nvram_get({k})" for k in keys))

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        d = self.nvram(["productid", "firmver", "buildno", "extendno", "odmpid"])
        fw = ".".join(x for x in (str(d.get("firmver", "")), str(d.get("buildno", ""))) if x)
        if d.get("extendno"):
            fw += f"_{d['extendno']}"
        return {k: v for k, v in {"vendor": "ASUS", "model": d.get("odmpid") or d.get("productid"), "firmware": fw or None}.items() if v}

    def wan(self) -> Dict[str, Any]:
        self.login()
        r = self.s.post("/appGet.cgi", {"hook": "wanlink()"})
        wl = parse_wanlink(r.text)
        d = self.nvram(["wan0_proto", "wan0_dns"])
        return {k: v for k, v in {"type": d.get("wan0_proto"), "connected": wl.get("status") == "1" if wl else None,
                                  "ip": wl.get("ipaddr"), "dns": str(wl.get("dns") or d.get("wan0_dns") or "").split() or None,
                                  "gateway": wl.get("gateway")}.items() if v not in (None, "", [])}

    def wifi(self) -> List[Dict[str, Any]]:
        keys = []
        for i in (0, 1, 2):
            keys += [f"wl{i}_ssid", f"wl{i}_chanspec", f"wl{i}_bw", f"wl{i}_nmode_x", f"wl{i}_auth_mode_x",
                     f"wl{i}_radio", f"wl{i}_txpower"]
        d = self.nvram(keys)
        out = []
        for i, band in ((0, "2.4GHz"), (1, "5GHz"), (2, "5GHz-2/6GHz")):
            if not d.get(f"wl{i}_ssid") and not d.get(f"wl{i}_chanspec"):
                continue
            bw = {"0": "auto", "1": "20MHz", "2": "40MHz", "3": "80MHz", "5": "160MHz"}.get(str(d.get(f"wl{i}_bw")), d.get(f"wl{i}_bw"))
            out.append({k: v for k, v in {"radio": f"wl{i}", "band": band, "ssid": d.get(f"wl{i}_ssid"),
                                          "enabled": str(d.get(f"wl{i}_radio", "1")) == "1",
                                          "channel": d.get(f"wl{i}_chanspec") or "auto", "width": bw,
                                          "security": d.get(f"wl{i}_auth_mode_x"), "tx_power": d.get(f"wl{i}_txpower")}.items()
                        if v not in (None, "")})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        d = self.hooks("get_clientlist()")
        cl = d.get("get_clientlist") or {}
        out = []
        for mac, c in cl.items() if isinstance(cl, dict) else []:
            if not isinstance(c, dict) or mac == "maclist":
                continue
            out.append({k: v for k, v in {"name": c.get("nickName") or c.get("name"), "ip": c.get("ip"), "mac": mac,
                                          "interface": {"0": "wired", "1": "2.4GHz", "2": "5GHz", "3": "5GHz-2"}.get(str(c.get("isWL")), c.get("isWL")),
                                          "rssi": num(c.get("rssi")), "online": c.get("isOnline") == "1"}.items() if v not in (None, "")})
        return out

    def extras(self) -> Dict[str, Any]:
        d = self.nvram(["qos_enable", "qos_type", "qos_obw", "qos_ibw"])
        if not d:
            return {}
        kind = {"0": "traditional", "1": "adaptive", "2": "bandwidth limiter", "3": "cake (Merlin)"}.get(str(d.get("qos_type")), d.get("qos_type"))
        return {"qos": {"enabled": str(d.get("qos_enable")) == "1", "type": kind,
                        "upload_kbps": d.get("qos_obw"), "download_kbps": d.get("qos_ibw")}}

    # ---- low level ---------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        return self.hooks(target)

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        d = self.nvram(list(flds))
        return {k: d.get(k, "") for k in flds}

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        if not re.fullmatch(r"[a-z0-9_;]+", target):
            raise NotSupported("target must be an rc_service name such as restart_wireless")
        self.login()
        form = {"action_mode": "apply", "rc_service": target}
        form.update({k: str(v) for k, v in flds.items()})
        r = self.s.post("/applyapp.cgi", form)
        d = parse_hooks(r.text)
        if str(d.get("modify")) == "1" or d.get("run_service"):
            return "OK"
        raise LoginError(f"applyapp.cgi answered {r.text[:120]}")
