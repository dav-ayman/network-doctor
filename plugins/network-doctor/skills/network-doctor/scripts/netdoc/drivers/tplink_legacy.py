"""Older TP-Link routers with the "/userRpm/" web UI (TL-WR840N/841N/940N/1043ND, Archer C20/C50 v1-v3...).

Tier: experimental, read-only. Written from public protocol descriptions; untested on hardware.

Protocol, as publicly described:
- Auth is a cookie  Authorization=Basic <base64("admin:" + md5hex(password))>  (very old firmware sends
  plain HTTP Basic instead). GET /userRpm/LoginRpm.htm?Save=Save returns a page whose script points to
  http://<ip>/<SESSION>/userRpm/Index.htm; later pages live under /<SESSION>/userRpm/ and need a Referer
  from the same session path.
- StatusRpm.htm carries JavaScript arrays: statusPara, lanPara, wlanPara, wanPara.
- AssignedIpAddrListRpm.htm carries DHCPDynList (name, MAC, IP, lease) in groups of 4.
Array positions differ between models, so parsing looks for value shapes (IPs, "Build" strings) instead
of fixed indexes wherever possible.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict, List

from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported

IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def js_array(page: str, name: str) -> List[Any]:
    m = re.search(rf"var\s+{name}\s*=\s*new\s+Array\((.*?)\);", page, re.S)
    if not m:
        return []
    out: List[Any] = []
    for tok in re.findall(r'"((?:[^"\\]|\\.)*)"|(-?\d+)', m.group(1)):
        out.append(tok[0] if tok[1] == "" else int(tok[1]))
    return out


class TPLinkLegacy(Driver):
    family = "tplink-legacy"
    name = "TP-Link legacy web UI (/userRpm/)"
    vendor = "TP-Link"
    tier = "experimental"
    models = "TL-WR740N/741ND/840N/841N/842N/940N/1043ND (v1-v13 era), TL-MR3420, Archer C20/C50 v1-v3, C2 v1"
    lockout = "many models lock the web login for ~2 hours after 10 wrong passwords"
    can_write = False
    can_revert = False

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.prefix = ""  # "/<SESSION>"

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        b = fp.body
        score = 0
        if "userRpm" in b or "LoginRpm" in b:
            score += 60
        www = (fp.root.header("WWW-Authenticate") or "") if fp.root else ""
        if "TP-LINK" in www.upper():
            score += 60
        if re.search(r"tp-?link", b, re.I):
            score += 20
        if "cgi-bin/luci" in b or "cgi_gdpr" in b:
            score -= 40
        return max(0, min(score, 100))

    def _login(self, password: str) -> None:
        tok = base64.b64encode(f"{self.user}:{hashlib.md5(password.encode()).hexdigest()}".encode()).decode()
        self.s.set_cookie("Authorization", f"Basic%20{tok}")
        r = self.s.get("/userRpm/LoginRpm.htm?Save=Save", headers={"Referer": self.base + "/"})
        m = re.search(r"https?://[^/]+/([A-Z]{16})/userRpm/Index\.htm", r.text)
        if m:
            self.prefix = "/" + m.group(1)
            return
        if r.status == 401:
            raise LoginRejected("router rejected the login (HTTP 401)")
        if "userRpm" in r.text and ("Index.htm" in r.text or "MenuRpm" in r.text) and r.status == 200:
            self.prefix = ""  # session-less firmware
            return
        raise LoginRejected("router did not accept the login (no session in the answer); not retrying")

    def logout(self) -> None:
        try:
            if self.logged_in:
                self.page("LogoutRpm.htm")
        except Exception:
            pass
        finally:
            self.logged_in = False

    def page(self, name: str) -> str:
        self.login()
        r = self.s.get(f"{self.prefix}/userRpm/{name}",
                       headers={"Referer": f"{self.base}{self.prefix}/userRpm/MenuRpm.htm"})
        if r.status in (401, 403) or "LoginRpm" in r.text[:2000] and "statusPara" not in r.text:
            raise LoginError("session expired")
        return r.text

    def info(self) -> Dict[str, Any]:
        st = js_array(self.page("StatusRpm.htm"), "statusPara")
        fw = next((x for x in st if isinstance(x, str) and "Build" in x), None)
        hw = next((x for x in st if isinstance(x, str) and re.search(r"\bv\d+\b", x) and x != fw), None)
        return {k: v for k, v in {"vendor": "TP-Link", "model": hw.split(" ")[0] if hw else None,
                                  "firmware": fw, "hardware": hw}.items() if v}

    def wan(self) -> Dict[str, Any]:
        w = js_array(self.page("StatusRpm.htm"), "wanPara")
        ips = [x for x in w if isinstance(x, str) and IP.match(x)]
        dns = next((x for x in w if isinstance(x, str) and "," in x and re.search(r"\d+\.\d+\.\d+\.\d+", x)), "")
        return {k: v for k, v in {"ip": ips[0] if ips else None, "gateway": ips[2] if len(ips) > 2 else None,
                                  "dns": [d.strip() for d in dns.split(",") if d.strip()] or None,
                                  "connected": bool(ips and ips[0] != "0.0.0.0")}.items() if v not in (None, [], "")}

    def wifi(self) -> List[Dict[str, Any]]:
        w = js_array(self.page("StatusRpm.htm"), "wlanPara")
        if not w:
            return []
        ssid = w[1] if len(w) > 1 and isinstance(w[1], str) else None
        return [{k: v for k, v in {"radio": "wlan0", "band": "2.4GHz", "ssid": ssid,
                                   "enabled": w[0] == 1 if isinstance(w[0], int) else None}.items() if v is not None}]

    def clients(self) -> List[Dict[str, Any]]:
        a = js_array(self.page("AssignedIpAddrListRpm.htm"), "DHCPDynList")
        out = []
        for i in range(0, len(a) - 3, 4):
            name, mac, ip = a[i], a[i + 1], a[i + 2]
            if isinstance(ip, str) and IP.match(ip):
                out.append({"name": name, "mac": mac, "ip": ip})
        return out

    def raw_get(self, target: str) -> Any:
        """A userRpm page name, e.g. StatusRpm.htm; returns the JS arrays found on it."""
        if not re.fullmatch(r"[A-Za-z0-9_]+\.htm", target):
            raise NotSupported("target must be a page name like StatusRpm.htm")
        page = self.page(target)
        return {n: js_array(page, n) for n in re.findall(r"var\s+(\w+)\s*=\s*new\s+Array", page)}
