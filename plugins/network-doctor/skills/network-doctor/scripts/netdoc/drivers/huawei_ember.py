"""Huawei "Ember" home gateways (VDSL/ADSL/fiber): HG630 V2, HG633, HG658, HG8245/HG8145 ISP builds.

Verified on an HG630 V2 (Telecom Egypt / WE firmware). Responses are JSON wrapped in /* ... */.
Login: sha256(user + base64(sha256hex(pw)) + csrf_param + csrf_token), POST /api/system/user_login.
Writes post {csrf:{csrf_param, csrf_token}, action, data} to the same API path, with a fresh CSRF pair.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..radio import num
from .base import Driver, Fingerprint, LoginBusy, LoginError, LoginRejected, NotSupported


def unwrap(txt: str) -> Any:
    m = re.search(r"/\*(.*)\*/", txt, re.S)
    s = m.group(1) if m else txt
    try:
        return json.loads(s)
    except ValueError:
        return s


def csrf_pair(html: str) -> Tuple[str, str]:
    p = re.search(r'name="csrf_param"\s+content="([^"]+)"', html)
    t = re.search(r'name="csrf_token"\s+content="([^"]+)"', html)
    if not (p and t):
        raise LoginError("no CSRF meta tags on the page")
    return p.group(1), t.group(1)


def login_password(user: str, password: str, csrf_param: str, csrf_token: str) -> str:
    h = hashlib.sha256(password.encode()).hexdigest()
    return hashlib.sha256((user + base64.b64encode(h.encode()).decode() + csrf_param + csrf_token).encode()).hexdigest()


class HuaweiEmber(Driver):
    family = "huawei-ember"
    name = "Huawei home gateway (HG630/HG633/HG658 web UI)"
    vendor = "Huawei"
    tier = "verified"
    models = "HG630 V2 (verified), HG633, HG658 V2, HG531 V1 newer firmware, some HG8245 ISP builds"
    lockout = "locks login for 1 minute after 3 wrong passwords, longer after more"
    can_write = True
    can_revert = True
    write_targets = "'<api path>:<action>' e.g. /api/ntwk/WlanBasic?showpass=false:SendSettings; fields = the data object"

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        b = fp.body
        score = 0
        if 'name="csrf_param"' in b and 'name="csrf_token"' in b:
            score += 50
        if "/api/system/user_login" in b or "exember" in b.lower() or "ember" in b.lower():
            score += 30
        if re.search(r"HG6\d\d|HG8\d{3}|HG5\d\d", b):
            score += 20
        return min(score, 100)

    def _json(self, path: str) -> Any:
        return unwrap(self.s.get(path).text)

    def _login(self, password: str) -> None:
        cp, ct = csrf_pair(self.s.get("/").text)
        body = {"csrf": {"csrf_param": cp, "csrf_token": ct},
                "data": {"UserName": self.user, "Password": login_password(self.user, password, cp, ct)}}
        r = unwrap(self.s.post_json("/api/system/user_login", body, headers={"X-Requested-With": "XMLHttpRequest"}).text)
        if isinstance(r, dict) and r.get("errorCategory") == "ok":
            return
        cat = r.get("errorCategory") if isinstance(r, dict) else str(r)[:80]
        if cat in ("user_pass_err", "Duplicate_user", "Three_time_err", "Five_time_err", "Wrong_password"):
            raise LoginRejected(f"router rejected the login ({cat}; lock count {r.get('count', '?')})")
        if cat in ("Duplicate_login", "too_many_user"):
            raise LoginBusy(f"someone else is logged in to the router web UI ({cat})")
        raise LoginRejected(f"router did not accept the login ({cat})")

    def logout(self) -> None:
        try:
            cp, ct = csrf_pair(self.s.get("/html/advance.html").text)
            self.s.post_json("/api/system/user_logout", {"csrf": {"csrf_param": cp, "csrf_token": ct}})
        except Exception:
            pass
        finally:
            self.logged_in = False

    def _authed(self, path: str) -> Any:
        self.login()
        return self._json(path)

    def info(self) -> Dict[str, Any]:
        d = self._authed("/api/system/deviceinfo")
        if not isinstance(d, dict):
            return {"vendor": "Huawei"}
        return {k: v for k, v in {"vendor": "Huawei", "model": d.get("DeviceName") or d.get("ProductClass"),
                                  "firmware": d.get("SoftwareVersion"), "hardware": d.get("HardwareVersion"),
                                  "uptime_s": d.get("UpTime")}.items() if v not in (None, "")}

    def wan(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        w = self._authed("/api/ntwk/wan?type=active")
        w = w[0] if isinstance(w, list) and w else w
        if isinstance(w, dict):
            out.update({"type": w.get("AccessType") or w.get("ConnectionType"), "connected": w.get("ConnectionStatus") == "Connected",
                        "ip": w.get("IPv4Addr") or w.get("ExternalIPAddress"),
                        "dns": [x for x in str(w.get("IPv4DnsServers") or w.get("DNSServers") or "").split(",") if x],
                        "mtu": w.get("IPv4Mtu") or w.get("MaxMTUSize"), "uptime_s": w.get("Uptime")})
        dsl = self._json("/api/ntwk/dslinfo")
        if isinstance(dsl, dict) and dsl:
            out["dsl"] = {k: dsl.get(k) for k in ("Status", "Modulation", "UpCurrRate", "DownCurrRate", "UpstreamMaxRate",
                                                   "DownstreamMaxRate", "UpstreamNoiseMargin", "DownstreamNoiseMargin",
                                                   "UpstreamAttenuation", "DownstreamAttenuation", "ShowtimeStart",
                                                   "FECErrors", "CRCErrors") if dsl.get(k) not in (None, "")}
        return {k: v for k, v in out.items() if v not in (None, "", [])}

    def wifi(self) -> List[Dict[str, Any]]:
        d = self._authed("/api/ntwk/WlanBasic?showpass=false")
        out = []
        for r in d if isinstance(d, list) else []:
            out.append({k: v for k, v in {
                "radio": r.get("ID"), "band": r.get("FrequencyBand") or ("2.4GHz" if (num(r.get("Channel")) or 1) <= 14 else "5GHz"),
                "ssid": r.get("WifiSsid"), "enabled": bool(r.get("WifiEnable")) and bool(r.get("WifiSsidEnable", True)),
                "channel": r.get("Channel") or "auto", "width": r.get("X_Wlan11NBWControl"),
                "guard_interval": r.get("X_Wlan11NGIControl"), "standard": r.get("WlanStandard"),
                "security": {"11i": "WPA2-PSK", "WPAand11i": "WPA/WPA2-PSK", "WPA": "WPA-PSK", "Basic": "open/WEP"}.get(
                    r.get("BeaconType"), r.get("BeaconType")),
                "encryption": r.get("IEEEiEncryptionMode") if r.get("BeaconType") == "11i" else
                (r.get("MixedEncryptionModes") or r.get("WpaEncryptionMode")),
                "tx_power": r.get("TransmitPower"), "wmm": r.get("WMMEnable"), "max_clients": r.get("X_AssociateDeviceNum"),
            }.items() if v not in (None, "")})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        d = self._authed("/api/system/HostInfo")
        return [{"name": h.get("HostName"), "ip": h.get("IPAddress"), "mac": h.get("MACAddress"),
                 "interface": h.get("Layer2Interface"), "active": h.get("Active"), "rssi": h.get("Rssi"),
                 "rate": h.get("AssociatedDeviceRate")} for h in (d if isinstance(d, list) else [])]

    def raw_get(self, target: str) -> Any:
        return self._authed(self._split(target)[0])

    def _split(self, target: str) -> Tuple[str, Optional[str]]:
        path, _, action = target.partition(":")
        return path, action or None

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        path, _ = self._split(target)
        d = self._authed(path)
        row = d[0] if isinstance(d, list) and d else d
        if not isinstance(row, dict):
            raise NotSupported(f"{path} did not return an object")
        # The write format uses short names (channel, nbw...) that differ from the read names, so a generic
        # backup is only possible when the caller writes read-side names.
        missing = [k for k in flds if k not in row]
        if missing:
            raise NotSupported(f"{path} has no read-back for {missing}; save the full object instead "
                               "(`netdoc.py router get` before writing)")
        return {k: row[k] for k in flds}

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        path, action = self._split(target)
        self.login()
        cp, ct = csrf_pair(self.s.get("/html/advance.html").text)
        body: Dict[str, Any] = {"csrf": {"csrf_param": cp, "csrf_token": ct}, "data": flds}
        if action:
            body["action"] = action
        r = unwrap(self.s.post_json(path, body, headers={"X-Requested-With": "XMLHttpRequest"}).text)
        if isinstance(r, dict) and (r.get("errcode") in (0, "0") or r.get("errorCategory") == "ok"):
            return "OK"
        raise LoginError(f"write to {path} failed: {json.dumps(r)[:160] if isinstance(r, (dict, list)) else str(r)[:160]}")
