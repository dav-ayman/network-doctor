"""Huawei HiLink XML API: LTE/5G MiFis, USB modems and CPE routers (E3372, E5577, E5785, B310-B818, 5G CPE Pro/5s).

Verified on a 5G CPE 5s (H153-381) with SCRAM login. The SHA256 ("password_type 4") and base64 logins
follow the long-documented HiLink web UI and are untested here.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import re
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from ..radio import num
from .base import Driver, Fingerprint, LoginBusy, LoginError, LoginRejected, NotSupported

XML_HEAD = '<?xml version="1.0" encoding="UTF-8"?>'

ERRORS = {
    "100002": "not supported by this firmware",
    "100003": "not logged in / no permission",
    "100004": "system busy",
    "108001": "wrong username",
    "108002": "wrong password",
    "108003": "already logged in elsewhere",
    "108005": "too many sessions logged in",
    "108006": "wrong username or password",
    "108007": "too many failed logins: account locked for a while",
    "125001": "token error",
    "125002": "session expired",
    "125003": "session/token mismatch",
}
REJECTED = {"108001", "108002", "108006", "108007"}
BUSY = {"108003", "108005", "100004"}


def fields(xml: str) -> Dict[str, str]:
    """Flat <tag>value</tag> map with entities decoded (the server escapes "/" as "&#x2F;", even in nonces)."""
    return {k: html.unescape(v) for k, v in re.findall(r"<(\w+)>([^<]*)</\1>", xml)}


def items(xml: str, tag: str) -> List[Dict[str, str]]:
    return [fields(m) for m in re.findall(rf"<{tag}>(.*?)</{tag}>", xml, re.S)]


def scram_client_proof(password: str, salt_hex: str, iterations: int, first_nonce: str, server_nonce: str) -> str:
    """Client proof as the HiLink web UI computes it.

    Unlike RFC 5802, the UI swaps HMAC key and message:
      ClientKey = HMAC(key="Client Key", msg=SaltedPassword)
      Signature = HMAC(key=AuthMessage,  msg=StoredKey)
    and AuthMessage = "first,server,server" (no "n=,r=" attributes).
    """
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations), 32)
    ck = hmac.new(b"Client Key", salted, hashlib.sha256).digest()
    sk = hashlib.sha256(ck).digest()
    msg = f"{first_nonce},{server_nonce},{server_nonce}".encode()
    sig = hmac.new(msg, sk, hashlib.sha256).digest()
    return bytes(a ^ b for a, b in zip(ck, sig)).hex()


def sha256_login_password(user: str, password: str, token: str) -> str:
    """password_type 4: base64(sha256hex(user + base64(sha256hex(pw)) + token))."""
    inner = base64.b64encode(hashlib.sha256(password.encode()).hexdigest().encode()).decode()
    return base64.b64encode(hashlib.sha256((user + inner + token).encode()).hexdigest().encode()).decode()


def generation(ex: str, endc: str = "", bands: str = "") -> str:
    n = num(ex)
    v = int(n) if n is not None else -1
    if v == 0:
        return "No service"
    if v in (1011, 111, 112, 1012) or (v < 0 and endc == "1"):
        return "5G"
    if v in (101, 102, 1001, 1002):
        if endc == "1":
            return "5G"
        return "4G+" if "+" in bands else "4G"
    if v in (45, 46, 65):
        return "H+"
    if 41 <= v <= 64:
        return "3G"
    if 1 <= v <= 3:
        return "2G"
    return "unknown" if v < 0 else str(v)


class HuaweiHiLink(Driver):
    family = "huawei-hilink"
    name = "Huawei HiLink (LTE/5G MiFi, modem, CPE)"
    vendor = "Huawei"
    tier = "verified"
    models = "5G CPE 5s/Pro (H153-381, H122-373...), B310/B311/B315/B525/B535/B618/B818, E5577/E5785/E5787, E3372"
    lockout = "locks the admin account after 3 wrong passwords (108007)"
    can_write = True
    can_revert = True
    write_targets = "an API path such as /api/net/net-mode; fields become <request><k>v</k>...</request>"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.token: Optional[str] = None
        self.s.headers["X-Requested-With"] = "XMLHttpRequest"

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        score = 0
        x = fp.text("/api/webserver/SesTokInfo")
        if "<TokInfo>" in x or "<SesInfo>" in x:
            score += 70
        if "/api/" in fp.body and ("csrf_token" in fp.body or "HUAWEI" in fp.body.upper()):
            score += 15
        if "<productfamily>" in fp.text("/api/device/basic_information").lower():
            score += 20
        return min(score, 100)

    # ---- transport ---------------------------------------------------------------------------
    def _send(self, path: str, body: Optional[str] = None) -> str:
        h = {}
        if self.token:
            h["__RequestVerificationToken"] = self.token
        r = self.s.post(path, body, headers=h) if body is not None else self.s.get(path, headers=h)
        for name in ("__RequestVerificationTokenone", "__RequestVerificationToken"):
            t = r.header(name)
            if t:
                self.token = t.split("#")[0]
                break
        return r.text

    def _refresh(self) -> None:
        """Open the page (SessionID cookie) and take a fresh CSRF token (meta tag or SesTokInfo)."""
        page = self._send("/")
        m = re.findall(r'name="csrf_token" content="([^"]+)"', page)
        if m:
            self.token = m[0]
            return
        f = fields(self._send("/api/webserver/SesTokInfo"))
        self.token = f.get("TokInfo")
        ses = f.get("SesInfo", "")
        if "=" in ses:
            k, v = ses.split("=", 1)
            self.s.set_cookie(k, v)

    def api(self, path: str, body: Optional[str] = None) -> str:
        if self.token is None:
            self._refresh()
        x = self._send(path, body)
        code = fields(x).get("code") if "<error>" in x else None
        if code in ("125001", "125002", "125003"):
            self._refresh()
            x = self._send(path, body)
        return x

    def api_fields(self, path: str, need_login: bool = False) -> Dict[str, str]:
        x = self.api(path)
        f = fields(x)
        if "<error>" in x and f.get("code") == "100003" and not self.logged_in and need_login:
            self.login()
            x = self.api(path)
            f = fields(x)
        if "<error>" in x:
            code = f.get("code", "?")
            raise LoginError(f"{path}: error {code} ({ERRORS.get(code, 'unknown')})")
        return f

    # ---- login -------------------------------------------------------------------------------
    def _login(self, password: str) -> None:
        self._refresh()
        st = fields(self.api("/api/user/state-login"))
        if st.get("State") == "0":  # already logged in on this session
            return
        first = os.urandom(32).hex()
        ch_xml = self._send("/api/user/challenge_login",
                            f"{XML_HEAD}<request><username>{escape(self.user)}</username>"
                            f"<firstnonce>{first}</firstnonce><mode>1</mode></request>")
        ch = fields(ch_xml)
        if ch.get("salt") and ch.get("servernonce") and ch.get("iterations"):
            proof = scram_client_proof(password, ch["salt"], int(ch["iterations"]), first, ch["servernonce"])
            r = self._send("/api/user/authentication_login",
                           f"{XML_HEAD}<request><clientproof>{proof}</clientproof>"
                           f"<finalnonce>{ch['servernonce']}</finalnonce></request>")
            if "<serversignature>" in r:
                return
            code = fields(r).get("code", "")
            if code not in BUSY:
                # a proof was sent and not accepted: treat any non-busy answer as a rejection (never retried)
                raise LoginRejected(f"SCRAM login: router answered {code or 'nothing'} "
                                    f"({ERRORS.get(code, 'unexpected answer')})")
            self._raise_for(code, "SCRAM login")
        code = ch.get("code", "")
        if code in BUSY or code in REJECTED:
            self._raise_for(code, "challenge")
        # Older firmware without SCRAM: /api/user/login with password_type 4 (sha256) or 0 (base64).
        ptype = st.get("password_type", "4")
        pw = sha256_login_password(self.user, password, self.token or "") if ptype == "4" \
            else base64.b64encode(password.encode()).decode()
        r = self._send("/api/user/login",
                       f"{XML_HEAD}<request><Username>{escape(self.user)}</Username><Password>{pw}</Password>"
                       f"<password_type>{ptype}</password_type></request>")
        if "<response>OK</response>" in r:
            return
        code = fields(r).get("code", "")
        if code not in BUSY:
            raise LoginRejected(f"login: router answered {code or 'nothing'} ({ERRORS.get(code, 'unexpected answer')})")
        self._raise_for(code, "login")

    @staticmethod
    def _raise_for(code: str, what: str) -> None:
        msg = f"{what}: router answered {code or 'nothing'} ({ERRORS.get(code, 'unexpected answer')})"
        if code in REJECTED:
            raise LoginRejected(msg)
        if code in BUSY:
            raise LoginBusy(msg + "; close the router's web page in your browser or wait a few minutes")
        raise LoginError(msg)

    def logout(self) -> None:
        try:
            self.api("/api/user/logout", f"{XML_HEAD}<request><Logout>1</Logout></request>")
        finally:
            self.logged_in = False

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"vendor": "Huawei"}
        b = fields(self.api("/api/device/basic_information"))
        out["model"] = b.get("devicename") or b.get("DeviceName") or b.get("productfamily")
        out["firmware"] = b.get("SoftwareVersion") or b.get("WebUIVersion")
        try:
            d = self.api_fields("/api/device/information", need_login=True)
            out.update({"model": d.get("DeviceName") or out["model"], "firmware": d.get("SoftwareVersion"),
                        "hardware": d.get("HardwareVersion"), "uptime_s": int(num(d.get("uptime")) or 0) or None})
        except LoginError:
            pass
        return {k: v for k, v in out.items() if v not in (None, "")}

    def cellular(self) -> Optional[Dict[str, Any]]:
        st = fields(self.api("/api/monitoring/status"))
        if "CurrentNetworkTypeEx" not in st and "SignalIcon" not in st and "CurrentNetworkType" not in st:
            return None
        plmn = fields(self.api("/api/net/current-plmn"))
        endc = st.get("EndcStatus", "")
        out: Dict[str, Any] = {
            "operator": plmn.get("FullName") or plmn.get("ShortName"),
            "connected": st.get("ConnectionStatus") == "901",
            "bars": int(num(st.get("SignalIconNr") if endc == "1" and st.get("SignalIconNr") else st.get("SignalIcon")) or 0),
            "max_bars": int(num(st.get("maxsignal")) or 5),
            "network_type_code": st.get("CurrentNetworkTypeEx") or st.get("CurrentNetworkType"),
            "router_flags_poor_signal": st.get("poorSignalStatus") == "1" or None,
        }
        if endc == "1":
            out["mode"] = "NSA: LTE anchor + 5G NR"
        try:
            sig = self.api_fields("/api/device/signal", need_login=True)
            band = sig.get("band", "")
            out.update({"rsrp": num(sig.get("rsrp")), "rsrq": num(sig.get("rsrq")), "sinr": num(sig.get("sinr")),
                        "rssi": num(sig.get("rssi")), "band": band or None, "cell_id": None,
                        "pci": sig.get("pci") or None})
            if sig.get("nrrsrp"):
                out["nr"] = {"rsrp": num(sig.get("nrrsrp")), "rsrq": num(sig.get("nrrsrq")),
                             "sinr": num(sig.get("nrsinr")), "band": sig.get("nrband") or None}
            out["generation"] = generation(st.get("CurrentNetworkTypeEx", ""), endc, band)
        except LoginError as e:
            out["generation"] = generation(st.get("CurrentNetworkTypeEx", ""), endc)
            out["details_error"] = str(e)
        m = fields(self.api("/api/monitoring/month_statistics"))
        if m.get("CurrentMonthDownload"):
            out["month_rx"] = int(num(m["CurrentMonthDownload"]) or 0)
            out["month_tx"] = int(num(m.get("CurrentMonthUpload")) or 0)
        return {k: v for k, v in out.items() if v is not None}

    def wan(self) -> Dict[str, Any]:
        st = fields(self.api("/api/monitoring/status"))
        tr = fields(self.api("/api/monitoring/traffic-statistics"))
        out = {"type": "cellular", "connected": st.get("ConnectionStatus") == "901",
               "ip": st.get("WanIPAddress") or None, "dns": [d for d in (st.get("PrimaryDns"), st.get("SecondaryDns")) if d],
               "now_down_bps": int(num(tr.get("CurrentDownloadRate")) or 0) * 8,
               "now_up_bps": int(num(tr.get("CurrentUploadRate")) or 0) * 8,
               "uptime_s": int(num(tr.get("CurrentConnectTime")) or 0) or None}
        return {k: v for k, v in out.items() if v not in (None, [], "")}

    def wifi(self) -> List[Dict[str, Any]]:
        radios: List[Dict[str, Any]] = []
        x = self.api("/api/wlan/multi-basic-settings")
        if "<error>" in x and fields(x).get("code") == "100003":
            self.login()
            x = self.api("/api/wlan/multi-basic-settings")
        for s in items(x, "Ssid"):
            radios.append({"radio": s.get("Index") or s.get("ID"), "ssid": s.get("WifiSsid"),
                           "enabled": s.get("WifiEnable") == "1", "security": s.get("WifiAuthmode"),
                           "encryption": s.get("WifiWpaencryptionmodes"), "hidden": s.get("WifiBroadcast") == "1" or None})
        b = fields(self.api("/api/wlan/basic-settings"))
        if b.get("WifiChannel") or b.get("WifiMode"):
            radios.append({"radio": "main", "ssid": b.get("WifiSsid"), "channel": b.get("WifiChannel"),
                           "standard": b.get("WifiMode"), "enabled": b.get("WifiEnable") == "1"})
        return [{k: v for k, v in r.items() if v not in (None, "")} for r in radios]

    def clients(self) -> List[Dict[str, Any]]:
        for path in ("/api/wlan/host-list", "/api/lan/HostInfo"):
            x = self.api(path)
            if "<error>" in x and fields(x).get("code") == "100003":
                self.login()
                x = self.api(path)
            hosts = items(x, "Host")
            if hosts:
                return [{"name": h.get("HostName") or h.get("ActualName"), "ip": h.get("IpAddress") or h.get("IPAddress"),
                         "mac": h.get("MacAddress"), "interface": h.get("InterfaceType") or h.get("AssociatedSsid")}
                        for h in hosts]
        return []

    def extras(self) -> Dict[str, Any]:
        out = {}
        nm = self.api("/api/net/net-mode")
        if "<error>" not in nm:
            f = fields(nm)
            out["net_mode"] = {"NetworkMode": f.get("NetworkMode"), "NetworkBand": f.get("NetworkBand"),
                               "LTEBand": f.get("LTEBand")}
        return out

    # ---- low level ---------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        x = self.api(target)
        if "<error>" in x and fields(x).get("code") == "100003":
            self.login()
            x = self.api(target)
        return re.sub(r"<\?xml[^>]*>|\r?\n\s*", "", x)

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        f = fields(self.raw_get(target))
        missing = [k for k in flds if k not in f]
        if missing:
            raise NotSupported(f"{target} does not return {missing}; cannot back them up")
        return {k: f[k] for k in flds}

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        self.login()
        body = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in flds.items())
        r = self.api(target, f"{XML_HEAD}<request>{body}</request>")
        if "<response>OK</response>" in r:
            return "OK"
        code = fields(r).get("code", "?")
        raise LoginError(f"write to {target} failed: {code} ({ERRORS.get(code, 'unexpected answer')})")
