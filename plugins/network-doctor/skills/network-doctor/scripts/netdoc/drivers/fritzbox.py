"""AVM FRITZ!Box via TR-064 (SOAP on port 49000; AVM publishes the service descriptions).

Tier: experimental. Written from AVM's public TR-064 documentation ("AVM TR-064 first steps", service
SCPDs) and the Broadband Forum TR-064 spec; covered by fixture tests, not yet confirmed on hardware.

Protocol: POST http://<box>:49000<controlURL> with SOAPAction "urn:dslforum-org:service:<Service>:<n>#<Action>".
Most actions need HTTP Digest auth (MD5, qop=auth) with a FRITZ!Box user (Home Network > Users, "access
from home network" + "FRITZ!Box settings"). TR-064 must be allowed (Home Network > Network > Network
Settings > "Allow access for applications").
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from ..web import Session
from ..radio import num
from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported

# service type -> control URL (AVM's fixed paths; also listed in tr64desc.xml)
CONTROL = {
    "DeviceInfo:1": "/upnp/control/deviceinfo",
    "WANCommonInterfaceConfig:1": "/upnp/control/wancommonifconfig1",
    "WANIPConnection:1": "/upnp/control/wanipconnection1",
    "WANPPPConnection:1": "/upnp/control/wanpppconn1",
    "WANDSLInterfaceConfig:1": "/upnp/control/wandslifconfig1",
    "WLANConfiguration:1": "/upnp/control/wlanconfig1",
    "WLANConfiguration:2": "/upnp/control/wlanconfig2",
    "WLANConfiguration:3": "/upnp/control/wlanconfig3",
    "Hosts:1": "/upnp/control/hosts",
}
NS = {"WANCommonInterfaceConfig:1": "urn:dslforum-org:service:WANCommonInterfaceConfig:1"}


def parse_challenge(h: str) -> Dict[str, str]:
    return dict(re.findall(r'(\w+)="?([^",]*)"?', h.replace("Digest ", "", 1)))


def digest_header(user: str, password: str, method: str, uri: str, ch: Dict[str, str], nc: int, cnonce: str) -> str:
    """RFC 2617 Digest, MD5, qop=auth (what the FRITZ!Box offers)."""
    realm, nonce = ch.get("realm", ""), ch.get("nonce", "")
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    ncs = f"{nc:08x}"
    if "auth" in ch.get("qop", ""):
        resp = hashlib.md5(f"{ha1}:{nonce}:{ncs}:{cnonce}:auth:{ha2}".encode()).hexdigest()
        return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", algorithm=MD5, '
                f'response="{resp}", qop=auth, nc={ncs}, cnonce="{cnonce}"')
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}"'


def soap_body(service: str, action: str, args: Dict[str, Any]) -> str:
    st = f"urn:dslforum-org:service:{service}"
    inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items())
    return ('<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{st}">{inner}</u:{action}></s:Body></s:Envelope>')


def soap_fields(xml: str) -> Dict[str, str]:
    m = re.search(r"<s:Body>(.*)</s:Body>", xml, re.S)
    body = m.group(1) if m else xml
    return dict(re.findall(r"<(New\w+)>([^<]*)</\1>", body))


class FritzBox(Driver):
    family = "fritzbox"
    name = "AVM FRITZ!Box (TR-064)"
    vendor = "AVM"
    tier = "experimental"
    models = "FRITZ!Box DSL/cable/fiber/LTE models with FRITZ!OS 6.x-8.x and TR-064 enabled (7590, 7530, 7490, 6690...)"
    default_user = ""  # FRITZ!OS may use password-only login; then pass --user with the auto-generated name
    lockout = "FRITZ!OS delays further logins progressively (doubling wait) after failures"
    can_write = True
    can_revert = False
    write_targets = "'Service:Action' with JSON-like key=value args, e.g. WLANConfiguration:1:SetChannel NewChannel=6"

    def __init__(self, base: str, *a: Any, **kw: Any):
        super().__init__(base, *a, **kw)
        host = urlsplit(base).hostname or base
        self.tr = Session(f"http://{host}:49000", timeout=self.s.timeout)
        self._pw: Optional[str] = None
        self._ch: Optional[Dict[str, str]] = None
        self._nc = 0

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        score = 60 if "FRITZ!Box" in fp.body or "fritz.box" in fp.body.lower() else 0
        d = fp.text(f"http://{fp.host}:49000/tr64desc.xml")
        if "AVM" in d or "FRITZ" in d:
            score += 40
        return min(score, 100)

    def soap(self, service: str, action: str, args: Optional[Dict[str, Any]] = None, auth: bool = True) -> Dict[str, str]:
        url = CONTROL.get(service)
        if not url:
            raise NotSupported(f"unknown TR-064 service {service}")
        body = soap_body(service, action, args or {})
        hdr = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f"urn:dslforum-org:service:{service}#{action}"}
        for _ in range(3):
            h = dict(hdr)
            sent_auth = False
            if auth and self._ch and self._pw is not None:
                self._nc += 1
                h["Authorization"] = digest_header(self.user, self._pw, "POST", url, self._ch, self._nc, os.urandom(8).hex())
                sent_auth = True
            r = self.tr.post(url, body, headers=h)
            if r.status == 401:
                www = r.header("WWW-Authenticate") or ""
                if not auth or self._pw is None:
                    raise LoginError(f"{service}#{action} needs a login")
                if not sent_auth or "stale=true" in www.lower():
                    # we only learned (or refreshed) the nonce; the password itself was not rejected
                    self._ch, self._nc = parse_challenge(www), 0
                    continue
                raise LoginRejected("FRITZ!Box rejected the user/password (HTTP 401 after digest auth)")
            if r.status == 500:
                err = re.search(r"<errorDescription>([^<]*)", r.text)
                raise NotSupported(f"{service}#{action}: {err.group(1) if err else 'SOAP fault'}")
            if r.status >= 400:
                raise LoginError(f"{service}#{action}: HTTP {r.status}")
            return soap_fields(r.text)
        raise LoginRejected("FRITZ!Box kept asking for credentials")

    def _login(self, password: str) -> None:
        self._pw = password
        self._ch = None
        self.soap("DeviceInfo:1", "GetInfo")

    def logout(self) -> None:
        self._pw = None
        self._ch = None
        self.logged_in = False

    def _s(self, service: str, action: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        self.login()
        return self.soap(service, action, args)

    def _try(self, service: str, action: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        try:
            return self._s(service, action, args)
        except NotSupported:
            return {}

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        d = self._s("DeviceInfo:1", "GetInfo")
        return {k: v for k, v in {"vendor": "AVM", "model": d.get("NewModelName"), "firmware": d.get("NewSoftwareVersion"),
                                  "hardware": d.get("NewHardwareVersion"),
                                  "uptime_s": int(num(d.get("NewUpTime")) or 0) or None}.items() if v}

    def wan(self) -> Dict[str, Any]:
        link = self._try("WANCommonInterfaceConfig:1", "GetCommonLinkProperties")
        ip = self._try("WANIPConnection:1", "GetExternalIPAddress") or self._try("WANPPPConnection:1", "GetExternalIPAddress")
        st = self._try("WANIPConnection:1", "GetStatusInfo") or self._try("WANPPPConnection:1", "GetStatusInfo")
        out: Dict[str, Any] = {
            "type": link.get("NewWANAccessType"), "connected": (st.get("NewConnectionStatus") == "Connected") if st else None,
            "ip": ip.get("NewExternalIPAddress"), "uptime_s": int(num(st.get("NewUptime")) or 0) or None,
            "max_down_bps": int(num(link.get("NewLayer1DownstreamMaxBitRate")) or 0) or None,
            "max_up_bps": int(num(link.get("NewLayer1UpstreamMaxBitRate")) or 0) or None,
        }
        dsl = self._try("WANDSLInterfaceConfig:1", "GetInfo")
        if dsl:
            out["dsl"] = {k.replace("New", ""): dsl[k] for k in (
                "NewStatus", "NewUpstreamCurrRate", "NewDownstreamCurrRate", "NewUpstreamMaxRate", "NewDownstreamMaxRate",
                "NewUpstreamNoiseMargin", "NewDownstreamNoiseMargin", "NewUpstreamAttenuation", "NewDownstreamAttenuation")
                if k in dsl}
        return {k: v for k, v in out.items() if v not in (None, "", {})}

    def wifi(self) -> List[Dict[str, Any]]:
        out = []
        for n in (1, 2, 3):
            d = self._try(f"WLANConfiguration:{n}", "GetInfo")
            if not d:
                continue
            assoc = self._try(f"WLANConfiguration:{n}", "GetTotalAssociations")
            out.append({k: v for k, v in {
                "radio": f"WLANConfiguration:{n}", "ssid": d.get("NewSSID"), "enabled": d.get("NewEnable") == "1",
                "channel": d.get("NewChannel"), "standard": d.get("NewStandard"),
                "security": d.get("NewBeaconType"), "clients": assoc.get("NewTotalAssociations"),
            }.items() if v not in (None, "")})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        n = int(num(self._try("Hosts:1", "GetHostNumberOfEntries").get("NewHostNumberOfEntries")) or 0)
        out = []
        for i in range(min(n, 100)):
            h = self._try("Hosts:1", "GetGenericHostEntry", {"NewIndex": i})
            if h and h.get("NewActive") == "1":
                out.append({k: v for k, v in {"name": h.get("NewHostName"), "ip": h.get("NewIPAddress"),
                                              "mac": h.get("NewMACAddress"), "interface": h.get("NewInterfaceType")}.items() if v})
        return out

    # ---- low level ---------------------------------------------------------------------------
    def _split(self, target: str):
        m = re.match(r"^(\w+:\d+)[:#](\w+)(?:\s+(.*))?$", target.strip())
        if not m:
            raise NotSupported("target must be 'Service:N:Action' (e.g. DeviceInfo:1:GetInfo) [json args]")
        return m.group(1), m.group(2), json.loads(m.group(3)) if m.group(3) else {}

    def raw_get(self, target: str) -> Any:
        svc, act, args = self._split(target)
        if not act.startswith("Get"):
            raise NotSupported("raw_get only runs Get* actions; use `router write` for Set* actions")
        return self._s(svc, act, args)

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        svc, act, _ = self._split(target)
        if not act.startswith("Set"):
            raise NotSupported("writes must be Set* actions")
        return self._s(svc, act, flds) or "OK"
