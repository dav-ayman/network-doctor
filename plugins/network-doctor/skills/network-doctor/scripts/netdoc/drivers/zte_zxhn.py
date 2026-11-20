"""ZTE ZXHN home gateways (fiber ONT / DSL / AP) with the "menuView / menuData" web UI.

Verified on an H188A V6 used as an access point. The same UI is used by H298A, H288A, H3600, F670L, F680
and many ISP-branded ZTE gateways, but those are untested.

Session mechanics (from the verified device):
- login: GET /?_type=loginData&_tag=login_entry -> sess_token; GET login_token (XML) -> salt;
  POST login_entry with Password = sha256(password + login_token)
- reads: load the view (/?_type=menuView&_tag=<view>) first, then /?_type=menuData&_tag=<data tag>
- writes: body "IF_ACTION=Apply&...&_sessionTOKEN=<token from the view just loaded>" with header
  Check: sha256(body). Each view load issues a fresh token.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List
from urllib.parse import quote

from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported

# (view, data tag) pairs known on the verified device; explore() finds the rest.
KNOWN = {
    "wifi": ("wlanBasic", "wlan_basicadconf_lua.lua"),
    "qos": ("qosBasic", "qos_basic_m.lua"),
    "qos_classes": ("qosType", "qos_type_m.lua"),
    "qos_shapers": ("qosShaper", "qos_shaper_lua.lua"),
    "qos_queues": ("qosQueue", "qos_queue_lua.lua"),
}


def unescape_js(tok: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), tok)


def instances(xml: str) -> List[Dict[str, str]]:
    return [dict(re.findall(r"<ParaName>([^<]*)</ParaName><ParaValue>([^<]*)</ParaValue>", i))
            for i in re.findall(r"<Instance>(.*?)</Instance>", xml, re.S)]


def encode_body(fields: List[Any], token: str) -> str:
    body = "IF_ACTION=Apply" + "".join(f"&{k}={quote(str(v), safe=chr(39) + '-_.!~*()')}" for k, v in fields)
    return body + "&_sessionTOKEN=" + token


class ZTEZXHN(Driver):
    family = "zte-zxhn"
    name = "ZTE ZXHN home gateway / AP (menuView UI)"
    vendor = "ZTE"
    tier = "verified"
    models = "H188A V6 (verified); likely H298A, H288A, H3600, F670L, F680 and ISP-branded variants"
    lockout = "locks login for a few minutes after repeated failures (login_entry reports lockingTime)"
    can_write = True
    can_revert = True
    write_targets = "'<view>:<data tag>' (e.g. qosBasic:qos_basic_m.lua); fields are the form names, " \
                    "including the instance field such as OBJ_QOSQB_ID._OBJ_InstID"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.s.headers["User-Agent"] = "Mozilla/5.0 (network-doctor)"

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        t = fp.text("/?_type=loginData&_tag=login_entry")
        if t.strip().startswith("{") and ("sess_token" in t or "lockingTime" in t):
            return 95
        return 30 if "_type=loginData" in fp.body or "ZXHN" in fp.body else 0

    # ---- login -------------------------------------------------------------------------------
    def _login(self, password: str) -> None:
        self.s.get("/")
        try:
            entry = self.s.get("/?_type=loginData&_tag=login_entry").json()
        except ValueError:
            raise LoginError("login_entry did not return JSON")
        if entry.get("lockingTime") not in (None, "", 0, "0"):
            raise LoginRejected(f"router has locked logins for {entry['lockingTime']} s ({entry.get('promptMsg', '')})")
        tok = re.sub(r"<[^>]+>", "", self.s.get("/?_type=loginData&_tag=login_token").text).strip()
        form = {"Password": hashlib.sha256((password + tok).encode()).hexdigest(), "Username": self.user,
                "_sessionTOKEN": entry.get("sess_token", ""), "action": "login"}
        r = self.s.post("/?_type=loginData&_tag=login_entry", form, headers={"X-Requested-With": "XMLHttpRequest"})
        try:
            res = r.json()
        except ValueError:
            raise LoginError(f"unexpected login answer (HTTP {r.status})")
        if res.get("login_need_refresh") is True and not res.get("loginErrMsg"):
            return  # success answer on the verified device
        # Anything else is treated as a rejection, so no later run retries it blindly.
        msg = res.get("loginErrMsg") or res.get("promptMsg") or json.dumps(res)[:120]
        raise LoginRejected(f"router did not accept the login: {msg}")

    def _page_token(self, html: str) -> str:
        toks = [t for t in re.findall(r'_sessionTmpToken\s*=\s*"([^"]*)"', html) if t]
        return unescape_js(toks[-1]) if toks else ""

    def logout(self) -> None:
        try:
            tok = self._page_token(self.s.get("/").text)
            self.s.post("/?_type=loginData&_tag=logout_entry", {"IF_LogOff": 1, "_sessionTOKEN": tok})
        finally:
            self.logged_in = False

    # ---- reads -------------------------------------------------------------------------------
    def rows(self, view: str, tag: str) -> List[Dict[str, str]]:
        self.login()
        self.s.get(f"/?_type=menuView&_tag={view}&Menu3Location=0")
        x = self.s.get(f"/?_type=menuData&_tag={tag}&InterfaceFilter=").text
        if "<Instance>" not in x and "SessionTimeout" in x:
            raise LoginError("session expired")
        return instances(x)

    def info(self) -> Dict[str, Any]:
        return {"vendor": "ZTE"}

    def wifi(self) -> List[Dict[str, Any]]:
        out = []
        for r in self.rows(*KNOWN["wifi"]):
            ch = r.get("Channel")
            out.append({k: v for k, v in {
                "radio": r.get("_InstID") or r.get("Alias"), "enabled": r.get("RadioStatus", r.get("Enable")) in ("1", "true"),
                "channel": ch if ch not in (None, "0") else "auto", "band": r.get("Band") or r.get("OperatingFrequencyBand"),
                "width": r.get("BandWidth") or r.get("OperatingChannelBandwidth"), "standard": r.get("WirelessMode") or r.get("Standard"),
                "tx_power": r.get("TxPower") or r.get("TransmitPower"), "country": r.get("CountryCode"),
            }.items() if v not in (None, "")})
        return out

    def extras(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        try:
            qb = self.rows(*KNOWN["qos"])
            if qb:
                out["qos_enabled"] = qb[0].get("Enable") == "1"
            cls = self.rows(*KNOWN["qos_classes"])
            if cls:
                out["qos_classes"] = [{k: c.get(k) for k in ("_InstID", "Alias", "Enable", "L3ProtocolList", "DestPort",
                                                             "DestPortMax", "DscpMark", "TrafficClass") if c.get(k)}
                                      for c in cls]
            sh = self.rows(*KNOWN["qos_shapers"])
            if sh:
                out["qos_shapers"] = [{k: c.get(k) for k in ("_InstID", "Alias", "Enable", "Interface", "ShapingRate")
                                       if c.get(k)} for c in sh]
        except LoginError:
            raise
        except Exception as e:
            out["qos_error"] = str(e)
        return out

    # ---- low level ---------------------------------------------------------------------------
    def _split(self, target: str):
        if ":" not in target:
            if target in KNOWN:
                return KNOWN[target]
            raise NotSupported(f"target must be '<view>:<data tag>' or one of {sorted(KNOWN)}")
        view, tag = target.split(":", 1)
        return view, tag

    def raw_get(self, target: str) -> Any:
        return self.rows(*self._split(target))

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        rows = self.rows(*self._split(target))
        inst_key = next((k for k in flds if k.endswith("_OBJ_InstID") or k == "_InstID"), None)
        inst = flds.get(inst_key) if inst_key else None
        row = next((r for r in rows if inst is None or r.get("_InstID") == inst), None)
        if row is None:
            raise NotSupported(f"instance {inst} not found in {target}; nothing to back up (new object?)")
        out = {}
        for k in flds:
            short = k.split(".", 1)[1] if "." in k else k
            short = "_InstID" if short == "_OBJ_InstID" else short
            if short not in row:
                raise NotSupported(f"cannot read back {k} from {target}")
            out[k] = row[short]
        return out

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        view, tag = self._split(target)
        self.login()
        page = self.s.get(f"/?_type=menuView&_tag={view}&Menu3Location=0").text
        tok = self._page_token(page) or self._page_token(self.s.get("/").text)
        items = flds.items() if isinstance(flds, dict) else flds
        body = encode_body(list(items), tok)
        r = self.s.post(f"/?_type=menuData&_tag={tag}", body,
                        headers={"X-Requested-With": "XMLHttpRequest", "Check": hashlib.sha256(body.encode()).hexdigest()})
        err = re.search(r"<IF_ERRORSTR>([^<]*)", r.text)
        code = re.search(r"<IF_ERRORID>([^<]*)", r.text)
        if err and err.group(1) == "SUCC":
            return "OK"
        raise LoginError(f"write failed: {err.group(1) if err else '?'} (id {code.group(1) if code else '?'})")

    def explore(self) -> Dict[str, Any]:
        """List menu views and the data tags each one loads (read-only)."""
        self.login()
        home = self.s.get("/").text
        views = sorted(set(re.findall(r"menuView&_tag=([A-Za-z0-9]+)", home)) |
                       set(re.findall(r"""['"]?menuPage['"]?\s*:\s*['"]([A-Za-z0-9]+)""", home)) |
                       set(KNOWN[v][0] for v in KNOWN))
        out: Dict[str, Any] = {}
        for v in views[:80]:
            page = self.s.get(f"/?_type=menuView&_tag={v}&Menu3Location=0").text
            tags = sorted(set(re.findall(r"_tag=([A-Za-z0-9_]+\.lua)", page)))
            if tags:
                out[v] = tags
        return {"views": out}
