"""TP-Link LTE routers with the "/cgi" + "/cgi_gdpr" web API (Archer MR200/MR400/MR500/MR600, TL-MR6400/MR6500v).

Tier: experimental. Written from public protocol descriptions; untested on hardware.

Protocol, as publicly described:
- POST /cgi/getParm returns JavaScript with the RSA key and a sequence number:  var ee="010001"; var nn="<hex>"; var seq="<n>";
- "gdpr" firmware (2020+): every request body is AES-128-CBC encrypted (random 16-digit key/iv) and carries
  an RSA "sign" of "k=..&i=..&h=md5(user+password)&s=<seq+len(data)>" (k/i only on login). Login posts the
  encrypted "user\\npassword" to /cgi/login?data=..&sign=..&Action=1&LoginStatus=0.
- older firmware: /cgi/login?UserName=<rsa(user)>&Passwd=<rsa(password)>&Action=1&LoginStatus=0, plain bodies.
- After login the index page contains var token="..."; data requests POST /cgi_gdpr (or /cgi?1&...) with a
  TokenID header and a "stack" body such as:  1\\r\\n[LTE_NET_STATUS#2,1,0,0,0,0#0,0,0,0,0,0]0,0\\r\\n
  Answers are "[stack]index" headers followed by key=value lines, ending with "[error]0".
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..crypto_compat import rsa_encrypt_pkcs1v15
from ..radio import num
from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported
from .tplink import TPLinkCipher

NETWORK_TYPE = {"0": "No service", "1": "2G", "2": "3G", "3": "4G", "4": "4G", "5": "5G"}


def parse_parm(js: str) -> Dict[str, str]:
    return dict(re.findall(r'var\s+(ee|nn|seq)\s*=\s*"([^"]*)"', js))


def parse_stack(text: str) -> Tuple[List[Dict[str, str]], Optional[str]]:
    """Parse '[2,1,0,0,0,0]0\\nkey=value...' blocks; returns (one dict per block, error code)."""
    blocks: List[Dict[str, str]] = []
    err = None
    cur: Optional[Dict[str, str]] = None
    for line in text.replace("\r", "").split("\n"):
        if not line:
            continue
        m = re.match(r"^\[(error)\](\d+)", line)
        if m:
            err = m.group(2)
            continue
        if re.match(r"^\[[\d,]+\]\d+$", line):
            cur = {}
            blocks.append(cur)
            continue
        if "=" in line and cur is not None:
            k, v = line.split("=", 1)
            cur[k] = v
    return blocks, err


def stack_request(objs: List[str]) -> str:
    """Body asking for one or more objects (action 1 = get)."""
    lines = []
    for i, o in enumerate(objs):
        lines.append("1")
        lines.append(f"[{o}#0,0,0,0,0,0#0,0,0,0,0,0]{i},0")
    return "\r\n".join(lines) + "\r\n"


class TPLinkMR(Driver):
    family = "tplink-mr"
    name = "TP-Link LTE router (MR series, cgi_gdpr API)"
    vendor = "TP-Link"
    tier = "experimental"
    models = "Archer MR200 v2+, MR400, MR500, MR550, MR600, TL-MR6400 v4+, TL-MR6500v (gdpr and older cgi firmware)"
    lockout = "locks the web login for several minutes after about 10 wrong passwords"
    can_write = False
    can_revert = False

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.s.headers["Referer"] = self.base + "/"
        self.variant: Optional[str] = None
        self.cipher: Optional[TPLinkCipher] = None
        self.token: Optional[str] = None
        self.parm: Dict[str, str] = {}

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        score = 0
        if re.search(r"tp-?link", fp.body, re.I):
            score += 30
        if "cgi_gdpr" in fp.body or "/cgi/getParm" in fp.body or "getParm" in fp.body:
            score += 40
        p = fp.text("/cgi/getParm")
        if 'nn="' in p and 'ee="' in p:
            score += 40
        if "LTE" in fp.body or "MR" in (re.search(r"<title>([^<]*)", fp.body) or [None, ""])[1]:
            score += 5
        return min(score, 100)

    def probe(self) -> str:
        r = self.s.post("/cgi/getParm", "")
        self.parm = parse_parm(r.text)
        if not (self.parm.get("nn") and self.parm.get("ee")):
            return "unknown"
        # gdpr firmware publishes a sequence number for the request signature; older firmware does not.
        return "gdpr" if self.parm.get("seq") else "rsa"

    def _login(self, password: str) -> None:
        self.variant = self.probe()
        if self.variant == "unknown":
            raise NotSupported("could not read the RSA parameters from /cgi/getParm; not sending the password")
        n, e = self.parm["nn"], self.parm["ee"]
        if self.variant == "gdpr":
            self.cipher = TPLinkCipher(n, e, int(self.parm["seq"]), self.user, password)
            env = self.cipher.encrypt(f"{self.user}\n{password}", first=True)
            r = self.s.post(f"/cgi/login?data={quote(env['data'], safe='')}&sign={env['sign']}&Action=1&LoginStatus=0", "")
        else:
            u = rsa_encrypt_pkcs1v15(n, e, self.user.encode())
            p = rsa_encrypt_pkcs1v15(n, e, password.encode())
            r = self.s.post(f"/cgi/login?UserName={u}&Passwd={p}&Action=1&LoginStatus=0", "")
        body = r.text
        if self.variant == "gdpr" and self.cipher and body.strip() and "$.ret" not in body:
            try:
                body = self.cipher.decrypt(body.strip())
            except Exception:
                pass
        m = re.search(r"\$\.ret\s*=\s*(\d+)", body)
        if not m or m.group(1) != "0":
            code = m.group(1) if m else "no answer"
            raise LoginRejected(f"router refused login (ret {code}); not retrying")
        idx = self.s.get("/").text
        t = re.search(r'var\s+token\s*=\s*"([^"]+)"', idx)
        if not t:
            raise LoginError("logged in but no token on the index page")
        self.token = t.group(1)

    def logout(self) -> None:
        try:
            if self.token:
                self._gdpr("8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n", raw=True)
        except Exception:
            pass
        finally:
            self.token = None
            self.logged_in = False

    def _gdpr(self, body: str, raw: bool = False) -> str:
        h = {"TokenID": self.token or "", "Content-Type": "text/plain"}
        if self.variant == "gdpr" and self.cipher:
            env = self.cipher.encrypt(body, first=False)
            r = self.s.post("/cgi_gdpr", f"sign={env['sign']}\r\ndata={env['data']}\r\n", headers=h)
            txt = r.text.strip()
            try:
                return self.cipher.decrypt(txt)
            except Exception:
                return txt
        r = self.s.post("/cgi?1", body, headers=h)
        return r.text

    def objects(self, names: List[str]) -> List[Dict[str, str]]:
        self.login()
        blocks, err = parse_stack(self._gdpr(stack_request(names)))
        if err not in (None, "0"):
            raise LoginError(f"router answered error {err} for {names}")
        return blocks

    def cellular(self) -> Optional[Dict[str, Any]]:
        b = self.objects(["LTE_NET_STATUS"])
        if not b:
            return None
        s = b[0]
        out = {"generation": NETWORK_TYPE.get(s.get("networkType", ""), s.get("networkType")),
               "connected": s.get("connectStatus") in ("4", "connected"),
               "bars": int(num(s.get("sigLevel")) or 0) or None, "max_bars": 5,
               "rsrp": num(s.get("rfInfoRsrp")), "rsrq": num(s.get("rfInfoRsrq")), "sinr": num(s.get("rfInfoSnr")),
               "rssi": num(s.get("rfInfoRssi")), "band": ("B" + s["rfInfoBand"]) if s.get("rfInfoBand", "").isdigit() else s.get("rfInfoBand"),
               "network_type_code": s.get("networkType")}
        return {k: v for k, v in out.items() if v not in (None, "")}

    def info(self) -> Dict[str, Any]:
        try:
            b = self.objects(["IGD_DEV_INFO"])
        except LoginError:
            return {"vendor": "TP-Link"}
        d = b[0] if b else {}
        return {k: v for k, v in {"vendor": "TP-Link", "model": d.get("modelName"), "firmware": d.get("softwareVersion"),
                                  "hardware": d.get("hardwareVersion"), "uptime_s": int(num(d.get("upTime")) or 0) or None}.items() if v}

    def raw_get(self, target: str) -> Any:
        """One or more stack object names, comma separated, e.g. LTE_NET_STATUS,WAN_LTE_LINK_CFG."""
        return self.objects([t for t in target.split(",") if t])
