"""TP-Link routers with the newer "luci" web UI (Archer AX*, Archer C6/C7/C80/A7 v4+ and similar).

Tier: experimental. Written from public protocol descriptions; untested on hardware. The Deco mesh app API
and the Omada controller are out of scope.

Protocol, as publicly described for these firmwares:
- POST /cgi-bin/luci/;stok=/login?form=keys  operation=read  -> data.password = [n_hex, e_hex]  (password RSA key)
- POST /cgi-bin/luci/;stok=/login?form=auth  operation=read  -> data.key = [n_hex, e_hex], data.seq  (signing key)
Two login variants exist:
- "signed-aes" (most firmware since ~2020): the request body is `sign=<hex>&data=<base64>` where
  data = AES-128-CBC(PKCS#7) of the form (key/iv are random 16-digit strings) and
  sign = RSA-PKCS#1 of "k=<key>&i=<iv>&h=<md5(user+password)>&s=<seq + len(data)>" (k/i only on the login
  request), chunked to the key size. Answers are {"data": base64(AES(json))}.
- "rsa-only" (older v4/v5 firmware): plain form posts; only the password is RSA-encrypted.
After login: {"stok": ...} plus a sysauth cookie; API paths become /cgi-bin/luci/;stok=<stok>/admin/<area>?form=<x>.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..crypto_compat import aes_cbc_decrypt, aes_cbc_encrypt, rsa_encrypt_chunked, rsa_encrypt_pkcs1v15
from .base import Driver, Fingerprint, LoginBusy, LoginError, LoginRejected, NotSupported

LOGIN = "/cgi-bin/luci/;stok=/login"


def _digits(n: int = 16) -> str:
    r = random.SystemRandom()
    return "".join(r.choice("0123456789") for _ in range(n))


class TPLinkCipher:
    """The signed-AES envelope. Kept separate so tests can run the same code on the "router" side."""

    def __init__(self, sign_n: str, sign_e: str, seq: int, user: str, password: str,
                 key: Optional[str] = None, iv: Optional[str] = None):
        self.n, self.e, self.seq = sign_n, sign_e, seq
        self.key = (key or _digits()).encode()
        self.iv = (iv or _digits()).encode()
        self.h = hashlib.md5((user + password).encode()).hexdigest()

    def encrypt(self, form: str, first: bool) -> Dict[str, str]:
        data = base64.b64encode(aes_cbc_encrypt(self.key, self.iv, form.encode())).decode()
        s = f"h={self.h}&s={self.seq + len(data)}"
        if first:
            s = f"k={self.key.decode()}&i={self.iv.decode()}&" + s
        return {"sign": rsa_encrypt_chunked(self.n, self.e, s.encode()), "data": data}

    def decrypt(self, b64: str) -> str:
        return aes_cbc_decrypt(self.key, self.iv, base64.b64decode(b64)).decode("utf-8", "replace")


def classify_error(d: Dict[str, Any]) -> Exception:
    data = d.get("data") if isinstance(d.get("data"), dict) else {}
    code = str(d.get("errorcode") or data.get("errorcode") or "")
    left = data.get("attemptsAllowed")
    msg = f"router refused login ({code or 'no error code'}" + (f", {left} attempts left" if left is not None else "") + ")"
    if "conflict" in code or "logged" in code:
        return LoginBusy(msg + ": someone else is logged in to the web UI; log them out or wait")
    return LoginRejected(msg)  # wrong password, max attempts, or anything unexpected: never retry blindly


class TPLinkWeb(Driver):
    family = "tplink"
    name = "TP-Link Archer (luci web UI)"
    vendor = "TP-Link"
    tier = "experimental"
    models = ("Archer AX10/AX20/AX23/AX50/AX55/AX73/AX3000, Archer C6/C7 v4+, C80, C1200 v2+, A7, A8, VR600 (web UI); "
              "not Deco, not Omada")
    lockout = "locks the web login for a while after roughly 5-10 wrong passwords (attemptsAllowed in the answer)"
    can_write = False   # read-only until someone verifies the write format on hardware
    can_revert = False

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.s.headers.update({"Referer": self.base + "/webpages/index.html", "X-Requested-With": "XMLHttpRequest"})
        self.variant: Optional[str] = None
        self.stok: Optional[str] = None
        self.cipher: Optional[TPLinkCipher] = None

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        b = fp.body
        score = 0
        if re.search(r"tp-?link", b, re.I):
            score += 40
        if "/webpages/" in b or "cgi-bin/luci" in b or "luci" in b and "stok" in b:
            score += 45
        if "userRpm" in b or "cgi_gdpr" in b or "/cgi/getParm" in b:
            score -= 40  # those are the legacy / MR UIs
        return max(0, min(score, 100))

    # ---- variant probe (no password involved) -------------------------------------------------
    def _read_json(self, path: str, body: str = "operation=read") -> Dict[str, Any]:
        r = self.s.post(path, body)
        try:
            return r.json()
        except ValueError:
            return {}

    def probe(self) -> Tuple[str, Dict[str, Any]]:
        keys = self._read_json(f"{LOGIN}?form=keys")
        pw_key = (keys.get("data") or {}).get("password") if isinstance(keys.get("data"), dict) else None
        auth = self._read_json(f"{LOGIN}?form=auth")
        ad = auth.get("data") if isinstance(auth.get("data"), dict) else {}
        if pw_key and ad.get("key") and ad.get("seq") is not None:
            return "signed-aes", {"pw": pw_key, "sign": ad["key"], "seq": int(ad["seq"])}
        if pw_key:
            return "rsa-only", {"pw": pw_key}
        return "unknown", {}

    def _login(self, password: str) -> None:
        self.variant, k = self.probe()
        if self.variant == "unknown":
            raise NotSupported("this TP-Link firmware's login variant is not recognised; not sending the password. "
                               "Run `netdoc.py capture` and open an issue.")
        pw_enc = rsa_encrypt_pkcs1v15(k["pw"][0], k["pw"][1], password.encode())
        form = f"operation=login&password={pw_enc}"
        if self.variant == "signed-aes":
            self.cipher = TPLinkCipher(k["sign"][0], k["sign"][1], k["seq"], self.user, password)
            env = self.cipher.encrypt(form, first=True)
            r = self.s.post(f"{LOGIN}?form=login", f"sign={env['sign']}&data={quote(env['data'], safe='')}")
            try:
                outer = r.json()
                d = json.loads(self.cipher.decrypt(outer["data"])) if isinstance(outer.get("data"), str) else outer
            except (ValueError, KeyError):
                raise LoginRejected(f"unexpected login answer (HTTP {r.status}); not retrying")
        else:
            d = self._read_json(f"{LOGIN}?form=login", form)
        if d.get("success") and isinstance(d.get("data"), dict) and d["data"].get("stok"):
            self.stok = d["data"]["stok"]
            return
        raise classify_error(d)

    def api(self, area: str, form: str, operation: str = "read") -> Any:
        self.login()
        path = f"/cgi-bin/luci/;stok={self.stok}/admin/{area}?form={form}"
        body = f"operation={operation}"
        if self.variant == "signed-aes" and self.cipher:
            env = self.cipher.encrypt(body, first=False)
            r = self.s.post(path, f"sign={env['sign']}&data={quote(env['data'], safe='')}")
            try:
                outer = r.json()
                d = json.loads(self.cipher.decrypt(outer["data"])) if isinstance(outer.get("data"), str) else outer
            except (ValueError, KeyError):
                raise LoginError(f"{area}/{form}: unreadable answer (HTTP {r.status})")
        else:
            d = self._read_json(path, body)
        if not d.get("success", True) and d.get("errorcode") in ("timeout", "permission denied"):
            raise LoginError(f"{area}/{form}: {d.get('errorcode')}")
        return d.get("data", d)

    def logout(self) -> None:
        try:
            if self.stok:
                self.api("system", "logout", "write")
        except Exception:
            pass
        finally:
            self.stok = None
            self.logged_in = False

    # ---- read model --------------------------------------------------------------------------
    def _status(self) -> Dict[str, Any]:
        d = self.api("status", "all")
        return d if isinstance(d, dict) else {}

    def info(self) -> Dict[str, Any]:
        try:
            fw = self.api("firmware", "upgrade")
        except LoginError:
            fw = {}
        fw = fw if isinstance(fw, dict) else {}
        return {k: v for k, v in {"vendor": "TP-Link", "model": fw.get("model"), "firmware": fw.get("firmware_version"),
                                  "hardware": fw.get("hardware_version")}.items() if v}

    def wan(self) -> Dict[str, Any]:
        s = self._status()
        return {k: v for k, v in {"type": s.get("wan_ipv4_conntype"), "ip": s.get("wan_ipv4_ipaddr"),
                                  "gateway": s.get("wan_ipv4_gateway"),
                                  "dns": [x for x in (s.get("wan_ipv4_pridns"), s.get("wan_ipv4_snddns")) if x and x != "0.0.0.0"] or None,
                                  "connected": bool(s.get("wan_ipv4_ipaddr")) and s.get("wan_ipv4_ipaddr") != "0.0.0.0",
                                  "uptime_s": s.get("wan_ipv4_uptime")}.items() if v not in (None, "", [])}

    def wifi(self) -> List[Dict[str, Any]]:
        s = self._status()
        out = []
        for band, label in (("2g", "2.4GHz"), ("5g", "5GHz"), ("5g_2", "5GHz-2"), ("6g", "6GHz")):
            if f"wireless_{band}_ssid" not in s and f"wireless_{band}_enable" not in s:
                continue
            out.append({k: v for k, v in {
                "radio": band, "band": label, "ssid": s.get(f"wireless_{band}_ssid"),
                "enabled": s.get(f"wireless_{band}_enable") in ("on", True, "1"),
                "channel": s.get(f"wireless_{band}_current_channel") or s.get(f"wireless_{band}_channel"),
                "width": s.get(f"wireless_{band}_htmode"), "standard": s.get(f"wireless_{band}_hwmode"),
                "security": s.get(f"wireless_{band}_encryption"),
            }.items() if v not in (None, "")})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        s = self._status()
        out = []
        for kind in ("wireless", "wired"):
            for c in s.get(f"access_devices_{kind}_host") or s.get(f"access_devices_{kind}") or []:
                out.append({k: v for k, v in {"name": c.get("hostname"), "ip": c.get("ipaddr"), "mac": c.get("macaddr"),
                                              "interface": c.get("wire_type") or kind}.items() if v})
        return out

    def extras(self) -> Dict[str, Any]:
        s = self._status()
        return {k: v for k, v in {"cpu_usage": s.get("cpu_usage"), "mem_usage": s.get("mem_usage")}.items() if v is not None}

    def raw_get(self, target: str) -> Any:
        """'area/form', e.g. 'status/all' or 'wireless/statistics'."""
        if "/" not in target:
            raise NotSupported("target must be 'area/form', e.g. status/all")
        area, form = target.split("/", 1)
        return self.api(area, form)
