"""ZTE "goform" web API: LTE/5G MiFis and CPEs (U20, MU5001, MU5120, MF971, MF286, MC801A...).

Verified on a U20 (LD-salted SHA256 login, AD token for writes). The base64 login used by older
firmware is from the public web UI and untested here.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from ..radio import num
from .base import Driver, Fingerprint, LoginError, LoginRejected, NotSupported

GET = "/goform/goform_get_cmd_process"
SET = "/goform/goform_set_cmd_process"


def sha_upper(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()


def login_hash(password: str, ld: str) -> str:
    """SHA256(SHA256(pw) + LD), uppercase hex, as the web UI sends it."""
    return sha_upper(sha_upper(password) + ld)


def ad_token(wa_inner_version: str, cr_version: str, rd: str) -> str:
    """Anti-CSRF "AD" field required on every write: SHA256(SHA256(wa_inner_version + cr_version) + RD)."""
    return sha_upper(sha_upper(wa_inner_version + cr_version) + rd)


def generation(network_type: str, ca: str = "") -> str:
    t = (network_type or "").upper()
    if not t or "NO_SERVICE" in t or "LIMITED" in t or t == "NONE":
        return "No service"
    if any(x in t for x in ("NR", "5G", "ENDC")) or t in ("SA", "NSA"):
        return "5G"
    if "LTE" in t or t == "4G":
        return "4G+" if ca == "ca_activated" else "4G"
    if "HSPA+" in t or "DC-HSPA" in t or "DC_HSPA" in t:
        return "H+"
    if any(x in t for x in ("HSPA", "HSDPA", "HSUPA", "UMTS", "WCDMA", "TD-SCDMA", "TDSCDMA", "3G", "EVDO")):
        return "3G"
    if any(x in t for x in ("GSM", "EDGE", "GPRS", "2G", "CDMA")):
        return "2G"
    return t


class ZTEGoform(Driver):
    family = "zte-goform"
    name = "ZTE MiFi / CPE (goform API)"
    vendor = "ZTE"
    tier = "verified"
    models = "U20, MU5001, MU5120, MF971, MF286, MF289, MC801A, MC888 and most ZTE MiFis since ~2018"
    lockout = "locks login after about 5 wrong passwords (psw_fail_num_str shows attempts left)"
    can_write = True
    can_revert = True
    write_targets = "a goformId such as SET_WIFI_SSID1_SETTINGS; fields are its form parameters"

    def __init__(self, *a: Any, **kw: Any):
        super().__init__(*a, **kw)
        self.s.headers.update({"Referer": self.base + "/index.html", "X-Requested-With": "XMLHttpRequest"})

    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        r = fp.get(GET + "?isTest=false&cmd=model_name%2Cwa_inner_version&multi_data=1",
                   headers={"Referer": (fp.base or "") + "/index.html"})
        if r is not None and r.status == 200 and r.text.strip().startswith("{"):
            try:
                d = r.json()
            except ValueError:
                return 0
            return 95 if "model_name" in d or "wa_inner_version" in d else 40
        return 20 if "goform" in fp.body else 0

    # ---- transport ---------------------------------------------------------------------------
    def get(self, cmds: List[str], multi: bool = True) -> Dict[str, Any]:
        q = {"isTest": "false", "cmd": ",".join(cmds)}
        if multi:
            q["multi_data"] = "1"
        r = self.s.get(GET + "?" + urlencode(q))
        try:
            return r.json()
        except ValueError:
            raise LoginError(f"unexpected answer from {GET} (HTTP {r.status})")

    def post(self, form: Dict[str, Any]) -> Dict[str, Any]:
        r = self.s.post(SET, form)
        try:
            return r.json()
        except ValueError:
            return {"raw": r.text[:200]}

    # ---- login -------------------------------------------------------------------------------
    def _login(self, password: str) -> None:
        pre = self.get(["loginfo", "psw_fail_num_str", "login_lock_time"])
        if pre.get("loginfo") == "ok":
            return
        left = str(pre.get("psw_fail_num_str", ""))
        if left == "0" or (pre.get("login_lock_time") not in (None, "", "0", "-1")):
            raise LoginRejected(f"router reports login locked (attempts left {left or '?'}, "
                                f"lock time {pre.get('login_lock_time')}); wait and fix the password first")
        ld = str(self.get(["LD"], multi=False).get("LD", ""))
        pw = login_hash(password, ld) if ld else base64.b64encode(password.encode()).decode()
        r = self.post({"isTest": "false", "goformId": "LOGIN", "password": pw})
        res = str(r.get("result", ""))
        if res in ("0", "4"):  # 4 = already logged in on some firmware
            return
        # Any other answer is treated as a rejection (conservative: the MiFi locks after a few failures).
        raise LoginRejected(f"router rejected the login (result {res or json.dumps(r)[:80]}, attempts left "
                            f"{self.get(['psw_fail_num_str']).get('psw_fail_num_str', '?')})")

    def logout(self) -> None:
        try:
            self.post({"isTest": "false", "goformId": "LOGOUT", "AD": self._ad()})
        finally:
            self.logged_in = False

    def _ad(self) -> str:
        v = self.get(["wa_inner_version", "cr_version"])
        rd = str(self.get(["RD"], multi=False).get("RD", ""))
        return ad_token(str(v.get("wa_inner_version", "")), str(v.get("cr_version", "")), rd)

    def _authed(self, cmds: List[str]) -> Dict[str, Any]:
        d = self.get(["loginfo"] + cmds)
        if d.get("loginfo") != "ok":
            self.login()
            d = self.get(["loginfo"] + cmds)
        return d

    # ---- read model --------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        d = self.get(["model_name", "wa_inner_version", "hardware_version", "cr_version"])
        return {k: v for k, v in {"vendor": "ZTE", "model": d.get("model_name"), "firmware": d.get("wa_inner_version"),
                                  "hardware": d.get("hardware_version")}.items() if v}

    def cellular(self) -> Optional[Dict[str, Any]]:
        q = self.get(["network_type", "signalbar", "network_provider", "ppp_status", "lte_rssi",
                      "battery_vol_percent", "battery_charging", "flux_monthly_rx_bytes", "flux_monthly_tx_bytes"])
        if not q.get("network_type") and not q.get("signalbar"):
            return None
        ppp = str(q.get("ppp_status", ""))
        out: Dict[str, Any] = {
            "operator": q.get("network_provider") or None,
            "connected": "connected" in ppp and "disconnected" not in ppp,
            "bars": int(num(q.get("signalbar")) or 0), "max_bars": 5,
            "network_type_code": q.get("network_type"), "rssi": num(q.get("lte_rssi")),
            "battery_pct": int(num(q.get("battery_vol_percent")) or 0) or None,
            "charging": (q.get("battery_charging") == "1") if q.get("battery_vol_percent") else None,
            "month_rx": int(num(q.get("flux_monthly_rx_bytes")) or 0) or None,
            "month_tx": int(num(q.get("flux_monthly_tx_bytes")) or 0) or None,
        }
        ca = ""
        try:
            d = self._authed(["lte_rsrp", "lte_rsrq", "lte_snr", "wan_active_band", "lte_ca_scell_band", "wan_lte_ca",
                              "Z5g_rsrp", "Z5g_rsrq", "Z5g_SINR", "nr5g_action_band", "cell_id", "lte_pci"])
            ca = str(d.get("wan_lte_ca", ""))
            band = str(d.get("wan_active_band", "") or "")
            if ca == "ca_activated" and d.get("lte_ca_scell_band"):
                band += f" + CA {d['lte_ca_scell_band']}"
            out.update({"rsrp": num(d.get("lte_rsrp")), "rsrq": num(d.get("lte_rsrq")), "sinr": num(d.get("lte_snr")),
                        "band": band or None, "pci": d.get("lte_pci") or None})
            if d.get("Z5g_rsrp"):
                out["nr"] = {"rsrp": num(d.get("Z5g_rsrp")), "rsrq": num(d.get("Z5g_rsrq")),
                             "sinr": num(d.get("Z5g_SINR")), "band": d.get("nr5g_action_band") or None}
        except LoginError as e:
            out["details_error"] = str(e)
        out["generation"] = generation(str(q.get("network_type", "")), ca)
        return {k: v for k, v in out.items() if v is not None}

    def wan(self) -> Dict[str, Any]:
        d = self.get(["ppp_status", "wan_ipaddr", "prefer_dns_auto", "standby_dns_auto", "realtime_time",
                      "realtime_tx_thrpt", "realtime_rx_thrpt"])
        ppp = str(d.get("ppp_status", ""))
        out = {"type": "cellular", "connected": "connected" in ppp and "disconnected" not in ppp,
               "ip": d.get("wan_ipaddr") or None,
               "dns": [x for x in (d.get("prefer_dns_auto"), d.get("standby_dns_auto")) if x],
               "now_down_bps": int(num(d.get("realtime_rx_thrpt")) or 0) * 8,
               "now_up_bps": int(num(d.get("realtime_tx_thrpt")) or 0) * 8,
               "uptime_s": int(num(d.get("realtime_time")) or 0) or None}
        return {k: v for k, v in out.items() if v not in (None, [], "")}

    WIFI_FIELDS = ["WiFiModuleSwitch", "wifi_band", "Channel", "wifi_11n_cap", "SSID1", "AuthMode", "EncrypType",
                   "wifi_coverage", "m_ssid_enable", "wifi_lbd_enable",
                   "wifi_chip1_ssid1_ssid", "wifi_chip1_ssid1_switch_onoff", "wifi_chip1_ssid1_access_sta_num",
                   "wifi_chip2_ssid1_ssid", "wifi_chip2_ssid1_switch_onoff", "wifi_chip2_ssid1_access_sta_num",
                   "wifi_chip1_ssid1_auth_mode", "wifi_chip2_ssid1_auth_mode"]

    def wifi(self) -> List[Dict[str, Any]]:
        d = self._authed(self.WIFI_FIELDS)
        radios = []
        for chip, band in (("chip1", "2.4GHz"), ("chip2", "5GHz")):
            if d.get(f"wifi_{chip}_ssid1_ssid") or d.get(f"wifi_{chip}_ssid1_switch_onoff"):
                radios.append({"radio": chip, "band": band, "ssid": d.get(f"wifi_{chip}_ssid1_ssid"),
                               "enabled": d.get(f"wifi_{chip}_ssid1_switch_onoff") == "1",
                               "security": d.get(f"wifi_{chip}_ssid1_auth_mode") or None,
                               "clients_reported": d.get(f"wifi_{chip}_ssid1_access_sta_num") or None})
        if not radios and (d.get("SSID1") or d.get("Channel")):
            radios.append({"radio": "main", "band": {"b": "2.4GHz", "a": "5GHz"}.get(str(d.get("wifi_band")), d.get("wifi_band")),
                           "ssid": d.get("SSID1"), "enabled": d.get("WiFiModuleSwitch") == "1",
                           "channel": d.get("Channel"), "security": d.get("AuthMode"), "encryption": d.get("EncrypType"),
                           "width": {"0": "20MHz", "1": "20/40MHz"}.get(str(d.get("wifi_11n_cap")))})
        if d.get("wifi_coverage"):
            for r in radios:
                r["coverage"] = d.get("wifi_coverage")
        return [{k: v for k, v in r.items() if v not in (None, "")} for r in radios]

    def clients(self) -> List[Dict[str, Any]]:
        self._authed([])
        d = self.get(["station_list"], multi=False)
        return [{"name": c.get("hostname"), "ip": c.get("ip_addr"), "mac": c.get("mac_addr")}
                for c in d.get("station_list", []) or []]

    # ---- low level ---------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        cmds = [c for c in target.split(",") if c]
        return self._authed(cmds) if cmds else {}

    def current(self, target: str, flds: Dict[str, Any]) -> Dict[str, Any]:
        d = self._authed(list(flds))
        missing = [k for k in flds if k not in d or d[k] == ""]
        if missing:
            raise NotSupported(f"cannot read back {missing} (goform parameter names differ from read names); "
                               "no automatic revert for this change")
        return {k: d[k] for k in flds}

    def raw_set(self, target: str, flds: Dict[str, Any]) -> Any:
        self.login()
        form = {"isTest": "false", "goformId": target}
        form.update({k: str(v) for k, v in flds.items()})
        form["AD"] = self._ad()
        r = self.post(form)
        if str(r.get("result")) in ("success", "0"):
            return "OK"
        raise LoginError(f"write {target} failed: {json.dumps(r)[:150]}")
