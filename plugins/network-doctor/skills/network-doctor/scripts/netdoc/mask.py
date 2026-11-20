"""Masking of secrets and personal identifiers in anything netdoc prints or saves.

Two levels:
- secrets (always): passwords, keys, PSKs, tokens, session ids, IMEI/IMSI/ICCID/MSISDN, serial numbers.
- identifiers (capture/share mode): MAC addresses, SSIDs, public IPs, host names, phone numbers.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

SECRET_KEY = re.compile(
    r"(pass(word|wd|phrase)?|pwd|psk|wpa_?key|wepkey|presharedkey|secret|token|nonce|salt|proof|"
    r"sessionid|session_id|sessiontoken|stok|sysauth|cookie|authorization|auth_?token|auth_?key|imei|imsi|iccid|msisdn|serial|sn$|"
    r"wifikey|key\d*$|_key$|^key$|pin$|puk$|apikey|private)",
    re.I,
)
# Keys that look like secrets by name but are harmless and useful.
SAFE_KEY = re.compile(r"(key_?mgmt|key_?type|encryption\w*|auth_?mode\w*|authentication_?mode|beacontype|tokenexpir\w*|"
                      r"password_?type|keyindex|key_?index|auth_?type)$", re.I)
IDENT_KEY = re.compile(r"(ssid|mac|bssid|hostname|host_?name|devicename|^name$|phone|number|ipv6|wan_?ip|"
                       r"public_?ip|externalip|ipaddress|ip_?address)", re.I)

MAC = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
IMEI_LIKE = re.compile(r"\b\d{15,20}\b")
XML_SECRET = re.compile(
    r"<(\w*(?:[Pp]assword|PSK|Psk|psk|WpaKey|WepKey|WifiKey|PreSharedKey|[Ss]alt|[Nn]once|[Pp]roof|[Tt]oken|Imei|IMEI|Imsi|IMSI|Iccid|ICCID|"
    r"Msisdn|MSISDN|SerialNumber|[Ss]erial)\w*)>[^<]*</\1>"
)
XML_IDENT = re.compile(r"<(\w*(?:Ssid|SSID|Mac|MAC|HostName|Hostname|PhoneNumber|WanIPAddress|WanIPv6Address)\w*)>[^<]*</\1>")
HIDDEN = "<hidden>"


def _is_public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_global


def is_secret_key(k: str) -> bool:
    k = str(k)
    return bool(SECRET_KEY.search(k)) and not SAFE_KEY.search(k)


def mask(obj: Any, identifiers: bool = False) -> Any:
    """Return a copy of obj (dict/list/str/number) with secrets (and optionally identifiers) hidden."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_secret_key(k) and v not in ("", None, [], {}) and not isinstance(v, (dict, list)):
                out[k] = HIDDEN
            elif identifiers and IDENT_KEY.search(str(k)) and isinstance(v, str) and v:
                out[k] = _ident(v)
            else:
                out[k] = mask(v, identifiers)
        return out
    if isinstance(obj, list):
        return [mask(v, identifiers) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj, identifiers)
    return obj


def _ident(v: str) -> str:
    if MAC.fullmatch(v.strip()):
        return "xx:xx:xx:xx:xx:xx"
    return "<redacted>"


def mask_text(s: str, identifiers: bool = False) -> str:
    s = XML_SECRET.sub(lambda m: f"<{m.group(1)}>{HIDDEN}</{m.group(1)}>", s)
    s = IMEI_LIKE.sub("<id>", s)
    if identifiers:
        s = XML_IDENT.sub(lambda m: f"<{m.group(1)}><redacted></{m.group(1)}>", s)
        s = MAC.sub("xx:xx:xx:xx:xx:xx", s)
        s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lambda m: "<public-ip>" if _is_public_ip(m.group(0)) else m.group(0), s)
    return s


def scrub_known(s: str, secrets: list) -> str:
    """Last line of defence: remove any literal secret values we know about from text output."""
    for sec in secrets:
        if sec and len(sec) >= 4:
            s = s.replace(sec, HIDDEN)
    return s
