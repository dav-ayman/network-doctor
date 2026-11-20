"""Router passwords: OS keychain or environment only. Never printed, never written to disk by netdoc.

Lookup order for host H and user U:
  1. env NETDOC_PASSWORD (applies to whatever router this run talks to; you set it, you chose the router)
  2. macOS Keychain generic password: service "network-doctor", account "U@H"
  3. Linux Secret Service (secret-tool): service network-doctor, account U@H

Router binding: a stored password is tied to the router's MAC address recorded by `secret set`. Many
networks share gateway IPs (192.168.1.1...), so without this a home password would be offered to any
router with the same IP, e.g. on cafe Wi-Fi. If the gateway's MAC differs (or can't be read), the stored
password is not used.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional

SERVICE = "network-doctor"
_seen: List[str] = []  # values handed out this run, so output can be scrubbed of them


def account(host: str, user: str) -> str:
    return f"{user}@{host}"


class RouterMismatch(Exception):
    """The gateway at this IP is not the router the password was saved for."""


STATE_DIR = os.path.expanduser(os.environ.get("NETDOC_HOME", "~/.network-doctor"))
BINDINGS = os.path.join(STATE_DIR, "routers.json")
_MAC = re.compile(r"\b([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}\b")


def gateway_mac(host: str) -> Optional[str]:
    """MAC of host from the ARP/neighbour table (pings once to populate it). None if not on this LAN."""
    try:
        subprocess.run(["ping", "-c", "1", "-t" if sys.platform == "darwin" else "-W", "1", host],
                       capture_output=True, timeout=4)
    except (OSError, subprocess.SubprocessError):
        pass
    for cmd in (["arp", "-n", host], ["ip", "neigh", "show", host]):
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        m = _MAC.search(out)
        if m:
            return ":".join(x.zfill(2) for x in re.split("[:-]", m.group(0).lower()))
    return None


def _bindings() -> Dict[str, str]:
    try:
        with open(BINDINGS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def bind(host: str, user: str, mac: Optional[str]) -> None:
    d = _bindings()
    d[account(host, user)] = mac or ""
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(BINDINGS, "w") as f:
        json.dump(d, f, indent=1)
    os.chmod(BINDINGS, 0o600)


def check_router(host: str, user: str) -> None:
    """Raise RouterMismatch unless this host is the router the stored password belongs to."""
    if os.environ.get("NETDOC_SKIP_ROUTER_CHECK") == "1":
        return
    want = _bindings().get(account(host, user))
    if want is None:
        raise RouterMismatch(
            f"the stored password for {account(host, user)} has no router binding (saved by an older version or "
            f"by hand). Re-run `netdoc.py secret set {host}` while connected to that router.")
    if want == "":
        return  # saved where no MAC was visible (e.g. routed/VPN path); user accepted IP-only binding
    have = gateway_mac(host)
    if have != want:
        raise RouterMismatch(
            f"{host} is not the router this password was saved for (router hardware address "
            f"{'unknown' if not have else 'differs'}). Not sending it. If you replaced the router, run "
            f"`netdoc.py secret set {host}` again.")


def get_password(host: str, user: str) -> Optional[str]:
    pw = os.environ.get("NETDOC_PASSWORD")
    if not pw:
        pw = _keychain_get(account(host, user))
        if pw:
            check_router(host, user)
    if pw:
        _seen.append(pw)
    return pw


def seen() -> List[str]:
    return list(_seen)


def _keychain_get(acct: str) -> Optional[str]:
    try:
        if sys.platform == "darwin":
            r = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", acct, "-w"],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout else None
        if shutil.which("secret-tool"):
            r = subprocess.run(["secret-tool", "lookup", "service", SERVICE, "account", acct],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout else None
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def store_interactive(host: str, user: str) -> str:
    """Prompt on the terminal (no echo) and store in the OS keychain. Must be run by the user, not an agent."""
    if not sys.stdin.isatty():
        return ("refusing: this needs a real terminal so the password is typed, not passed around. "
                "Run it yourself, e.g. in Claude Code type:  ! python3 netdoc.py secret set " + host)
    acct = account(host, user)
    mac = gateway_mac(host)
    if not mac:
        print(f"note: could not read the hardware address of {host}; the password will be tied to the IP only.")
    if sys.platform == "darwin":
        # -w as the LAST option makes `security` prompt on the terminal itself (twice, no echo),
        # so the password never appears in argv or passes through this process.
        print(f"Router admin password for {acct} (typed twice, not shown):")
        p = subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", acct,
                            "-l", f"network-doctor {acct}", "-w"])
        if p.returncode != 0:
            return "Keychain error (exit %d)" % p.returncode
        bind(host, user, mac)
        return "stored in Keychain (tied to this router)"
    pw = getpass.getpass(f"Router admin password for {acct} (not shown): ")
    if not pw:
        return "nothing stored"
    if shutil.which("secret-tool"):
        p = subprocess.run(["secret-tool", "store", "--label", f"network-doctor {acct}", "service", SERVICE,
                            "account", acct], input=pw, text=True, capture_output=True)
        if p.returncode != 0:
            return "secret-tool error: " + p.stderr.strip()
        bind(host, user, mac)
        return "stored in Secret Service (tied to this router)"
    return "no keychain available; set NETDOC_PASSWORD in your shell for this session instead"


def delete(host: str, user: str) -> str:
    acct = account(host, user)
    if sys.platform == "darwin":
        p = subprocess.run(["security", "delete-generic-password", "-s", SERVICE, "-a", acct], capture_output=True)
        return "deleted" if p.returncode == 0 else "not found"
    if shutil.which("secret-tool"):
        p = subprocess.run(["secret-tool", "clear", "service", SERVICE, "account", acct], capture_output=True)
        return "deleted" if p.returncode == 0 else "not found"
    return "no keychain available"
