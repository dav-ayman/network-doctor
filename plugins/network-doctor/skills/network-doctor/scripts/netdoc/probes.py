"""Measurements: link baseline, latency under load (bufferbloat), call quality, MTU, DNS, Wi-Fi.

Everything here is read-only for the network: it sends pings, STUN binding requests, DNS lookups and
speed-test traffic, and never changes system settings.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

MAC = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
STUN_SERVERS = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478), ("global.stun.twilio.com", 3478)]


def run(cmd: List[str], timeout: float = 30) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# ---------------------------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------------------------
def default_route() -> Dict[str, Optional[str]]:
    gw = iface = None
    if MAC:
        out = run(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\S+)", out)
        gw = m.group(1) if m else None
        m = re.search(r"interface:\s*(\S+)", out)
        iface = m.group(1) if m else None
    elif LINUX:
        out = run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            gw, iface = m.group(1), m.group(2)
    return {"gateway": gw, "interface": iface, "medium": interface_medium(iface)}


def interface_medium(iface: Optional[str]) -> Optional[str]:
    if not iface:
        return None
    if MAC:
        out = run(["networksetup", "-listallhardwareports"])
        for block in out.split("\n\n"):
            if f"Device: {iface}" in block:
                port = re.search(r"Hardware Port: (.+)", block)
                p = port.group(1) if port else ""
                return "wifi" if "Wi-Fi" in p or "AirPort" in p else ("vpn" if iface.startswith("utun") else "ethernet")
        return "vpn" if iface.startswith(("utun", "ipsec", "ppp")) else None
    if LINUX:
        if os.path.isdir(f"/sys/class/net/{iface}/wireless") or iface.startswith("wl"):
            return "wifi"
        if iface.startswith(("tun", "wg", "ppp")):
            return "vpn"
        return "ethernet"
    return None


def dns_servers() -> List[str]:
    if MAC:
        out = run(["scutil", "--dns"])
        seen: List[str] = []
        for s in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out):
            if s not in seen:
                seen.append(s)
        return seen[:4]
    try:
        with open("/etc/resolv.conf") as f:
            return [l.split()[1] for l in f if l.startswith("nameserver")][:4]
    except OSError:
        return []


def dns_timing(names=("www.google.com", "zoom.us", "teams.microsoft.com", "meet.google.com")) -> Dict[str, Any]:
    out = {}
    for n in names:
        t0 = time.time()
        try:
            socket.getaddrinfo(n, 443, proto=socket.IPPROTO_TCP)
            out[n] = round((time.time() - t0) * 1000)
        except OSError:
            out[n] = None
    vals = [v for v in out.values() if v is not None]
    return {"per_name_ms": out, "max_ms": max(vals) if vals else None, "failures": sum(v is None for v in out.values())}


# ---------------------------------------------------------------------------------------------
# ping series
# ---------------------------------------------------------------------------------------------
def summarize(rtts: List[Optional[float]], late_ms: float = 150) -> Dict[str, Any]:
    """rtts: one entry per probe, None = lost."""
    n = len(rtts)
    got = [r for r in rtts if r is not None]
    if not got:
        return {"sent": n, "loss_pct": 100.0 if n else None}
    srt = sorted(got)
    jit = statistics.mean(abs(a - b) for a, b in zip(got, got[1:])) if len(got) > 1 else 0.0
    # longest run of consecutive losses (a dropout)
    run_, worst = 0, 0
    for r in rtts:
        run_ = run_ + 1 if r is None else 0
        worst = max(worst, run_)
    return {"sent": n, "loss_pct": round(100 * (n - len(got)) / n, 1), "avg_ms": round(statistics.mean(got), 1),
            "p50_ms": round(srt[len(srt) // 2], 1), "p95_ms": round(srt[max(0, int(len(srt) * 0.95) - 1)], 1),
            "max_ms": round(srt[-1], 1), "jitter_ms": round(jit, 1),
            "late_pct": round(100 * sum(1 for r in got if r > late_ms) / n, 1), "longest_gap": worst}


def ping_series(host: str, count: int = 30, interval: float = 0.2, timeout_s: float = 2.0) -> Dict[str, Any]:
    """System ping, one result per probe (None = lost). interval >= 0.2 works unprivileged on macOS and Linux."""
    if not shutil.which("ping"):
        return {"error": "ping not available"}
    cmd = ["ping", "-n", "-c", str(count), "-i", str(interval)]
    if LINUX:
        cmd += ["-W", str(int(timeout_s))]
    out = run(cmd + [host], timeout=count * interval + timeout_s + 10)
    seqs: Dict[int, float] = {}
    for m in re.finditer(r"icmp_seq=(\d+).*?time=([\d.]+)", out):
        seqs[int(m.group(1))] = float(m.group(2))
    base = 1 if LINUX else 0  # iputils counts from 1, BSD/macOS ping from 0
    rtts = [seqs.get(i + base) for i in range(count)]
    s = summarize(rtts)
    s["target"] = host
    return s


# ---------------------------------------------------------------------------------------------
# call-quality probe (STUN, the same UDP path a Meet/Teams/Zoom call uses)
# ---------------------------------------------------------------------------------------------
def stun_probe(seconds: float = 15, rate_hz: int = 10, server: Optional[tuple] = None) -> Dict[str, Any]:
    """Send STUN binding requests at rate_hz for `seconds`; per-packet RTT like a voice stream sees it."""
    servers = [server] if server else STUN_SERVERS
    addr = None
    for host, port in servers:
        try:
            addr = (socket.gethostbyname(host), port)
            break
        except OSError:
            continue
    if not addr:
        return {"error": "could not resolve any STUN server (DNS down?)"}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.01)
    order: List[bytes] = []
    sent_at: Dict[bytes, float] = {}
    got: Dict[bytes, float] = {}
    t_end = time.time() + seconds
    nxt = time.time()
    while True:
        now = time.time()
        if now >= nxt and now < t_end:
            tid = os.urandom(12)
            try:
                s.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + tid, addr)
            except OSError:
                pass
            order.append(tid)
            sent_at[tid] = now
            nxt += 1.0 / rate_hz
        try:
            data, _ = s.recvfrom(2048)
            tid = data[8:20]
            if tid in sent_at and tid not in got:
                got[tid] = (time.time() - sent_at[tid]) * 1000
        except (socket.timeout, OSError):
            pass
        if now > t_end + 2:
            break
    s.close()
    out = summarize([got.get(t) for t in order])
    out["target"] = f"stun {addr[0]}:{addr[1]}"
    return out


# ---------------------------------------------------------------------------------------------
# load generators
# ---------------------------------------------------------------------------------------------
class Load:
    """Saturate upload or download while a probe runs. Uses Apple's networkQuality on macOS
    (-d = no download test, i.e. upload only; -u = no upload test, i.e. download only), else HTTP streams."""

    def __init__(self, direction: str, seconds: float = 25, streams: int = 4):
        assert direction in ("up", "down")
        self.direction, self.seconds, self.streams = direction, seconds, streams
        self.proc: Optional[subprocess.Popen] = None
        self.threads: List[threading.Thread] = []
        self.stop = threading.Event()
        self.bytes = 0
        self.lock = threading.Lock()
        self.method = ""

    def __enter__(self) -> "Load":
        if MAC and shutil.which("networkQuality"):
            flag = "-d" if self.direction == "up" else "-u"
            self.proc = subprocess.Popen(["networkQuality", flag, "-c"], stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True)
            self.method = f"networkQuality {flag}"
        else:
            for _ in range(self.streams):
                t = threading.Thread(target=self._up if self.direction == "up" else self._down, daemon=True)
                t.start()
                self.threads.append(t)
            self.method = f"{self.streams} HTTPS streams (speed.cloudflare.com)"
        time.sleep(3)  # let the queue fill before measuring
        return self

    def _down(self) -> None:
        ctx = ssl.create_default_context()
        while not self.stop.is_set():
            try:
                r = urllib.request.urlopen("https://speed.cloudflare.com/__down?bytes=200000000", timeout=10, context=ctx)
                while not self.stop.is_set():
                    b = r.read(65536)
                    if not b:
                        break
                    with self.lock:
                        self.bytes += len(b)
            except Exception:
                time.sleep(0.5)

    def _up(self) -> None:
        # Cloudflare throttles repeated large uploads from one client; good enough to fill the uplink queue
        # for ~20 s, which is all the probe needs.
        chunk = os.urandom(65536)
        ctx = ssl.create_default_context()
        while not self.stop.is_set():
            try:
                conn = __import__("http.client").client.HTTPSConnection("speed.cloudflare.com", timeout=10, context=ctx)
                conn.putrequest("POST", "/__up")
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("Transfer-Encoding", "chunked")
                conn.endheaders()
                sent = 0
                while not self.stop.is_set() and sent < 200_000_000:
                    conn.send(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    sent += len(chunk)
                    with self.lock:
                        self.bytes += len(chunk)
                conn.send(b"0\r\n\r\n")
                conn.close()
            except Exception:
                time.sleep(0.5)

    def __exit__(self, *exc: Any) -> None:
        self.stop.set()
        self.result: Dict[str, Any] = {"method": self.method}
        if self.proc:
            try:
                self.proc.terminate()
                out, _ = self.proc.communicate(timeout=10)
                d = json.loads(out) if out and out.strip().startswith("{") else {}
                key = "ul_throughput" if self.direction == "up" else "dl_throughput"
                if d.get(key):
                    self.result["throughput_mbps"] = round(d[key] / 1e6, 1)
            except Exception:
                self.proc.kill()


def latency_under_load(seconds: float = 15) -> Dict[str, Any]:
    """Call-quality probe idle, during upload, during download. The core bufferbloat test."""
    out: Dict[str, Any] = {"idle": stun_probe(seconds)}
    for direction in ("up", "down"):
        with Load(direction, seconds + 8) as ld:
            r = stun_probe(seconds)
        r["load"] = getattr(ld, "result", {"method": ld.method})
        out["upload" if direction == "up" else "download"] = r
    for k in ("upload", "download"):
        if out[k].get("p95_ms") is not None and out["idle"].get("p95_ms") is not None:
            out[k]["added_p95_ms"] = round(out[k]["p95_ms"] - out["idle"]["p95_ms"], 1)
            out[k]["grade"] = bloat_grade(out[k]["added_p95_ms"])
    return out


def bloat_grade(added_ms: float) -> str:
    """Latency added under load. Same spirit as common bufferbloat graders."""
    if added_ms < 5:
        return "A+"
    if added_ms < 30:
        return "A"
    if added_ms < 60:
        return "B"
    if added_ms < 200:
        return "C"
    if added_ms < 400:
        return "D"
    return "F"


def throughput() -> Dict[str, Any]:
    """Apple's networkQuality on macOS (down/up/responsiveness), else None."""
    if not (MAC and shutil.which("networkQuality")):
        return {"error": "networkQuality not available (macOS only); skipped"}
    out = run(["networkQuality", "-c"], timeout=90)
    try:
        d = json.loads(out)
    except ValueError:
        return {"error": "networkQuality failed"}
    return {k: v for k, v in {
        "down_mbps": round(d.get("dl_throughput", 0) / 1e6, 1) or None,
        "up_mbps": round(d.get("ul_throughput", 0) / 1e6, 1) or None,
        "responsiveness_rpm": d.get("responsiveness") or d.get("dl_responsiveness"),
        "base_rtt_ms": d.get("base_rtt"),
    }.items() if v is not None}


# ---------------------------------------------------------------------------------------------
# MTU
# ---------------------------------------------------------------------------------------------
def _df_ping(host: str, payload: int) -> bool:
    if MAC:
        cmd = ["ping", "-D", "-c", "1", "-t", "2", "-s", str(payload), host]
    else:
        cmd = ["ping", "-M", "do", "-c", "1", "-W", "2", "-s", str(payload), host]
    out = run(cmd, timeout=6)
    return bool(re.search(r"bytes from", out))


def path_mtu(host: str = "1.1.1.1") -> Dict[str, Any]:
    """Largest unfragmented IPv4 packet to host (payload + 28 bytes of headers), via binary search."""
    if not shutil.which("ping"):
        return {"error": "ping not available"}
    if not _df_ping(host, 1172):
        return {"error": f"no reply from {host} even at 1200 bytes (ICMP blocked?)"}
    lo, hi = 1172, 1472
    if _df_ping(host, hi):
        return {"mtu": 1500, "target": host}
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _df_ping(host, mid):
            lo = mid
        else:
            hi = mid
    return {"mtu": lo + 28, "target": host}


# ---------------------------------------------------------------------------------------------
# Wi-Fi
# ---------------------------------------------------------------------------------------------
def wifi() -> Dict[str, Any]:
    if MAC:
        return _wifi_macos()
    if LINUX:
        return _wifi_linux()
    return {"error": "Wi-Fi details are supported on macOS and Linux"}


def _wifi_macos() -> Dict[str, Any]:
    out = run(["system_profiler", "SPAirPortDataType", "-json"], timeout=40)
    try:
        d = json.loads(out)["SPAirPortDataType"][0]
    except (ValueError, KeyError, IndexError):
        return {"error": "system_profiler gave no Wi-Fi data"}
    ifaces = d.get("spairport_airport_interfaces", [])
    cur = next((i for i in ifaces if i.get("spairport_current_network_information")), None)
    if not cur:
        return {"connected": False}
    c = cur["spairport_current_network_information"]
    sn = c.get("spairport_signal_noise", "")
    m = re.search(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)", sn)
    rssi, noise = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    chan = str(c.get("spairport_network_channel", ""))
    cm = re.match(r"(\d+)\s*\(([^,]+),\s*([^)]+)\)", chan)
    ch_num = int(cm.group(1)) if cm else None
    out_d: Dict[str, Any] = {
        "connected": True, "interface": cur.get("_name"),
        "rssi_dbm": rssi, "noise_dbm": noise, "snr_db": (rssi - noise) if rssi is not None and noise is not None else None,
        "channel": ch_num, "band": cm.group(2).strip() if cm else None, "width": cm.group(3).strip() if cm else None,
        "phy_mode": c.get("spairport_network_phymode"), "tx_rate_mbps": c.get("spairport_network_rate"),
        "security": c.get("spairport_security_mode", "").replace("spairport_security_mode_", "") or None,
        "mcs": c.get("spairport_network_mcs"),
    }
    neigh = []
    for n in cur.get("spairport_airport_other_local_wireless_networks", []):
        nm = re.match(r"(\d+)\s*\(([^,]+)", str(n.get("spairport_network_channel", "")))
        sm = re.search(r"(-?\d+)\s*dBm", str(n.get("spairport_signal_noise", "")))
        if nm:
            neigh.append({"channel": int(nm.group(1)), "band": nm.group(2).strip(), "rssi_dbm": int(sm.group(1)) if sm else None})
    out_d["neighbors"] = neigh
    out_d.update(_congestion(ch_num, out_d.get("band"), neigh))
    return {k: v for k, v in out_d.items() if v is not None}


def _wifi_linux() -> Dict[str, Any]:
    iface = default_route().get("interface")
    if not iface or interface_medium(iface) != "wifi":
        devs = re.findall(r"Interface (\S+)", run(["iw", "dev"])) if shutil.which("iw") else []
        iface = devs[0] if devs else None
    if not iface:
        return {"connected": False}
    out_d: Dict[str, Any] = {"interface": iface}
    if shutil.which("iw"):
        link = run(["iw", "dev", iface, "link"])
        if "Not connected" in link:
            return {"connected": False, "interface": iface}
        m = re.search(r"signal:\s*(-?\d+)", link)
        out_d["rssi_dbm"] = int(m.group(1)) if m else None
        m = re.search(r"freq:\s*(\d+)", link)
        if m:
            f = int(m.group(1))
            out_d["band"] = "2.4GHz" if f < 3000 else ("5GHz" if f < 5925 else "6GHz")
            out_d["channel"] = (f - 2407) // 5 if f < 3000 else (f - 5000) // 5
        m = re.search(r"tx bitrate:\s*([\d.]+) MBit/s(.*)", link)
        if m:
            out_d["tx_rate_mbps"] = float(m.group(1))
            w = re.search(r"(\d+)MHz", m.group(2))
            out_d["width"] = w.group(1) + "MHz" if w else "20MHz"
        out_d["connected"] = True
    neigh = []
    if shutil.which("nmcli"):
        for line in run(["nmcli", "-t", "-f", "CHAN,SIGNAL,IN-USE", "dev", "wifi", "list"]).splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[0].isdigit() and parts[-1] != "*":
                ch = int(parts[0])
                # nmcli SIGNAL is 0-100; rough dBm conversion for overlap scoring only
                neigh.append({"channel": ch, "band": "2.4GHz" if ch <= 14 else "5GHz",
                              "rssi_dbm": int(int(parts[1]) / 2 - 100) if parts[1].isdigit() else None})
    out_d["neighbors"] = neigh
    out_d.update(_congestion(out_d.get("channel"), out_d.get("band"), neigh))
    return {k: v for k, v in out_d.items() if v is not None}


def _congestion(ch: Optional[int], band: Optional[str], neigh: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not ch:
        return {}
    if ch <= 14:
        same = [n for n in neigh if n.get("band", "").startswith("2") and abs(n["channel"] - ch) < 5]
        best = None
        counts = {}
        for c in (1, 6, 11):
            counts[c] = sum(1 for n in neigh if n.get("band", "").startswith("2") and abs(n["channel"] - c) < 5
                            and (n.get("rssi_dbm") or -100) > -80)
        best = min(counts, key=lambda c: counts[c])
        return {"overlapping_networks": len(same), "strong_overlapping": sum(1 for n in same if (n.get("rssi_dbm") or -100) > -70),
                "least_busy_24ghz_channel": best, "per_channel_strong_neighbors": counts}
    same = [n for n in neigh if n["channel"] == ch]
    return {"overlapping_networks": len(same), "strong_overlapping": sum(1 for n in same if (n.get("rssi_dbm") or -100) > -70)}


def link_monitor(gateway: str, seconds: int = 60) -> Dict[str, Any]:
    """Ping the gateway 5x/s for `seconds`: dropouts and spikes on the local link (Wi-Fi or cable)."""
    r = ping_series(gateway, count=seconds * 5, interval=0.2)
    if "longest_gap" in r:
        r["dropout_s"] = round(r["longest_gap"] * 0.2, 1)
    return r
