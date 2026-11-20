"""--demo: a synthetic network (5G CPE with bufferbloat, crowded 2.4 GHz Wi-Fi) so anyone can try the skill,
and so docs/videos never contain real data. All values are made up."""
from __future__ import annotations

import sys
import time
from typing import Any, Dict, List, Optional

from .drivers.base import Driver

SCENARIO: Dict[str, Any] = {
    "route": {"gateway": "192.168.8.1", "interface": "en0", "medium": "wifi"},
    "dns_servers": ["192.168.8.1"],
    "wifi": {"connected": True, "interface": "en0", "rssi_dbm": -67, "noise_dbm": -90, "snr_db": 23, "channel": 11,
             "band": "2GHz", "width": "40MHz", "phy_mode": "802.11n", "tx_rate_mbps": 72, "security": "wpa2_personal",
             "overlapping_networks": 9, "strong_overlapping": 4, "least_busy_24ghz_channel": 1,
             "per_channel_strong_neighbors": {"1": 0, "6": 2, "11": 4}},
    "gateway_ping": {"target": "192.168.8.1", "sent": 50, "loss_pct": 0.0, "avg_ms": 6.1, "p50_ms": 4.2, "p95_ms": 21.0,
                     "max_ms": 48.3, "jitter_ms": 4.4, "late_pct": 0.0, "longest_gap": 0},
    "internet_ping": {"target": "1.1.1.1", "sent": 50, "loss_pct": 0.0, "avg_ms": 41.7, "p50_ms": 38.0, "p95_ms": 66.0,
                      "max_ms": 92.1, "jitter_ms": 7.9, "late_pct": 0.0, "longest_gap": 0},
    "dns": {"per_name_ms": {"www.google.com": 24, "zoom.us": 31, "teams.microsoft.com": 44, "meet.google.com": 22},
            "max_ms": 44, "failures": 0},
    "mtu": {"mtu": 1500, "target": "1.1.1.1"},
    "throughput": {"down_mbps": 182.4, "up_mbps": 41.3, "responsiveness_rpm": 212},
    "load": {
        "idle": {"target": "stun", "sent": 150, "loss_pct": 0.0, "avg_ms": 44.0, "p50_ms": 41.0, "p95_ms": 63.0,
                 "max_ms": 120.0, "jitter_ms": 5.1, "late_pct": 0.7, "longest_gap": 0},
        "upload": {"target": "stun", "sent": 150, "loss_pct": 3.3, "avg_ms": 388.0, "p50_ms": 362.0, "p95_ms": 702.0,
                   "max_ms": 1210.0, "jitter_ms": 61.0, "late_pct": 61.3, "longest_gap": 3, "added_p95_ms": 639.0,
                   "grade": "F", "load": {"method": "demo", "throughput_mbps": 40.8}},
        "download": {"target": "stun", "sent": 150, "loss_pct": 0.7, "avg_ms": 151.0, "p50_ms": 140.0, "p95_ms": 245.0,
                     "max_ms": 402.0, "jitter_ms": 18.0, "late_pct": 38.0, "longest_gap": 1, "added_p95_ms": 182.0,
                     "grade": "C", "load": {"method": "demo", "throughput_mbps": 176.0}},
    },
}


class DemoRouter(Driver):
    family = "demo"
    name = "Demo 5G CPE (synthetic)"
    vendor = "Demo"
    tier = "verified"
    models = "synthetic device for --demo"
    lockout = "none (not a real router)"
    can_write = True
    can_revert = True
    write_targets = "wifi.2g / wifi.5g (channel, width, enabled) or /api/net/net-mode; nothing is sent anywhere"

    def __init__(self, base: str = "http://192.168.8.1", *a: Any, **kw: Any):
        super().__init__(base, *a, **kw)
        self.state = {
            "/api/net/net-mode": {"NetworkMode": "00", "NetworkBand": "3FFFFFFF", "LTEBand": "7FFFFFFFFFFFFFFF"},
            "wifi.2g": {"channel": "11", "width": "40MHz", "enabled": "1", "ssid": "DemoHome"},
            "wifi.5g": {"channel": "auto", "width": "80MHz", "enabled": "0", "ssid": "DemoHome-5G"},
        }

    def login(self) -> None:
        self.logged_in = True

    def info(self) -> Dict[str, Any]:
        return {"vendor": "Demo", "model": "5G CPE (demo)", "firmware": "1.0.0-demo", "uptime_s": 302400}

    def cellular(self) -> Optional[Dict[str, Any]]:
        return {"operator": "DemoTel", "connected": True, "generation": "5G", "mode": "NSA: LTE anchor + 5G NR",
                "bars": 4, "max_bars": 5, "rsrp": -104.0, "rsrq": -14.0, "sinr": -1.0, "rssi": -71.0, "band": "B3",
                "nr": {"rsrp": -96.0, "rsrq": -11.0, "sinr": 15.0, "band": "n78"},
                "month_rx": 412_000_000_000, "month_tx": 38_000_000_000}

    def wan(self) -> Dict[str, Any]:
        return {"type": "cellular", "connected": True, "ip": "10.64.0.12", "now_down_bps": 1_200_000, "now_up_bps": 38_500_000}

    def wifi(self) -> List[Dict[str, Any]]:
        out = []
        for key, band in (("wifi.2g", "2.4GHz"), ("wifi.5g", "5GHz")):
            w = self.state[key]
            out.append({"radio": key, "band": band, "ssid": w["ssid"], "enabled": w["enabled"] == "1",
                        "channel": w["channel"], "width": w["width"]})
        return out

    def clients(self) -> List[Dict[str, Any]]:
        return [{"name": "laptop", "ip": "192.168.8.100", "mac": "02:00:00:00:00:01"},
                {"name": "phone", "ip": "192.168.8.101", "mac": "02:00:00:00:00:02"},
                {"name": "tv", "ip": "192.168.8.102", "mac": "02:00:00:00:00:03"}]

    def extras(self) -> Dict[str, Any]:
        return {"net_mode": self.state["/api/net/net-mode"], "qos": "not available", "sqm": "not available"}

    def raw_get(self, target: str) -> Any:
        return self.state.get(target, {})

    def current(self, target: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        from .drivers.base import NotSupported
        cur = self.state.get(target)
        if cur is None:
            raise NotSupported(f"unknown demo target {target}; use one of {sorted(self.state)}")
        missing = [k for k in fields if k not in cur]
        if missing:
            raise NotSupported(f"{target} has no {missing}; fields are {sorted(cur)}")
        return {k: cur[k] for k in fields}

    def raw_set(self, target: str, fields: Dict[str, Any]) -> Any:
        self.state.setdefault(target, {}).update({k: str(v) for k, v in fields.items()})
        return "OK"


def pace(label: str, seconds: float) -> None:
    """Show progress like a real run, so recordings look natural (stderr, not part of JSON output)."""
    if not sys.stderr.isatty():
        return
    sys.stderr.write(f"  {label} ")
    sys.stderr.flush()
    steps = max(1, int(seconds * 4))
    for _ in range(steps):
        time.sleep(seconds / steps)
        sys.stderr.write(".")
        sys.stderr.flush()
    sys.stderr.write(" done\n")
