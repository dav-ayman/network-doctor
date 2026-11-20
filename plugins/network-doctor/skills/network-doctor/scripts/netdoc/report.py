"""Turn measurements into ranked findings with evidence and fixes, and render them for a terminal."""
from __future__ import annotations

import shutil
import textwrap
from typing import Any, Dict, List, Optional

from .radio import rsrp_label, sinr_label, wifi_rssi_label

SEV = {"critical": 3, "warning": 2, "info": 1, "ok": 0}


def finding(sev: str, area: str, title: str, evidence: str, fix: str = "", impact: str = "") -> Dict[str, str]:
    return {k: v for k, v in {"severity": sev, "area": area, "title": title, "evidence": evidence, "fix": fix,
                              "impact": impact}.items() if v}


def analyze(r: Dict[str, Any]) -> List[Dict[str, str]]:
    """r is the dict produced by diagnose(): route, wifi, gateway_ping, internet_ping, load, mtu, dns, router."""
    f: List[Dict[str, str]] = []
    route = r.get("route") or {}
    wifi = r.get("wifi") or {}
    gw = r.get("gateway_ping") or {}
    inet = r.get("internet_ping") or {}
    load = r.get("load") or {}
    router = r.get("router") or {}
    cell = (router.get("status") or {}).get("cellular") or {}

    # --- latency under load: the usual reason calls break -----------------------------------
    for k, name in (("upload", "uploading"), ("download", "downloading")):
        x = load.get(k) or {}
        if x.get("added_p95_ms") is None:
            continue
        added, late = x["added_p95_ms"], x.get("late_pct", 0)
        if x.get("grade") in ("D", "F") or late >= 10:
            f.append(finding(
                "critical", "bufferbloat",
                f"Latency explodes while {name} (grade {x['grade']})" if x.get("grade") in ("D", "F")
                else f"Voice packets arrive late while {name} (grade {x.get('grade')})",
                f"call probe p95 {load['idle'].get('p95_ms')} ms idle -> {x.get('p95_ms')} ms while {name} "
                f"(+{added} ms); {late}% of voice packets later than 150 ms",
                "Enable SQM / Smart Queue (fq_codel or cake) on the router, shaped to ~85-90% of the measured "
                f"{'upload' if k == 'upload' else 'download'} speed. If the router has no SQM, cap {'upload' if k == 'upload' else 'download'} "
                "with QoS bandwidth limits, or pause cloud backup/sync during calls.",
                "voice breaks up or freezes whenever anything on the network uploads/downloads"))
        elif x.get("grade") == "C" or late >= 3:
            f.append(finding("warning", "bufferbloat", f"Noticeable lag while {name} (grade {x['grade']})",
                             f"+{added} ms p95, {late}% late packets", "Same fix as above, less urgent."))
    idle = load.get("idle") or {}
    if idle.get("loss_pct", 0) >= 2:
        f.append(finding("critical", "loss", "Packet loss on an idle connection",
                         f"{idle['loss_pct']}% of call-probe packets lost with nothing else running",
                         "Check the local link first (below); if the link is clean, the loss is upstream: ISP line/cell signal."))

    # --- local link -----------------------------------------------------------------------
    if gw.get("loss_pct", 0) >= 1 or (gw.get("p95_ms") or 0) > 60 or (gw.get("longest_gap") or 0) >= 5:
        medium = route.get("medium") or "link"
        f.append(finding(
            "critical" if gw.get("loss_pct", 0) >= 3 or (gw.get("longest_gap") or 0) >= 10 else "warning",
            "local-link", f"Unstable {medium} link to the router",
            f"router ping: loss {gw.get('loss_pct')}%, p95 {gw.get('p95_ms')} ms, longest dropout "
            f"{round((gw.get('longest_gap') or 0) * 0.2, 1)} s",
            "Use Ethernet for calls if possible; otherwise see the Wi-Fi findings." if medium == "wifi"
            else "Check the cable/port; try another port or cable."))

    # --- Wi-Fi ----------------------------------------------------------------------------
    if wifi.get("connected"):
        rssi = wifi.get("rssi_dbm")
        if rssi is not None and rssi < -70:
            f.append(finding("critical" if rssi < -78 else "warning", "wifi", f"Weak Wi-Fi signal ({wifi_rssi_label(rssi)})",
                             f"RSSI {rssi} dBm, SNR {wifi.get('snr_db')} dB on channel {wifi.get('channel')} ({wifi.get('band')})",
                             "Move closer / remove obstacles, add an access point or mesh node, or use Ethernet. "
                             "On 2.4 GHz a stronger signal often beats 5 GHz through walls."))
        snr = wifi.get("snr_db")
        if snr is not None and snr < 20 and (rssi is None or rssi >= -70):
            f.append(finding("warning", "wifi", "Low Wi-Fi signal-to-noise", f"SNR {snr} dB (noise {wifi.get('noise_dbm')} dBm)",
                             "Change channel away from interference (microwaves, other networks)."))
        if wifi.get("band", "").startswith("2") and (wifi.get("strong_overlapping") or 0) >= 2:
            best = wifi.get("least_busy_24ghz_channel")
            f.append(finding("warning", "wifi", "Crowded 2.4 GHz channel",
                             f"{wifi['strong_overlapping']} strong networks overlap channel {wifi.get('channel')}",
                             f"Set the router's 2.4 GHz channel to {best} (1/6/11 only) and 20 MHz width." if best else
                             "Use channel 1, 6 or 11 with 20 MHz width."))
        if wifi.get("band", "").startswith("2") and "40" in str(wifi.get("width", "")):
            f.append(finding("warning", "wifi", "40 MHz width on 2.4 GHz",
                             f"channel width {wifi.get('width')}", "Use 20 MHz on 2.4 GHz: less interference, more stable."))

    # --- cellular -------------------------------------------------------------------------
    if cell:
        sinr, rsrp = cell.get("sinr"), cell.get("rsrp")
        if sinr is not None and sinr < 5:
            f.append(finding("critical" if sinr < 0 else "warning", "cellular", f"Poor cellular signal quality ({sinr_label(sinr)})",
                             f"LTE SINR {sinr} dB, RSRP {rsrp} dBm ({rsrp_label(rsrp)}), band {cell.get('band')}",
                             "Move the router to a window / higher floor facing the tower, try each side of the building, "
                             "or add an external antenna. Low SINR means interference, not just distance.",
                             "unstable latency and upload; the LTE anchor also carries 5G NSA control traffic"))
        elif rsrp is not None and rsrp < -105:
            f.append(finding("warning", "cellular", "Weak cellular signal", f"RSRP {rsrp} dBm",
                             "Relocate the router or use an external antenna."))
        nr = cell.get("nr") or {}
        if nr.get("sinr") is not None and nr["sinr"] < 3:
            f.append(finding("warning", "cellular", "Weak 5G (NR) quality", f"NR SINR {nr['sinr']} dB, RSRP {nr.get('rsrp')} dBm",
                             "Same placement advice; 5G bands fade faster indoors."))
        if cell.get("connected") is False:
            f.append(finding("critical", "cellular", "Router has no data connection", "router reports data disconnected",
                             "Check the SIM/plan balance and APN."))

    # --- MTU / DNS ------------------------------------------------------------------------
    mtu = (r.get("mtu") or {}).get("mtu")
    if mtu and mtu < 1400:
        f.append(finding("warning", "mtu", "Small path MTU", f"largest unfragmented packet {mtu} bytes",
                         "Usually a VPN or PPPoE/cellular overhead. If some sites hang, set the router WAN MTU to this value."))
    dns = r.get("dns") or {}
    if (dns.get("max_ms") or 0) > 300 or dns.get("failures"):
        f.append(finding("warning", "dns", "Slow or failing DNS",
                         f"slowest lookup {dns.get('max_ms')} ms, {dns.get('failures', 0)} failures; servers {', '.join(r.get('dns_servers') or [])}",
                         "Use a fast public resolver (1.1.1.1 / 8.8.8.8 / 9.9.9.9) on the router or this device."))

    # --- internet path ---------------------------------------------------------------------
    if inet.get("loss_pct", 0) >= 2 and gw.get("loss_pct", 0) < 1:
        f.append(finding("warning", "isp", "Loss beyond the router", f"internet ping loss {inet['loss_pct']}% while router ping is clean",
                         "Upstream problem: ISP line, cell signal, or congestion. Log it with timestamps and contact the ISP."))

    if not f:
        f.append(finding("ok", "summary", "No problems found in this run",
                         "local link, latency under load, DNS and MTU all look healthy",
                         "If calls still break, run again while the problem is happening."))
    return sorted(f, key=lambda x: -SEV.get(x["severity"], 0))


ICON = {"critical": "✖", "warning": "▲", "info": "•", "ok": "✔"}


def render(r: Dict[str, Any], color: bool = True) -> str:
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    col = {"critical": "31;1", "warning": "33;1", "info": "36", "ok": "32;1"}
    lines = []
    route = r.get("route") or {}
    lines.append(c("1", "network-doctor report"))
    lines.append(f"  link: {route.get('medium') or '?'} via {route.get('interface') or '?'} -> router {route.get('gateway') or '?'}")
    w = r.get("wifi") or {}
    if w.get("connected"):
        lines.append(f"  wifi: {w.get('rssi_dbm')} dBm ({wifi_rssi_label(w.get('rssi_dbm'))}), SNR {w.get('snr_db')} dB, "
                     f"ch {w.get('channel')} {w.get('band')} {w.get('width') or ''}, {w.get('tx_rate_mbps')} Mbps")
    for key, label in (("gateway_ping", "router"), ("internet_ping", "internet")):
        p = r.get(key) or {}
        if p.get("avg_ms") is not None:
            lines.append(f"  {label:8} ping avg {p['avg_ms']} ms, p95 {p['p95_ms']} ms, loss {p['loss_pct']}%")
    ld = r.get("load") or {}
    if ld.get("idle"):
        lines.append("  call probe (UDP, 10 pkt/s):")
        for k in ("idle", "upload", "download"):
            x = ld.get(k) or {}
            if x.get("p95_ms") is not None:
                g = f"  grade {x['grade']}" if x.get("grade") else ""
                lines.append(f"    {k:9} p95 {x['p95_ms']:>6} ms  late {x.get('late_pct', 0):>5}%  loss {x.get('loss_pct', 0):>4}%{g}")
    tp = r.get("throughput") or {}
    if tp.get("down_mbps"):
        lines.append(f"  speed: {tp['down_mbps']} down / {tp.get('up_mbps')} up Mbps")
    router = r.get("router") or {}
    if router.get("driver"):
        st = router.get("status") or {}
        info = st.get("info") or {}
        lines.append(f"  router: {info.get('vendor', '')} {info.get('model', '')} ({router['driver']}, {router.get('tier')})".rstrip())
        cell = st.get("cellular") or {}
        if cell:
            lines.append(f"  cellular: {cell.get('operator', '')} {cell.get('generation', '')} RSRP {cell.get('rsrp')} "
                         f"SINR {cell.get('sinr')} band {cell.get('band')}")
    lines.append("")
    lines.append(c("1", "findings (most important first)"))
    width = max(60, min(110, shutil.get_terminal_size((100, 24)).columns - 2))
    for i, x in enumerate(r.get("findings") or [], 1):
        lines.append(c(col.get(x["severity"], "0"), f" {ICON.get(x['severity'], '-')} {i}. {x['title']}"))
        for label in ("evidence", "impact", "fix"):
            if x.get(label):
                lines.extend(textwrap.wrap(x[label], width=width, initial_indent=f"     {label + ':':<10}",
                                           subsequent_indent=" " * 15))
    return "\n".join(lines)


def _bar(ms: Optional[float], scale: float = 800, width: int = 34) -> str:
    if ms is None:
        return ""
    n = max(1, min(width, int(round(ms / scale * width))))
    return "█" * n


def render_part(cmd: str, d: Any, color: bool = True) -> str:
    """Compact human view for single commands (bloat, call, wifi, router status...)."""
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    grade_col = {"A+": "32;1", "A": "32;1", "B": "33;1", "C": "33;1", "D": "31;1", "F": "31;1"}
    out: List[str] = []
    if cmd == "bloat":
        out.append(c("1", "call quality vs load  (p95 latency of a 10 pkt/s voice-like UDP stream)"))
        for k, label in (("idle", "idle       "), ("upload", "uploading  "), ("download", "downloading")):
            x = d.get(k) or {}
            if x.get("p95_ms") is None:
                continue
            g = x.get("grade")
            gcol = grade_col.get(g or "", "32")
            out.append(f"  {label} {c(gcol, _bar(x['p95_ms']).ljust(34))} {x['p95_ms']:>6.0f} ms  "
                       f"late {x.get('late_pct', 0):>4.1f}%  loss {x.get('loss_pct', 0):>3.1f}%"
                       + (f"  grade {c(gcol, g)}" if g else ""))
        worst = max((d.get(k) or {} for k in ("upload", "download")), key=lambda x: x.get("added_p95_ms") or 0)
        if (worst.get("late_pct") or 0) >= 3:
            out.append(c("31;1", f"  → {worst['late_pct']}% of voice packets arrive too late to play while the line is busy"))
        return "\n".join(out)
    if cmd == "call":
        return (f"call probe: p95 {d.get('p95_ms')} ms, jitter {d.get('jitter_ms')} ms, late {d.get('late_pct')}%, "
                f"loss {d.get('loss_pct')}%, longest gap {d.get('longest_gap')} packets")
    if cmd == "wifi":
        if not d.get("connected"):
            return "Wi-Fi: not connected"
        out.append(c("1", "Wi-Fi"))
        out.append(f"  signal   {d.get('rssi_dbm')} dBm ({wifi_rssi_label(d.get('rssi_dbm'))}), SNR {d.get('snr_db')} dB")
        out.append(f"  channel  {d.get('channel')} ({d.get('band')}, {d.get('width')}), {d.get('phy_mode')}, {d.get('tx_rate_mbps')} Mbps")
        if d.get("per_channel_strong_neighbors"):
            per = ", ".join(f"ch{k}: {v}" for k, v in d["per_channel_strong_neighbors"].items())
            out.append(f"  strong neighbours per 2.4 GHz channel: {per}  → best: {d.get('least_busy_24ghz_channel')}")
        return "\n".join(out)
    if cmd == "router":
        info = d.get("info") or {}
        out.append(c("1", f"{info.get('vendor', '')} {info.get('model', '')}".strip() or "router")
                   + f"  ({d.get('driver')}, {d.get('tier')})")
        cell = d.get("cellular") or {}
        if cell:
            mode = f" ({cell['mode']})" if cell.get("mode") else ""
            out.append(f"  network  {cell.get('operator', '')} {cell.get('generation', '')}{mode}")
            bars = int(cell.get("bars") or 0)
            out.append(f"  bars     {'▮' * bars}{'▯' * (int(cell.get('max_bars') or 5) - bars)}  {bars}/{cell.get('max_bars') or 5}")
            if cell.get("rsrp") is not None:
                out.append(f"  LTE      RSRP {cell['rsrp']:.0f} dBm ({rsrp_label(cell['rsrp'])})   "
                           f"SINR {cell.get('sinr')} dB ({c('31;1' if (cell.get('sinr') or 0) < 5 else '32', sinr_label(cell.get('sinr')))})"
                           f"   band {cell.get('band')}")
            nr = cell.get("nr") or {}
            if nr.get("rsrp") is not None:
                out.append(f"  5G NR    RSRP {nr['rsrp']:.0f} dBm ({rsrp_label(nr['rsrp'])})   "
                           f"SINR {nr.get('sinr')} dB ({sinr_label(nr.get('sinr'))})   band {nr.get('band')}")
        for w in d.get("wifi") or []:
            out.append(f"  wifi     {w.get('radio')}: {'on' if w.get('enabled') else 'off'}"
                       + (f", channel {w['channel']}" if w.get("channel") else "") + (f", {w['width']}" if w.get("width") else ""))
        if d.get("clients"):
            out.append(f"  clients  {len(d['clients'])}")
        for k, v in (d.get("errors") or {}).items():
            out.append(c("33", f"  {k}: {v}"))
        return "\n".join(out)
    import json as _json
    return _json.dumps(d, indent=1, ensure_ascii=False)
