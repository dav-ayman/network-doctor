#!/usr/bin/env python3
"""network-doctor MCP server (stdio, JSON-RPC 2.0, standard library only).

Gives Claude Desktop (as a .mcpb extension) and Claude Code (via the plugin's .mcp.json) the same tools as
netdoc.py. It runs on the user's own machine, so it can reach their router; cloud sandboxes can't.
Every tool runs the netdoc CLI in-process and returns its masked JSON.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from netdoc import __version__  # noqa: E402
from netdoc.cli import main as netdoc_main  # noqa: E402

PROTOCOL = "2025-06-18"
INSTRUCTIONS = """network-doctor measures why the internet feels bad, then (only with approval) changes router settings.
Workflow: 1) network_diagnose (quick=true first). Tell the user it briefly saturates the connection.
2) Explain the top findings with their numbers. 3) Dig deeper only where findings point (latency_under_load,
wifi_status, router_status...). 4) For a fix: router_write with apply=false shows a plan; describe it and get an
explicit yes; then call it again with apply=true (backup is automatic); re-measure; offer router_revert.
Passwords: never ask for them in chat. If a router tool says no password is stored, call router_password_setup:
it opens a terminal window where the user types it into the OS keychain. Never retry a failed login: routers lock
the admin account. demo=true uses a synthetic network (for trying the tool only, never as evidence)."""

DEMO = {"type": "boolean", "description": "Use the synthetic demo network instead of real measurements", "default": False}
HOST = {"type": "string", "description": "Router IP (default: the default gateway)"}
DRIVER = {"type": "string", "description": "Force a driver family (see router_drivers)"}
USER = {"type": "string", "description": "Router admin user (default: admin, root for OpenWrt)"}


def tool(name, description, props=None, required=None, read_only=True, destructive=False, title=None):
    t = {"name": name, "description": description,
         "inputSchema": {"type": "object", "properties": props or {}, "required": required or []},
         "annotations": {"title": title or name.replace("_", " ").capitalize(), "readOnlyHint": read_only,
                         "destructiveHint": destructive, "openWorldHint": True}}
    return t


TOOLS = [
    tool("network_diagnose",
         "Full read-only checkup: Wi-Fi, router/internet ping, DNS, call-quality probe idle vs while uploading vs "
         "while downloading (bufferbloat), MTU, and router status. Returns ranked findings with evidence and fixes. "
         "quick=true takes about 1 minute; it briefly saturates the connection unless no_load=true.",
         {"quick": {"type": "boolean", "default": True}, "no_load": {"type": "boolean", "default": False},
          "no_router": {"type": "boolean", "default": False}, "demo": DEMO, "host": HOST, "driver": DRIVER},
         title="Diagnose network"),
    tool("latency_under_load", "Call-quality probe idle, while uploading and while downloading. Grades bufferbloat "
         "A+ to F and reports the share of voice packets arriving too late.",
         {"seconds": {"type": "number", "default": 10}, "demo": DEMO}, title="Latency under load"),
    tool("call_quality", "UDP STUN probe at 10 packets/s on the path calls use: loss, jitter, p95, late packets. "
         "load='up' or 'down' runs an upload/download at the same time.",
         {"seconds": {"type": "number", "default": 15}, "load": {"type": "string", "enum": ["up", "down"]}, "demo": DEMO}),
    tool("wifi_status", "Wi-Fi link: RSSI, SNR, channel, width, PHY rate, neighbouring networks and the least busy 2.4 GHz channel.",
         {"demo": DEMO}),
    tool("link_monitor", "Ping the router 5x/s to catch Wi-Fi dropouts and spikes.",
         {"seconds": {"type": "integer", "default": 60}, "host": HOST, "demo": DEMO}),
    tool("path_mtu", "Largest unfragmented packet to the internet (PPPoE/VPN black holes).", {"target": {"type": "string"}, "demo": DEMO}),
    tool("dns_check", "DNS servers in use and lookup times.", {"demo": DEMO}),
    tool("router_detect", "Identify the router behind the gateway with read-only requests (no login).", {"host": HOST, "demo": DEMO}),
    tool("router_drivers", "List supported router families, their tier (verified/experimental) and lockout behaviour."),
    tool("router_status", "Normalized router status: info, cellular (4G/5G RSRP/RSRQ/SINR/band), WAN, Wi-Fi, clients, "
         "extras (QoS/SQM). Logs in with the stored password if needed.",
         {"host": HOST, "driver": DRIVER, "user": USER, "demo": DEMO,
          "sections": {"type": "array", "items": {"type": "string", "enum": ["info", "cellular", "wan", "wifi", "clients", "extras"]}}}),
    tool("router_get", "Read one raw router API object (target format depends on the driver; see router_drivers).",
         {"target": {"type": "string"}, "host": HOST, "driver": DRIVER, "user": USER, "demo": DEMO}, required=["target"]),
    tool("router_write",
         "Change router settings. apply=false (default) only returns a plan with current and new values. Show the plan "
         "to the user and get an explicit yes BEFORE calling again with apply=true. A backup is saved automatically and "
         "the result says how to revert. Wi-Fi changes briefly disconnect devices.",
         {"target": {"type": "string"}, "fields": {"type": "object", "additionalProperties": {"type": "string"}},
          "apply": {"type": "boolean", "default": False}, "host": HOST, "driver": DRIVER, "user": USER, "demo": DEMO},
         required=["target", "fields"], read_only=False, destructive=True, title="Change router settings"),
    tool("router_revert", "Restore the values saved in a backup file from router_write. apply=false shows what would be restored.",
         {"backup_file": {"type": "string"}, "apply": {"type": "boolean", "default": False}},
         required=["backup_file"], read_only=False, destructive=True),
    tool("router_password_setup",
         "Open a terminal window on the user's computer where they type the router admin password into the OS keychain "
         "(tied to this router). The password never passes through the chat or this server.",
         {"host": HOST, "user": USER}, read_only=False, title="Store router password"),
    tool("router_unblock", "Allow logins again after the router rejected the stored password. Only after the user re-saved it.",
         {"host": HOST, "user": USER}, read_only=False),
    tool("router_capture", "Masked snapshot of the router's web API (no secrets, MACs, SSIDs or public IPs) for an "
         "'Add my router' issue. Saves a JSON file and returns its path.", {"host": HOST, "driver": DRIVER}),
]


def argv_for(name, a):
    def common(router=False):
        out = []
        if a.get("demo"):
            out.append("--demo")
        if a.get("host"):
            out += ["--host", str(a["host"])]
        if router and a.get("driver"):
            out += ["--driver", str(a["driver"])]
        if router and a.get("user"):
            out += ["--user", str(a["user"])]
        return out

    if name == "network_diagnose":
        v = ["diagnose", "--json"] + common(True)
        if a.get("quick", True):
            v.append("--quick")
        if a.get("no_load"):
            v.append("--no-load")
        if a.get("no_router"):
            v.append("--no-router")
        return v
    if name == "latency_under_load":
        return ["bloat", "--seconds", str(a.get("seconds", 10))] + common()
    if name == "call_quality":
        v = ["call", "--seconds", str(a.get("seconds", 15))] + common()
        return v + (["--load", a["load"]] if a.get("load") else [])
    if name == "wifi_status":
        return ["wifi"] + common()
    if name == "link_monitor":
        return ["link", "--seconds", str(int(a.get("seconds", 60)))] + common()
    if name == "path_mtu":
        return ["mtu"] + ([a["target"]] if a.get("target") else []) + common()
    if name == "dns_check":
        return ["dns"] + common()
    if name == "router_detect":
        return ["router", "detect"] + common(True)
    if name == "router_drivers":
        return ["router", "drivers"]
    if name == "router_status":
        v = ["router", "status"] + common(True)
        for s in a.get("sections") or []:
            v += ["--section", s]
        return v
    if name == "router_get":
        return ["router", "get", str(a["target"])] + common(True)
    if name == "router_write":
        fields = a.get("fields") or {}
        if not fields:
            raise ValueError("fields must name at least one setting")
        v = ["router", "write", str(a["target"])] + [f"{k}={v}" for k, v in fields.items()] + common(True)
        return v + (["--apply"] if a.get("apply") else [])
    if name == "router_revert":
        return ["router", "revert", str(a["backup_file"])] + (["--apply"] if a.get("apply") else [])
    if name == "router_unblock":
        return ["router", "unblock"] + common(True)
    if name == "router_capture":
        return ["capture"] + common(True)
    raise KeyError(name)


def open_password_terminal(a):
    host = a.get("host")
    if not host:
        from netdoc.probes import default_route
        host = default_route().get("gateway")
    if not host:
        return {"error": "no default gateway; pass host"}
    cmd = f"python3 '{os.path.join(HERE, 'netdoc.py')}' secret set {host}" + (f" --user {a['user']}" if a.get("user") else "")
    if sys.platform == "darwin":
        script = f'tell application "Terminal" to activate\ntell application "Terminal" to do script "{cmd}"'
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=15)
        return {"opened": "Terminal", "host": host,
                "tell_user": "A Terminal window opened. Type the router admin password there (twice, it stays hidden), "
                             "then come back and say done."}
    for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xterm"):
        if shutil.which(term):
            args = [term, "--", "bash", "-c", cmd + "; read -p 'Done. Press Enter to close.'"] if term == "gnome-terminal" \
                else [term, "-e", f"bash -c \"{cmd}; read -p 'Done. Press Enter to close.'\""]
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"opened": term, "host": host, "tell_user": "Type the router password in the terminal window that opened."}
    return {"error": "no terminal found", "tell_user": f"Run this in a terminal yourself: {cmd}"}


_lock = threading.Lock()


def call_tool(name, a):
    if name == "router_password_setup":
        return json.dumps(open_password_terminal(a), indent=1), False
    argv = argv_for(name, a)
    buf = io.StringIO()
    with _lock, contextlib.redirect_stdout(buf):
        try:
            code = netdoc_main(argv)
        except SystemExit as e:  # argparse errors
            code = e.code if isinstance(e.code, int) else 2
    text = buf.getvalue().strip() or json.dumps({"exit_code": code})
    return text, bool(code)


def respond(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.__stdout__.write(json.dumps(out) + "\n")
    sys.__stdout__.flush()


def handle(msg):
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if mid is None:  # notification
        return
    if method == "initialize":
        respond(mid, {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "network-doctor", "version": __version__},
                      "instructions": INSTRUCTIONS})
    elif method == "ping":
        respond(mid, {})
    elif method == "tools/list":
        respond(mid, {"tools": TOOLS})
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {t["name"] for t in TOOLS}:
            respond(mid, error={"code": -32602, "message": f"unknown tool {name}"})
            return
        try:
            text, is_error = call_tool(name, args)
        except Exception as e:
            text, is_error = json.dumps({"error": type(e).__name__, "message": str(e)}), True
        respond(mid, {"content": [{"type": "text", "text": text}], "isError": is_error})
    elif method in ("resources/list", "prompts/list"):
        respond(mid, {"resources": []} if method.startswith("resources") else {"prompts": []})
    else:
        respond(mid, error={"code": -32601, "message": f"method not found: {method}"})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            respond(None, error={"code": -32700, "message": "parse error"})
            continue
        for m in msg if isinstance(msg, list) else [msg]:
            handle(m)


if __name__ == "__main__":
    main()
