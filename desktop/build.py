#!/usr/bin/env python3
"""Build the Claude Desktop extension: dist/network-doctor-<version>.mcpb

An .mcpb file is a zip with manifest.json at its root (MCP Bundle format). This bundles the stdlib-only
MCP server and the netdoc package; nothing to install besides Python 3.9+ on the user's machine.

Usage (repo root):  python3 desktop/build.py
"""
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "network-doctor", "skills", "network-doctor", "scripts")
sys.path.insert(0, SCRIPTS)

from netdoc import __version__  # noqa: E402
import netdoc_mcp  # noqa: E402

REPO = "https://github.com/dav-ayman/network-doctor"


def manifest() -> dict:
    return {
        "manifest_version": "0.2",
        "name": "network-doctor",
        "display_name": "Network Doctor",
        "version": __version__,
        "description": "Find out why your internet feels bad (Wi-Fi, bufferbloat, call quality, 4G/5G signal) and fix it at the router.",
        "long_description": (
            "Runs on your computer, so Claude can measure your real network: Wi-Fi signal and channel, latency while "
            "the line is busy (the usual reason calls break up), a voice-like UDP probe, MTU and DNS. It can read your "
            "router (Huawei, ZTE, TP-Link, ASUS, FRITZ!Box, MikroTik, OpenWrt) including 4G/5G signal, and change "
            "settings only after you approve a plan, with an automatic backup. Router passwords are typed into your "
            "OS keychain in a terminal window, never into the chat. Needs Python 3.9+ (macOS: installed with the "
            "Xcode command line tools)."),
        "author": {"name": "dav-ayman", "url": "https://github.com/dav-ayman"},
        "repository": {"type": "git", "url": REPO},
        "homepage": REPO,
        "documentation": REPO + "#readme",
        "support": REPO + "/issues",
        "icon": "icon.png",
        "server": {
            "type": "python",
            "entry_point": "server/netdoc_mcp.py",
            "mcp_config": {"command": "python3", "args": ["${__dirname}/server/netdoc_mcp.py"], "env": {}},
        },
        "tools": [{"name": t["name"], "description": t["description"]} for t in netdoc_mcp.TOOLS],
        "keywords": ["network", "wifi", "router", "bufferbloat", "latency", "voip", "5g", "lte", "diagnostics"],
        "license": "MIT",
        "compatibility": {"platforms": ["darwin", "linux"], "runtimes": {"python": ">=3.9"}},
    }


def main() -> None:
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    out = os.path.join(dist, f"network-doctor-{__version__}.mcpb")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest(), indent=2))
        z.write(os.path.join(ROOT, "desktop", "icon.png"), "icon.png")
        z.write(os.path.join(ROOT, "LICENSE"), "LICENSE")
        for base, dirs, files in os.walk(SCRIPTS):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in sorted(files):
                if f.endswith(".py"):
                    full = os.path.join(base, f)
                    z.write(full, os.path.join("server", os.path.relpath(full, SCRIPTS)))
    print(out)


if __name__ == "__main__":
    main()
