---
name: network-doctor
description: Diagnose bad internet end to end and fix it at the router. Use when the user says their internet, Wi-Fi or connection is slow, laggy, dropping, unstable, or that their voice or video breaks up in calls (Zoom, Teams, Meet, Discord, gaming), or asks about bufferbloat, latency, packet loss, jitter, MTU, DNS, Wi-Fi channels or signal, 4G/5G/LTE signal (RSRP, SINR, band), or wants to read or change settings on a home router, MiFi or 5G CPE (Huawei, ZTE, TP-Link, ASUS, FRITZ!Box, MikroTik, OpenWrt).
---

# network-doctor

Measure first, explain with evidence, then propose fixes. Only change router settings after the user approves the exact change.

All tools are in one CLI, `scripts/netdoc.py`, relative to this skill's directory. It needs Python 3.9+ and nothing else. Run it as `python3 <skill-dir>/scripts/netdoc.py <command>`. Commands print JSON. `diagnose` prints a report, or JSON with `--json`.

## Triage flow

1. **Full checkup**: `netdoc.py diagnose --json`.
   - Takes about 2 minutes and uses bandwidth for about 45 s.
   - `--quick` takes about 1 minute. `--no-load` skips the bandwidth test.
   - It measures:
     - the route and medium;
     - Wi-Fi (RSSI, SNR, channel, neighbours);
     - router and internet ping;
     - DNS;
     - a **call-quality probe** (UDP STUN, 10 packets/s, the same path a call uses): idle, then during an upload, then during a download;
     - MTU;
     - router identity, plus read-only router status if a password is stored.
   - Tell the user it will briefly saturate their connection. Run it while they aren't in a call, unless they want to catch the problem live.
2. **Read `findings`** (most severe first). Each has `evidence` and `fix`. Explain the top 1-3 in plain words, with the numbers.
3. **Dig deeper only where the findings point.** Load the matching reference:
   - Calls break up, or latency spikes under load: [references/latency-under-load.md](references/latency-under-load.md) and [references/calls-voip.md](references/calls-voip.md)
   - Wi-Fi weak, crowded or dropping: [references/wifi.md](references/wifi.md). `netdoc.py link --seconds 120` watches for dropouts.
   - 4G/5G MiFi or CPE: [references/cellular.md](references/cellular.md)
   - Some sites hang, or VPN or PPPoE is in use: [references/mtu.md](references/mtu.md)
   - Any router read or change: [references/router-safety.md](references/router-safety.md). **Read it before the first router command.**
4. **Fix**: propose the smallest change with the biggest impact, apply it only after approval (see below), then **re-run the same measurement** to show the before and after.

## Router access

- `netdoc.py router detect`: identify the router with read-only requests. No login.
- `netdoc.py secret check <ip>`: says whether a password is stored. It never prints the password.
- If no password is stored, ask the user to run this themselves: `! python3 <skill-dir>/scripts/netdoc.py secret set <ip>` (the `!` prefix runs it in their terminal). The password then goes to the OS keychain.
  - **Never ask the user to paste the password into chat.**
  - **Never put a password on a command line.**
- `netdoc.py router status [--section cellular|wifi|wan|clients|info|extras]`: normalized status.
- `netdoc.py router get <target>`: one raw API object.
- `netdoc.py router explore`: list the API views or objects (where supported).
- `netdoc.py router drivers`: supported families, with tier (verified or experimental) and lockout behaviour.

## Changing settings (strict)

1. Run `netdoc.py router write <target> key=value ...` **without** `--apply`. It prints a plan: the current values, the new values, and whether a backup is possible.
2. Show the plan to the user in plain words: what changes, the expected effect, and the risk. Wi-Fi changes disconnect devices for about 30 s. A wrong Wi-Fi setting can cut off the device you're on.
3. Only after an explicit yes, run the same command with `--apply`. It saves a backup and prints `revert_with`.
4. Re-measure. If it got worse, offer `netdoc.py router revert <backup> --apply`.
5. If the plan says `backup: false`, say so plainly. Only use `--no-backup` if the user explicitly accepts that there is no automatic undo.

## Hard rules

- **Never retry a failed login.** Routers lock the admin account after 3-10 failures, and some for hours.
  - netdoc records rejected logins and refuses the next attempts until `router unblock`.
  - Only suggest `router unblock` after the user has re-saved the correct password.
- Experimental drivers have not been confirmed on real hardware. Say so when using one, and prefer reads.
- Don't change DNS, firmware, admin passwords, remote access, port forwarding or firewall rules as a "fix" unless the user asks.
- Don't share the user's IPs, MACs, SSIDs or device names outside the conversation. `netdoc.py capture` produces a masked file meant for public issues.
- `--demo` runs on a synthetic network. Use it to show what the tool does, never as evidence about the user's network.

## Unknown router

1. Run `netdoc.py router detect`. If it finds no candidate, run `netdoc.py capture`. It writes a masked JSON file with the login page title, headers and the API paths it found.
2. Suggest the user attach that file to an "Add my router" issue: https://github.com/dav-ayman/network-doctor/issues
3. Meanwhile, give generic advice based on the measurements. Guide the user through the router's web UI by describing where the setting usually lives. See [references/adding-a-router.md](references/adding-a-router.md).
