# Router safety rules

Read these before the first `router` command in a session.

## Passwords
- They come from the OS keychain (service `network-doctor`, account `<user>@<router-ip>`) or the `NETDOC_PASSWORD` env var. Nowhere else.
- A stored password is tied to the router's MAC address. If the gateway is a different device (another network, a replaced router), netdoc refuses with a "not the router this password was saved for" message. Tell the user to run `secret set` again, and only if this really is their router.
- The user stores one with `! python3 <skill-dir>/scripts/netdoc.py secret set <ip> [--user name]`. They type it into a hidden prompt.
- Never ask for the password in chat. Never put it on a command line or in a file. Never echo it.
- All netdoc output passes through a masking filter. Passwords, keys, tokens, IMEI/IMSI/ICCID and serial numbers come out as `<hidden>`.

## Lockouts
- A rejected login is recorded in `~/.network-doctor/login-guard.json`. Every later attempt to that router is refused without contacting it.
- Clear it with `netdoc.py router unblock`, and only after the user has re-saved the right password.
- `LoginBusy` (another session is logged in) is transient. Tell the user to close the router page in their browser, or wait a few minutes.
- Never loop or retry logins yourself.

## Writes
1. Read first: `router get <target>` or `router status`. Decide on the smallest change.
2. `router write <target> k=v ...` without `--apply`. This is the plan.
3. Explain it to the user: what changes, the impact, any disconnect, and how to undo it. Get an explicit yes.
4. `--apply`. This saves `~/.network-doctor/backups/<driver>-<ip>-<time>.json` and prints `revert_with`.
5. Re-measure. Offer to revert if it isn't better.

Changes that can lock the user out, so warn twice and suggest they have another way in (Ethernet, or the router's other band):
- Wi-Fi security, SSID or password.
- Disabling the radio they're using.
- LAN IP / DHCP.
- Cellular band locks and network-mode changes.

Never change these as part of a "fix" unless the user asks: admin password, firmware, remote management, port forwarding, firewall/DMZ, DNS hijack settings, factory reset.

## Tiers
- **verified**: a maintainer has tested the driver on real hardware: Huawei HiLink 5G CPE, ZTE U20 MiFi, ZTE ZXHN H188A and Huawei HG630 V2.
- **experimental**: written from public protocol documentation, and only tested against synthetic answers. Say "experimental" to the user, prefer reads, and if anything looks off, stop and suggest `capture` plus an issue.
