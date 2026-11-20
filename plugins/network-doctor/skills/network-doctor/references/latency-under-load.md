# Latency under load (bufferbloat)

## What it is
A router or modem with oversized buffers queues packets when the link is full. Every packet behind the queue, including voice, waits for it to drain. Idle ping looks fine, but the moment anything uploads (cloud backup, photo sync, a video call's own screen share) or downloads (updates, streaming), latency jumps from 20-60 ms to 300-3000 ms.

**Upload is usually the worse direction.** Uplinks are smaller, and on cellular the modem's own buffer is huge.

## How netdoc measures it
`netdoc.py bloat`, or the `load` section of `diagnose`, runs the call probe in three phases:
- idle;
- while saturating upload. On macOS this uses `networkQuality -d`, where `-d` means "no download test", so it's an upload-only load.
- while saturating download (`networkQuality -u`).

Without networkQuality it falls back to parallel HTTPS streams to speed.cloudflare.com. Cloudflare throttles repeated large uploads from one client, so a low upload number on a re-run can be that throttle rather than the line. Prefer `networkQuality` where it's available.

| added p95 latency | grade | effect on calls |
|---|---|---|
| < 5 ms | A+ | none |
| < 30 ms | A | none |
| < 60 ms | B | rare glitches |
| < 200 ms | C | noticeable, choppy when something syncs |
| < 400 ms | D | voice breaks up |
| >= 400 ms | F | robotic audio, freezes, drops |

`late_pct` is the share of probe packets that arrived later than 150 ms. That's roughly what a jitter buffer can absorb. **Above 3-5%, people hear it.**

## Fixes, best first
1. **SQM / Smart Queue Management** (fq_codel or cake), shaped to about 85-90% of the measured speed in each direction. This is the real fix.
   - OpenWrt: install `luci-app-sqm`.
   - Asuswrt-Merlin: Adaptive QoS / cake.
   - MikroTik: a queue tree with the cake type.
   - FRITZ!Box: has built-in prioritisation, which helps somewhat.
   - Most ISP routers and MiFis have nothing equivalent.
2. **Bandwidth cap (QoS limiter) below the link speed.** It moves the queue from the modem to a device you control.
   - Example: a ZTE H188A used as an access point can attach a shaper to its LAN port. That caps upload from everything behind it.
   - It can't shape Wi-Fi downloads.
3. **Put a router with SQM behind the ISP box**, and set the ISP box to bridge mode or use it as an AP. On 5G/LTE CPEs this is often the only option.
4. **Behavioural**: pause cloud backup and photo sync during calls, and schedule big uploads overnight.
5. **Wired Ethernet for the call machine.** It doesn't fix bloat at the modem, but it removes Wi-Fi contention and retries from the picture.

## Verify
Re-run `netdoc.py bloat` after the change. Show the user the before and after p95 and late_pct for upload and download.
