# MTU

`netdoc.py mtu [host]` finds the largest IPv4 packet that crosses the path without fragmenting. It does a binary search with DF pings, and reports the MTU (payload + 28 bytes of headers).

| result | usual reason |
|---|---|
| 1500 | normal Ethernet / most fibre and cable |
| 1492 | PPPoE (DSL, many fibre ISPs) |
| 1420-1480 | VPN (WireGuard 1420, IPsec ~1400-1438), some cellular |
| < 1400 | stacked tunnels, broken PMTUD |

## When it matters
These are the symptoms of an MTU "black hole": ICMP is blocked, so the endpoints never learn the smaller size.
- Some websites hang on loading while others work.
- A VPN connects, but large transfers stall.
- Video calls connect, but screen share freezes.

## Fixes
- Set the router's WAN MTU, or the VPN interface MTU, to the measured value. Or enable MSS clamping (OpenWrt firewall zone `mtu_fix=1`; MikroTik `change-mss` mangle rule).
- On a single machine, set the interface MTU to the measured value for a quick test.
