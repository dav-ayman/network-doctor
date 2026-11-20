# Calls breaking up (Zoom, Teams, Meet, WhatsApp, Discord)

## Typical causes, most common first

1. **Latency under load from other traffic.** See latency-under-load.md. The symptom is that it's fine most of the time, then the voice breaks when someone else streams or a sync starts.
2. **Wi-Fi retries, power saving or roaming.** The symptoms are spikes on the *router* ping and gaps in `netdoc.py link`.
3. **Cellular radio quality.**
   - Low SINR causes retransmissions on the uplink. The listener hears your voice breaking, while you hear them fine.
   - The 5G NSA "LTE anchor" matters too: a poor LTE leg hurts even with good 5G numbers.
4. **Packet loss beyond the router** (the ISP). The router ping is clean while internet ping and call-probe loss are not.
5. **VPN** adding MTU problems or a far exit.
6. **CPU or app**: a busy laptop, or a browser tab doing the call. Rule this out by testing on another device.

## Probe
`netdoc.py call --seconds 30` sends UDP STUN binding requests to Google/Cloudflare STUN servers at 10 packets/s. Google's servers sit on the ports Meet uses. It reports:
- `loss_pct`
- `p95_ms`
- `jitter_ms`: mean change between consecutive RTTs
- `late_pct`: share of packets over 150 ms
- `longest_gap`: consecutive losses, where 5 equals 0.5 s of silence

`netdoc.py call --load up` repeats the probe while uploading, which reproduces "my voice breaks when I share my screen".

## What to tell the user
- Lead with one number: "while something uploads, X% of your voice packets arrive too late to be played".
- Then the cause, then one fix.
- Re-measure after the fix and show the change.

## Quick mitigations while waiting for a real fix
- Turn off video, or lower outgoing video quality. In Zoom: Settings > Video, untick HD. Teams and Meet adapt automatically, but the upload drops faster with video off.
- Pause cloud sync: iCloud Photos, Google Drive, OneDrive, Dropbox, and backup tools.
- Move closer to the access point, or plug in Ethernet.
- On cellular, put the router by a window. See cellular.md.
