# Wi-Fi

## Read the numbers (`netdoc.py wifi`)
| RSSI | quality |
|---|---|
| >= -55 dBm | excellent |
| -55 to -65 | good |
| -65 to -72 | fair: OK for calls if the channel is clean |
| -72 to -80 | poor: retries, rate drops, call glitches |
| < -80 | unusable for calls |

- **SNR** is RSSI minus noise. Above 25 dB is solid. Under 20 dB means trouble even with a decent RSSI.
- `strong_overlapping` counts neighbouring networks above -70 dBm that overlap your channel.
- `least_busy_24ghz_channel` picks among 1, 6 and 11 by strong-neighbour count.

Since macOS 14, SSIDs may be hidden without Location permission. That's fine: channels and RSSI are still reported.

## Fixes, best first
1. **2.4 GHz channel: only 1, 6 or 11, and 20 MHz width.** 40 MHz on 2.4 GHz overlaps almost everything and is the most common avoidable problem in apartments.
2. **Use 5 GHz when the signal allows it** (RSSI better than about -67 dBm). It's much cleaner. Some MiFis ship with 5 GHz off: ZTE U20 / MU5001 `WiFiModuleSwitch` / band settings, Huawei `wifi-feature-switch`.
3. **Security: WPA2-AES (CCMP) or WPA3.** Mixed TKIP+AES, or WPA/WPA2 mixed mode, forces legacy rates on some routers.
4. **Placement**: centre of the home, raised, away from metal, aquariums and microwaves. A mesh node or a wired access point beats any setting.
5. **Short guard interval** on 2.4 GHz when the link is clean (a small gain). Leave transmit power at max unless neighbours are an issue.
6. **Ethernet for the call machine**, if there's any way to do it.

## Dropouts
`netdoc.py link --seconds 120` pings the router 5 times a second and reports `longest_gap` and `dropout_s`. Gaps of 1 s or more while RSSI is fine point to:
- roaming between access points with the same SSID;
- aggressive power saving on the client;
- router radio resets;
- DFS radar events on 5 GHz channels 52-144. Try a non-DFS channel: 36-48 or 149-165.

## Changing it (verified drivers)
- **Huawei HG630/HG633 (huawei-ember)**: target `/api/ntwk/WlanBasic?showpass=false:SendSettings`, with a `config2g` object containing `channel`, `nbw` (20/40) and `ngi` (short/long). Read the current object first with `router get /api/ntwk/WlanBasic?showpass=false`.
- **ZTE MiFi (zte-goform)**: goformIds such as `SET_WIFI_INFO` (`wifi_band`, `Channel`, `wifi_11n_cap`).
  - Read names and write names differ, so a backup isn't automatic.
  - Read and save the current values with `router get` first.
- **OpenWrt**: target `wireless.radio0`, with `channel=6` and `htmode=HT20`.
- **ASUS**: target `restart_wireless`, with `wl0_chanspec=6` and `wl0_bw=1` (1 = 20 MHz).
