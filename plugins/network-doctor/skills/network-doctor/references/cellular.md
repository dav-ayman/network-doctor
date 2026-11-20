# 4G / 5G MiFi and CPE

## Read the numbers (`netdoc.py router status --section cellular`)
| metric | excellent | good | fair | poor |
|---|---|---|---|---|
| RSRP (dBm) | >= -80 | -80 to -90 | -90 to -100 | < -100 |
| RSRQ (dB) | >= -10 | -10 to -15 | -15 to -20 | < -20 |
| SINR (dB) | >= 20 | 13 to 20 | 5 to 13 | < 5 (< 0 very poor) |

- **SINR matters most for stability and upload.** RSRP is just strength. A strong signal with low SINR means interference, often from a neighbouring cell.
- **5G NSA** (`mode: 5G NSA`) means the 5G (NR) leg depends on an LTE "anchor" for control. A poor LTE anchor makes the connection unstable even when the NR numbers look good, so report both.
- `bars` come from the router's own icon logic, which is crude. Prefer the numbers.

## Fixes, best first
1. **Placement.** Try each window and each side of the building. Higher is better. Give each spot 1-2 minutes, then read `--section cellular` again. Small moves can change SINR by 10 dB. Keep the unit away from walls and metal.
2. **External antenna**, if the device has SMA/TS9 ports. Point it at the tower (use cellmapper.net, with the operator and band from the status).
3. **Network mode / band lock.** Sometimes forcing LTE-only, or locking a cleaner band, beats Auto.
   - Huawei: `/api/net/net-mode`, which has `NetworkMode`, `NetworkBand` and `LTEBand`. Some firmware has band selection disabled. Then Auto is already the best available.
   - ZTE: `SET_BEARER_PREFERENCE` / `BAND_SELECT`, depending on the model.
   - Always plan, back up and confirm first (router-safety.md). A wrong band lock can drop the connection, and you may need the router's own Wi-Fi or a reset to undo it.
4. **Bufferbloat is extreme on cellular.** Modems queue seconds of data, so pair the radio work with latency-under-load.md.
5. **Data cap and throttling**: check `month_rx`/`month_tx` against the plan. Operators slow you down after the cap.

## Lockouts
Huawei HiLink devices lock the admin account after 3 wrong passwords (code 108007). ZTE MiFis show the attempts left in `psw_fail_num_str`. netdoc never retries a rejected password.
