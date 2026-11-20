# Changelog

## 0.1.0 (unreleased)

First public release.

- `diagnose` command with ranked findings:
  - Wi-Fi;
  - local link;
  - latency under load (graded A+ to F);
  - call-quality probe (UDP STUN);
  - MTU;
  - DNS;
  - router status.
- Verified router drivers: Huawei HiLink (5G CPE / MiFi, SCRAM login), ZTE goform MiFi, ZTE ZXHN gateways, Huawei HG630/HG633.
- Experimental drivers: TP-Link (Archer web UI, MR LTE, legacy), ASUSWRT/Merlin, AVM FRITZ!Box (TR-064), MikroTik RouterOS 7, OpenWrt (ubus).
- Safe writes: plan first, `--apply`, automatic backup, `router revert`.
- Lockout guard, keychain-only passwords, masked output and masked `capture` files for router-support issues.
- `--demo` mode with a synthetic network.
