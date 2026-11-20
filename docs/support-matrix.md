# Support matrix

**Tiers.** *Verified* means a maintainer has used the driver on real hardware. *Experimental* means it was written from public protocol documentation and tested only against synthetic answers. *Confirmed by users* lists model/firmware pairs reported working in issues.

| driver | family | login | reads | writes / revert | verified on | confirmed by users |
|---|---|---|---|---|---|---|
| `huawei-hilink` | Huawei HiLink LTE/5G MiFi, modem, CPE | SCRAM (verified); SHA256 "type 4" and base64 (from docs) | status, cellular (LTE + NR), Wi-Fi, clients, net-mode | XML API paths / yes | 5G CPE 5s H153-381 | |
| `zte-goform` | ZTE MiFi / CPE goform API | SHA256(SHA256(pw)+LD) (verified); base64 (from docs) | cellular (LTE + NR, CA), Wi-Fi, clients, usage | goformId + AD token / when read names match | U20 | |
| `zte-zxhn` | ZTE ZXHN gateways (menuView UI) | sha256(pw + login_token) | Wi-Fi radios, QoS, any view via `explore` | view:tag with Check header / yes | H188A V6 | |
| `huawei-ember` | Huawei HG630/HG633/HG658 | sha256(user + b64(sha256(pw)) + csrf) | device, VDSL line stats, WAN, Wi-Fi, clients | JSON API + action / when read names match | HG630 V2 | |
| `tplink` | TP-Link Archer "luci" web UI | RSA password, signed AES-CBC envelope or RSA-only (variant probe) | status/all (WAN, Wi-Fi, clients), firmware | read-only for now | | |
| `tplink-mr` | TP-Link MR LTE routers | RSA via /cgi/getParm, gdpr AES envelope or legacy RSA | LTE_NET_STATUS (RSRP/RSRQ/SNR/band), device info | read-only | | |
| `tplink-legacy` | old TP-Link /userRpm/ UI | Basic cookie with md5(pw) | status arrays, DHCP clients | read-only | | |
| `asuswrt` | ASUSWRT / Merlin | login.cgi + asus_token | nvram hooks: Wi-Fi, WAN, clients, QoS | applyapp.cgi rc_service / yes | | |
| `fritzbox` | AVM FRITZ!Box | TR-064 digest auth | device, WAN, DSL line, Wi-Fi, hosts | Set* actions / no | | |
| `mikrotik` | MikroTik RouterOS 7 | REST basic auth | resource, LTE monitor, Wi-Fi, registrations, DHCP, queues | PATCH / yes | | |
| `openwrt` | OpenWrt / LuCI | ubus session.login | board, WAN, iwinfo, assoclist, SQM config | UCI set + commit / yes | | |

## Help wanted
- **Netgear** (SOAP / Genie API), **Deco** mesh, **Linksys** (JNAP), **Ubiquiti UniFi** (controller API), **Eero** (cloud-only).
- Cable modems (Arris/Technicolor/Sagemcom DOCSIS status pages).
- Fiber ONTs from Nokia and Huawei (HG8xxx) beyond the Ember UI.

If you own one, open an [Add my router](https://github.com/dav-ayman/network-doctor/issues/new?template=router-support.yml) issue with a `netdoc.py capture` file.
