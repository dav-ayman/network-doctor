# Security

network-doctor logs in to routers with admin credentials, so we take these seriously.

## Report a vulnerability
Please use GitHub's private vulnerability reporting (Security tab > "Report a vulnerability"). Don't open a public issue for it.

## Design
- **Credential storage.**
  - Passwords are read from the OS keychain (macOS Keychain / Linux Secret Service, service `network-doctor`) or the `NETDOC_PASSWORD` environment variable.
  - netdoc never writes them to disk, never prints them, and never sends them anywhere except the router you point it at. The router address is the default gateway unless you pass `--host`.
  - Every output passes through a masking filter, plus a literal scrub of the password values used in that run.
- **Router binding.**
  - `secret set` records the gateway's MAC address next to the password.
  - A stored password is only sent if the gateway at that IP still has that MAC, so a home password is never offered to a different network that reuses the same IP.
  - `NETDOC_PASSWORD` skips this check: you chose the router when you set the variable.
  - `NETDOC_SKIP_ROUTER_CHECK=1` disables the check. Not recommended.
- **One attempt per run.** After any failed login, the same process never sends the password again.
- **Lockout protection.** A rejected login is recorded in `~/.network-doctor/login-guard.json`. Later attempts are refused without contacting the router.
- **TLS.** Router web UIs use self-signed certificates, so certificate verification is off for router connections. Only use netdoc on a network you trust.
- **Writes.**
  - Writes require an explicit `--apply`, after a plan has been shown.
  - Backups of changed values go to `~/.network-doctor/backups/`. They contain router settings, which may include an SSID. They never contain the admin password.
- **Capture files** are masked for public sharing. Review them before you post one.

## Measurement traffic
`diagnose`, `bloat` and `call` contact third parties:
- Google, Cloudflare and Twilio STUN servers;
- `speed.cloudflare.com`, or Apple's `networkQuality` servers on macOS;
- `1.1.1.1` for ping and MTU.

No telemetry is collected.
