# Contributing

Thanks for helping! The highest-value contributions, in order:

1. **Confirm an experimental driver on your router.** Run `netdoc.py router detect` and `netdoc.py router status`. If they work, open an issue with the model and firmware. If they don't, attach a `netdoc.py capture` file.
2. **Add a router family**, using a capture from someone who owns the router.
3. Improve diagnosis rules (`netdoc/report.py`) and playbooks (`skills/network-doctor/references/`).

## Ground rules

- **Standard library only, Python 3.9+.** The skill has to run on any machine Claude Code runs on, without installs.
- **Clean-room drivers.**
  - Write from protocol documentation, your own observation of your own device, or a capture.
  - Never paste vendor JavaScript, firmware code, or code from projects whose license isn't compatible with MIT.
  - Describe the protocol in your own words in the module docstring.
- **Safety is not optional.**
  - `detect()` may only use `fp.get`/`fp.text` (read-only, unauthenticated).
  - `_login()` must raise `LoginRejected` for wrong passwords. Treat unknown answers as rejected.
  - If a firmware variant is unknown, raise `NotSupported` **before** sending the password.
  - Never log or print passwords.
- **No personal data in fixtures.** Use documentation IPs (192.0.2.x, 198.51.100.x), MACs like `02:00:00:..`, SSIDs like `HomeNet`, and fake serials.

## Writing a driver

1. Copy the shape of `drivers/zte_goform.py` (small) or `drivers/huawei_hilink.py` (bigger).
2. Implement:
   - `detect`;
   - `_login` and `logout`;
   - the read model you can support: `info`, `cellular`, `wifi`, `wan`, `clients`, `extras`;
   - `raw_get`;
   - optionally `current` + `raw_set` for writes.
3. Register it in `drivers/__init__.py`.
4. Add `tests/test_<family>.py` with fixtures. Cover:
   - detect positive/negative;
   - login success;
   - login rejected, then blocked by `LoginGuard` with **no request sent**;
   - status normalization;
   - the write request shape (if writes are supported).
5. Set `tier = "experimental"` until someone confirms it on hardware, then `"verified"` with the model and firmware in `docs/support-matrix.md`.

## Running tests

```
python3 -m unittest discover -s tests -t .
python3 plugins/network-doctor/skills/network-doctor/scripts/netdoc.py diagnose --demo
```

## Media

The banners, GIFs and video in `docs/media/` are generated from sources in that folder. See `docs/media/README.md`. They're recorded with `--demo`, so they never contain real network data.
