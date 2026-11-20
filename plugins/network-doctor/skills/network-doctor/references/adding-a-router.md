# Unknown router: what to do

1. `netdoc.py router detect`: shows candidate drivers and scores. Below 50 means "not recognised". Pass `--driver <family>` only if you're sure (for example, a rebranded HiLink device).
2. `netdoc.py capture`: a masked snapshot. It contains the login page title, headers, script names and the API paths referenced by the page and its scripts. It holds **no script contents and no credentials**. MACs, SSIDs and public IPs are redacted.
   - With a working driver and a stored password, `capture --login --target <x>` also includes normalized status and raw objects, all masked.
3. Have the user open an issue using the "Add my router" template at https://github.com/dav-ayman/network-doctor/issues, and attach the capture file. Tell them to read it first, so they can see it holds nothing private.

## Meanwhile
Guide the user through the router's web UI by hand.
- Wi-Fi channel and width are usually under Wireless / WLAN > Advanced.
- QoS / bandwidth control is usually under Advanced / Traffic Control.
- Cellular network mode is usually under Mobile Network / Network Settings.
- Ask for a screenshot if needed. Don't open their browser yourself.

## For contributors
See CONTRIBUTING.md in the repository. A driver is a single file implementing `Driver` (`detect`, `_login`, the read model). It needs fixture tests that cover login success, login rejected → blocked, and status parsing.
