"""Driver interface for router families, plus the login guard that keeps routers from locking the account.

A driver turns one router family's web API into a common read model:
  info()      {vendor, model, firmware, hardware, uptime_s}
  cellular()  {generation, operator, bars, max_bars, connected, rsrp, rsrq, sinr, rssi, band, nr:{...}, month_rx, month_tx}
              or None for fixed-line routers
  wifi()      [{radio, band, ssid, enabled, channel, width, standard, security, tx_power, clients}]
  wan()       {type, connected, ip, dns, uptime_s, ...}
  clients()   [{name, ip, mac, interface, rssi}]
and exposes low-level access for everything else:
  raw_get(target)            read one API object
  current(target, fields)    read the current values of the fields a write would change (for the backup)
  raw_set(target, fields)    write (only called by the CLI after --apply and a saved backup)

Every value returned may contain identifiers; the CLI masks output before printing.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from .. import keystore as secrets
from ..web import Response, Session

STATE_DIR = os.path.expanduser(os.environ.get("NETDOC_HOME", "~/.network-doctor"))


class DriverError(Exception):
    pass


class LoginError(DriverError):
    """Login did not succeed (network, unexpected answer). Safe to try again later."""


class LoginRejected(LoginError):
    """The router said the password is wrong (or the account is locked). Never retried automatically."""


class LoginBusy(LoginError):
    """Too many sessions / someone else is logged in. Transient."""


class NoPassword(LoginError):
    pass


class NotSupported(DriverError):
    pass


class Fingerprint:
    """What we know about the gateway from unauthenticated, read-only requests. Caches every GET."""

    def __init__(self, host: str, base: Optional[str], root: Optional[Response]):
        self.host = host
        self.base = base
        self.root = root
        self._cache: Dict[str, Optional[Response]] = {}
        self.session = Session(base, timeout=5) if base else None

    @property
    def body(self) -> str:
        return self.root.text[:200_000] if self.root else ""

    @property
    def server(self) -> str:
        return (self.root.header("Server") or "") if self.root else ""

    def get(self, path: str, **kw: Any) -> Optional[Response]:
        """Read-only GET relative to the gateway base URL (or an absolute URL), cached; None on network error."""
        key = path + json.dumps(kw, sort_keys=True, default=str)
        if key not in self._cache:
            try:
                self._cache[key] = self.session.get(path, **kw) if self.session else None
            except Exception:
                self._cache[key] = None
        return self._cache[key]

    def text(self, path: str, **kw: Any) -> str:
        r = self.get(path, **kw)
        return r.text if r is not None and r.status < 500 else ""


class Driver:
    family = "base"
    name = "Base driver"
    vendor = ""
    tier = "experimental"          # "verified" = tested on real hardware by a maintainer
    models = ""                    # human list of covered models
    default_user = "admin"
    lockout = "unknown: assume the router locks the account after a few wrong passwords"
    can_write = False
    can_revert = False             # current() can read back what a write changes
    write_targets = ""             # help text: what raw_set targets look like

    def __init__(self, base: str, user: Optional[str] = None, timeout: float = 15.0):
        self.s = Session(base, timeout=timeout)
        self.base = base
        self.user = user or self.default_user
        self.logged_in = False
        self._login_error: Optional[Exception] = None

    @property
    def host(self) -> str:
        return self.s.host

    # ---- detection -------------------------------------------------------------------------
    @classmethod
    def detect(cls, fp: Fingerprint) -> int:
        """Confidence 0-100 that the gateway is this family. Must only use fp (read-only GETs)."""
        return 0

    # ---- session ---------------------------------------------------------------------------
    def _password(self) -> str:
        try:
            pw = secrets.get_password(self.host, self.user)
        except secrets.RouterMismatch as e:
            raise NoPassword(str(e))
        if not pw:
            raise NoPassword(
                f"no password stored for {self.user}@{self.host}. Ask the user to run (in their own terminal, "
                f"or in Claude Code as `! python3 <skill>/scripts/netdoc.py secret set {self.host}`)")
        return pw

    def login(self) -> None:
        """Guarded login: refuses if a previous run got a wrong-password answer from this router."""
        if self.logged_in:
            return
        if self._login_error is not None:
            # one attempt per run: never send the password again after any failure in this process
            raise self._login_error
        block = LoginGuard.blocked(self.host, self.user)
        if block:
            raise LoginRejected(
                f"login to {self.user}@{self.host} is blocked since {block}: the router rejected the stored password "
                "earlier. Fix the password (`netdoc.py secret set`), then `netdoc.py router unblock`. Not retrying, "
                f"to avoid a lockout ({self.lockout}).")
        pw = self._password()
        try:
            self._login(pw)
        except LoginRejected as e:
            LoginGuard.block(self.host, self.user, str(e))
            self._login_error = e
            raise
        except Exception as e:
            self._login_error = e
            raise
        self.logged_in = True

    def _login(self, password: str) -> None:
        raise NotSupported(f"{self.name}: login not implemented")

    def logout(self) -> None:
        self.logged_in = False

    def relogin(self) -> None:
        """For drivers whose session expired mid-run: allowed only after a successful login in this run."""
        if self._login_error is None:
            self.logged_in = False
            self.login()

    def __enter__(self) -> "Driver":
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.logged_in:
            try:
                self.logout()
            except Exception:
                pass

    # ---- read model ------------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        return {"vendor": self.vendor}

    def cellular(self) -> Optional[Dict[str, Any]]:
        return None

    def wifi(self) -> List[Dict[str, Any]]:
        return []

    def wan(self) -> Dict[str, Any]:
        return {}

    def clients(self) -> List[Dict[str, Any]]:
        return []

    def extras(self) -> Dict[str, Any]:
        """Anything else worth showing in a status report (QoS, DSL line stats, logs...)."""
        return {}

    # ---- low level -------------------------------------------------------------------------
    def raw_get(self, target: str) -> Any:
        raise NotSupported(f"{self.name}: raw_get not implemented")

    def current(self, target: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        raise NotSupported(f"{self.name}: cannot read back values before a write, so a change cannot be reverted")

    def raw_set(self, target: str, fields: Dict[str, Any]) -> Any:
        raise NotSupported(f"{self.name}: writes are not supported")

    def explore(self) -> Dict[str, Any]:
        """Read-only discovery of API endpoints/views, for building new features or drivers."""
        return {}

    # ---- helpers ---------------------------------------------------------------------------
    def status(self, sections: Optional[List[str]] = None) -> Dict[str, Any]:
        """Collect the read model. Each section is independent; failures are reported, not raised."""
        out: Dict[str, Any] = {"driver": self.family, "tier": self.tier}
        for sec in sections or ["info", "cellular", "wan", "wifi", "clients", "extras"]:
            try:
                v = getattr(self, sec)()
            except LoginRejected:
                raise
            except NoPassword as e:
                out.setdefault("errors", {})[sec] = str(e)
                continue
            except Exception as e:  # keep going: partial status is still useful
                out.setdefault("errors", {})[sec] = f"{type(e).__name__}: {e}"
                continue
            if v not in (None, {}, []):
                out[sec] = v
        return out


class LoginGuard:
    """Persists "this router rejected the password" across runs so no agent loop can lock the account."""

    path = os.path.join(STATE_DIR, "login-guard.json")

    @classmethod
    def _load(cls) -> Dict[str, Any]:
        try:
            with open(cls.path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    @classmethod
    def _save(cls, d: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(cls.path), mode=0o700, exist_ok=True)
        tmp = cls.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, cls.path)

    @classmethod
    def blocked(cls, host: str, user: str) -> Optional[str]:
        e = cls._load().get(f"{user}@{host}")
        return e.get("since") if e else None

    @classmethod
    def block(cls, host: str, user: str, reason: str) -> None:
        d = cls._load()
        d[f"{user}@{host}"] = {"since": time.strftime("%Y-%m-%d %H:%M:%S"), "reason": reason[:300]}
        cls._save(d)

    @classmethod
    def unblock(cls, host: str, user: str) -> bool:
        d = cls._load()
        found = d.pop(f"{user}@{host}", None) is not None
        cls._save(d)
        return found
