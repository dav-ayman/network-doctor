"""netdoc command line. Every command prints JSON (masked) unless it says otherwise; `diagnose` prints a
human report by default and JSON with --json."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from . import __version__, probes, report
from . import keystore as secrets
from .drivers import all_drivers
from .drivers.base import STATE_DIR, DriverError, LoginGuard, NoPassword, NotSupported
from .mask import mask, scrub_known


def emit(obj: Any) -> None:
    text = json.dumps(mask(obj), indent=1, ensure_ascii=False, default=str)
    print(scrub_known(text, secrets.seen()))


def progress(msg: str) -> None:
    if sys.stderr.isatty():
        sys.stderr.write(f"  {msg}\n")
        sys.stderr.flush()


def gateway(args: argparse.Namespace) -> str:
    if getattr(args, "host", None):
        return args.host
    if getattr(args, "demo", False):
        return "192.168.8.1"
    gw = probes.default_route().get("gateway")
    if not gw:
        raise SystemExit("no default gateway found (offline?). Pass --host.")
    return gw


def get_driver(args: argparse.Namespace):
    if getattr(args, "demo", False):
        from .demo import DemoRouter
        return DemoRouter()
    from .fingerprint import pick_driver
    d = pick_driver(gateway(args), getattr(args, "driver", None))
    if getattr(args, "user", None):
        d.user = args.user
    return d


# ---------------------------------------------------------------------------------------------
def cmd_diagnose(args: argparse.Namespace) -> int:
    secs = 8 if args.quick else args.seconds
    r: Dict[str, Any] = {"netdoc": __version__, "time": time.strftime("%Y-%m-%d %H:%M")}
    if args.demo:
        from .demo import SCENARIO, DemoRouter, pace
        r.update(json.loads(json.dumps(SCENARIO)))
        for label, t in (("baseline + Wi-Fi", 1.2), ("router + internet ping", 1.5), ("call probe idle", 1.2),
                         ("call probe while uploading", 2.0), ("call probe while downloading", 1.6), ("MTU + DNS", 0.8),
                         ("router (demo 5G CPE)", 0.8)):
            pace(label, t)
        d = DemoRouter()
        r["router"] = {"driver": d.family, "tier": d.tier, "status": d.status()}
    else:
        progress("baseline...")
        r["route"] = probes.default_route()
        r["dns_servers"] = probes.dns_servers()
        if r["route"].get("medium") == "wifi":
            progress("Wi-Fi details...")
            r["wifi"] = probes.wifi()
        gw = r["route"].get("gateway")
        if gw:
            progress("router ping...")
            r["gateway_ping"] = probes.ping_series(gw, count=int(secs * 5), interval=0.2)
        progress("internet ping...")
        r["internet_ping"] = probes.ping_series("1.1.1.1", count=int(secs * 5), interval=0.2)
        r["dns"] = probes.dns_timing()
        if not args.no_load:
            progress(f"call probe idle / during upload / during download ({secs:.0f}s each, uses your bandwidth)...")
            r["load"] = probes.latency_under_load(secs)
        progress("MTU...")
        r["mtu"] = probes.path_mtu()
        if gw and not args.no_router:
            r["router"] = router_snapshot(gw, args)
    r["findings"] = report.analyze(r)
    if args.json:
        emit(r)
    else:
        print(scrub_known(report.render(mask(r), color=sys.stdout.isatty() and not args.no_color), secrets.seen()))
    return 0


def router_snapshot(gw: str, args: argparse.Namespace) -> Dict[str, Any]:
    from .fingerprint import identify, pick_driver
    progress("identifying router...")
    ident = identify(gw)
    out: Dict[str, Any] = {"identify": ident}
    fam = getattr(args, "driver", None) or ident.get("best")
    if not fam:
        return out
    d = pick_driver(gw, fam)
    out.update({"driver": d.family, "tier": d.tier})
    progress(f"reading router ({d.name})...")
    try:
        with d:
            out["status"] = d.status()
    except NoPassword as e:
        out["needs_password"] = str(e)
    except DriverError as e:
        out["error"] = str(e)
    return out


def cmd_simple(args: argparse.Namespace) -> int:
    c = args.cmd
    if getattr(args, "demo", False):
        return demo_simple(args)
    if c == "wifi":
        out = probes.wifi()
    elif c == "ping":
        out = probes.ping_series(args.target or gateway(args), count=args.count, interval=0.2)
    elif c == "link":
        out = probes.link_monitor(args.target or gateway(args), seconds=args.seconds)
    elif c == "call":
        if args.load:
            progress(f"call probe while {'uploading' if args.load == 'up' else 'downloading'} ({args.seconds:.0f}s)...")
            with probes.Load(args.load, args.seconds + 8) as ld:
                out = probes.stun_probe(args.seconds)
            out["load"] = getattr(ld, "result", {})
        else:
            out = probes.stun_probe(args.seconds)
    elif c == "bloat":
        progress(f"call probe idle / while uploading / while downloading ({args.seconds:.0f}s each)...")
        out = probes.latency_under_load(args.seconds)
    elif c == "mtu":
        out = probes.path_mtu(args.target or "1.1.1.1")
    elif c == "dns":
        out = {"servers": probes.dns_servers(), **probes.dns_timing()}
    elif c == "speed":
        out = probes.throughput()
    else:
        out = probes.default_route()
    show(args, c, out)
    return 0


def show(args: argparse.Namespace, cmd: str, out: Any) -> None:
    if getattr(args, "text", False):
        print(scrub_known(report.render_part(cmd, mask(out), color=sys.stdout.isatty()), secrets.seen()))
    else:
        emit(out)


def demo_simple(args: argparse.Namespace) -> int:
    from .demo import SCENARIO, pace
    sc = json.loads(json.dumps(SCENARIO))
    c = args.cmd
    if c == "bloat":
        for label, t in (("call probe idle", 1.5), ("call probe while uploading", 2.5), ("call probe while downloading", 2.0)):
            pace(label, t)
        out = sc["load"]
    elif c == "call":
        pace("call probe" + (f" while {'uploading' if args.load == 'up' else 'downloading'}" if args.load else ""), 2.5)
        out = sc["load"]["upload" if args.load == "up" else "download" if args.load == "down" else "idle"]
    else:
        out = {"wifi": sc["wifi"], "ping": sc["gateway_ping"], "link": sc["gateway_ping"], "mtu": sc["mtu"],
               "dns": {"servers": sc["dns_servers"], **sc["dns"]}, "speed": sc["throughput"], "route": sc["route"]}[c]
    show(args, c, out)
    return 0


# ---------------------------------------------------------------------------------------------
def cmd_router(args: argparse.Namespace) -> int:
    a = args.action
    if a == "drivers":
        emit([{"driver": d.family, "name": d.name, "tier": d.tier, "models": d.models, "writes": d.can_write,
               "revert": d.can_revert, "lockout": d.lockout} for d in all_drivers()])
        return 0
    if a == "detect":
        if args.demo:
            emit({"host": "192.168.8.1", "best": "demo", "candidates": [{"driver": "demo", "score": 100}]})
            return 0
        from .fingerprint import identify
        emit(identify(gateway(args)))
        return 0
    if a == "unblock":
        host = gateway(args)
        user = args.user or "admin"
        emit({"unblocked": LoginGuard.unblock(host, user), "account": f"{user}@{host}",
              "note": "only do this after fixing the stored password (netdoc.py secret set)"})
        return 0
    if a == "revert":
        return do_revert(args)

    d = get_driver(args)
    try:
        with d:
            if a == "status":
                st = d.status(args.section or None)
                if getattr(args, "text", False):
                    print(scrub_known(report.render_part("router", mask(st), color=sys.stdout.isatty()), secrets.seen()))
                else:
                    emit(st)
            elif a == "get":
                emit({"driver": d.family, "target": args.target, "value": d.raw_get(args.target)})
            elif a == "explore":
                emit({"driver": d.family, **d.explore()})
            elif a == "write":
                return do_write(d, args)
    except NoPassword as e:
        emit({"error": "no_password", "message": str(e)})
        return 3
    except DriverError as e:
        emit({"error": type(e).__name__, "message": str(e), "driver": d.family})
        return 2
    return 0


def parse_fields(pairs: List[str]) -> Dict[str, Any]:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"field {p!r} must look like key=value")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def do_write(d, args: argparse.Namespace) -> int:
    fields = parse_fields(args.fields)
    if not d.can_write:
        emit({"error": "read_only_driver", "driver": d.family})
        return 2
    try:
        old = d.current(args.target, fields)
        backup_ok = True
    except (NotSupported, DriverError) as e:
        old, backup_ok = {"unavailable": str(e)}, False
    plan = {"driver": d.family, "host": d.host, "target": args.target, "current": old, "new": fields,
            "backup": backup_ok, "applied": False}
    if not args.apply:
        plan["next"] = ("Show this plan to the user. Only after they approve, re-run with --apply"
                        + ("" if backup_ok else " --no-backup (no automatic revert possible: confirm that explicitly)"))
        emit(plan)
        return 0
    if not backup_ok and not args.no_backup:
        plan["error"] = "cannot back up the current values; refusing without --no-backup"
        emit(plan)
        return 2
    path = None
    if backup_ok:
        os.makedirs(os.path.join(STATE_DIR, "backups"), mode=0o700, exist_ok=True)
        path = os.path.join(STATE_DIR, "backups", f"{d.family}-{d.host}-{time.strftime('%Y%m%d-%H%M%S')}.json")
        with open(path, "w") as f:
            json.dump({"driver": d.family, "host": d.host, "base": d.base, "user": d.user, "target": args.target,
                       "old": old, "new": fields, "time": time.strftime("%Y-%m-%d %H:%M:%S")}, f, indent=1)
        os.chmod(path, 0o600)
    plan["result"] = d.raw_set(args.target, fields)
    plan["applied"] = True
    plan["backup_file"] = path
    try:
        plan["after"] = d.current(args.target, fields)
    except Exception:
        pass
    if path:
        plan["revert_with"] = f"netdoc.py router revert {path} --apply"
    emit(plan)
    return 0


def do_revert(args: argparse.Namespace) -> int:
    from .drivers import by_family
    with open(args.target) as f:
        b = json.load(f)
    plan = {"driver": b["driver"], "host": b["host"], "target": b["target"], "restore": b["old"], "applied": False}
    if not args.apply:
        plan["next"] = "Show the user, then re-run with --apply"
        emit(plan)
        return 0
    if b["driver"] == "demo":
        from .demo import DemoRouter
        d = DemoRouter()
    else:
        d = by_family(b["driver"])(b["base"], user=b.get("user"))
    with d:
        plan["result"] = d.raw_set(b["target"], b["old"])
        plan["applied"] = True
    emit(plan)
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    from .fingerprint import capture
    emit(capture(gateway(args), args.driver, args.target or [], login=args.login))
    return 0


def cmd_secret(args: argparse.Namespace) -> int:
    user = args.user or "admin"
    if args.action == "set":
        print(secrets.store_interactive(args.host, user))
    elif args.action == "delete":
        print(secrets.delete(args.host, user))
    elif args.action == "check":
        try:
            has, router = secrets.get_password(args.host, user) is not None, "ok"
        except secrets.RouterMismatch as e:
            has, router = True, str(e)
        print(json.dumps({"account": f"{user}@{args.host}", "stored": has, "router_check": router,
                          "login_blocked_since": LoginGuard.blocked(args.host, user)}))
    return 0


# ---------------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netdoc.py", description="Find out why the internet feels bad.")
    p.add_argument("--version", action="version", version=f"network-doctor {__version__}")
    p.add_argument("--demo", dest="demo_global", action="store_true",
                   help="synthetic network for every command (same as passing --demo to the subcommand)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, router: bool = False, text: bool = False) -> None:
        sp.add_argument("--demo", action="store_true", help="synthetic network, no real measurements")
        if text:
            sp.add_argument("--text", action="store_true", help="human-readable output instead of JSON")
        sp.add_argument("--host", help="router IP (default: the default gateway)")
        if router:
            sp.add_argument("--driver", help="force a driver family (see `router drivers`)")
            sp.add_argument("--user", help="router admin user (default: admin)")

    d = sub.add_parser("diagnose", help="full read-only checkup with ranked findings")
    common(d, router=True)
    d.add_argument("--quick", action="store_true", help="shorter probes (~1 min)")
    d.add_argument("--seconds", type=float, default=15, help="seconds per call-probe phase (default 15)")
    d.add_argument("--no-load", action="store_true", help="skip the latency-under-load test (uses bandwidth)")
    d.add_argument("--no-router", action="store_true", help="don't talk to the router")
    d.add_argument("--json", action="store_true")
    d.add_argument("--no-color", action="store_true")
    d.set_defaults(func=cmd_diagnose)

    for name, hlp in (("wifi", "Wi-Fi link + neighbours"), ("route", "default route and medium"),
                      ("dns", "DNS servers and lookup times"), ("speed", "throughput (macOS networkQuality)")):
        sp = sub.add_parser(name, help=hlp)
        common(sp, text=True)
        sp.set_defaults(func=cmd_simple)
    sp = sub.add_parser("ping", help="ping series with loss/jitter/p95")
    common(sp, text=True)
    sp.add_argument("target", nargs="?")
    sp.add_argument("--count", type=int, default=50)
    sp.set_defaults(func=cmd_simple)
    sp = sub.add_parser("link", help="watch the link to the router for dropouts")
    common(sp, text=True)
    sp.add_argument("target", nargs="?")
    sp.add_argument("--seconds", type=int, default=60)
    sp.set_defaults(func=cmd_simple)
    sp = sub.add_parser("call", help="call-quality probe (UDP STUN, 10 pkt/s)")
    common(sp, text=True)
    sp.add_argument("--seconds", type=float, default=15)
    sp.add_argument("--load", choices=["up", "down"], help="run an upload or download at the same time")
    sp.set_defaults(func=cmd_simple)
    sp = sub.add_parser("bloat", help="latency under load: idle vs upload vs download")
    common(sp, text=True)
    sp.add_argument("--seconds", type=float, default=15)
    sp.set_defaults(func=cmd_simple)
    sp = sub.add_parser("mtu", help="path MTU")
    common(sp, text=True)
    sp.add_argument("target", nargs="?")
    sp.set_defaults(func=cmd_simple)

    r = sub.add_parser("router", help="talk to the router")
    rs = r.add_subparsers(dest="action", required=True)
    for name, hlp in (("drivers", "list supported router families"), ("detect", "identify the router (no login)"),
                      ("status", "normalized status (logs in if needed)"), ("explore", "list API views (read-only)"),
                      ("unblock", "allow logins again after fixing a rejected password")):
        sp = rs.add_parser(name, help=hlp)
        common(sp, router=True)
        if name == "status":
            sp.add_argument("--text", action="store_true", help="human-readable output")
            sp.add_argument("--section", action="append", choices=["info", "cellular", "wan", "wifi", "clients", "extras"])
    sp = rs.add_parser("get", help="read one raw API object")
    common(sp, router=True)
    sp.add_argument("target")
    sp = rs.add_parser("write", help="change settings (plan first; --apply to execute)")
    common(sp, router=True)
    sp.add_argument("target")
    sp.add_argument("fields", nargs="+", metavar="key=value")
    sp.add_argument("--apply", action="store_true")
    sp.add_argument("--no-backup", action="store_true")
    sp = rs.add_parser("revert", help="restore values from a backup file")
    common(sp, router=True)
    sp.add_argument("target", metavar="BACKUP_FILE")
    sp.add_argument("--apply", action="store_true")
    r.set_defaults(func=cmd_router)

    c = sub.add_parser("capture", help="masked snapshot of the router's API for an 'Add my router' issue")
    common(c, router=True)
    c.add_argument("--login", action="store_true", help="also log in and include normalized status")
    c.add_argument("--target", action="append", help="raw targets to include (with --login)")
    c.set_defaults(func=cmd_capture)

    s = sub.add_parser("secret", help="store the router password in the OS keychain (run it yourself)")
    s.add_argument("action", choices=["set", "delete", "check"])
    s.add_argument("host")
    s.add_argument("--user")
    s.set_defaults(func=cmd_secret)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "demo_global", False):
        args.demo = True
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
