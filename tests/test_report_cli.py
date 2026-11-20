import contextlib
import io
import json
import os
import unittest

from tests.fakerouter import FakeSession  # noqa: F401
from netdoc import cli, report
from netdoc.demo import SCENARIO


def run(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(list(argv))
    return code, buf.getvalue()


class Report(unittest.TestCase):
    def test_demo_ranking(self):
        r = json.loads(json.dumps(SCENARIO))
        f = report.analyze(r)
        self.assertEqual(f[0]["area"], "bufferbloat")
        self.assertIn("uploading", f[0]["title"])
        areas = [x["area"] for x in f]
        self.assertIn("wifi", areas)

    def test_healthy(self):
        r = {"route": {"medium": "ethernet"}, "gateway_ping": {"loss_pct": 0, "p95_ms": 2, "longest_gap": 0},
             "load": {"idle": {"p95_ms": 30}, "upload": {"p95_ms": 40, "added_p95_ms": 10, "grade": "A", "late_pct": 0},
                      "download": {"p95_ms": 35, "added_p95_ms": 5, "grade": "A", "late_pct": 0}}}
        self.assertEqual(report.analyze(r)[0]["severity"], "ok")

    def test_cellular_finding(self):
        r = {"router": {"status": {"cellular": {"sinr": -2, "rsrp": -104, "band": "B3"}}}}
        self.assertEqual(report.analyze(r)[0]["area"], "cellular")


class CLI(unittest.TestCase):
    def test_diagnose_demo_json(self):
        code, out = run("diagnose", "--demo", "--json")
        d = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(d["router"]["driver"], "demo")
        self.assertEqual(d["findings"][0]["severity"], "critical")

    def test_write_plan_apply_revert(self):
        code, out = run("router", "write", "/api/net/net-mode", "NetworkMode=03", "--demo")
        plan = json.loads(out)
        self.assertFalse(plan["applied"])
        self.assertEqual(plan["current"], {"NetworkMode": "00"})
        code, out = run("router", "write", "/api/net/net-mode", "NetworkMode=03", "--demo", "--apply")
        res = json.loads(out)
        self.assertTrue(res["applied"])
        self.assertTrue(os.path.exists(res["backup_file"]))
        code, out = run("router", "revert", res["backup_file"], "--apply")
        self.assertTrue(json.loads(out)["applied"])

    def test_drivers_listed(self):
        code, out = run("router", "drivers")
        fams = {d["driver"] for d in json.loads(out)}
        self.assertTrue({"huawei-hilink", "zte-goform", "zte-zxhn", "huawei-ember", "openwrt", "mikrotik", "fritzbox",
                         "asuswrt", "tplink", "tplink-mr", "tplink-legacy"} <= fams, fams)

    def test_output_never_contains_password(self):
        code, out = run("diagnose", "--demo", "--json")
        self.assertNotIn(os.environ["NETDOC_PASSWORD"], out)


if __name__ == "__main__":
    unittest.main()


class CLIDemoGlobal(unittest.TestCase):
    def test_global_demo_flag_and_wifi_plan(self):
        code, out = run("--demo", "router", "write", "wifi.2g", "channel=1", "width=20MHz")
        plan = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(plan["current"], {"channel": "11", "width": "40MHz"})
        self.assertTrue(plan["backup"])

    def test_unknown_demo_target_has_no_backup(self):
        code, out = run("--demo", "router", "write", "nope", "x=1")
        self.assertFalse(json.loads(out)["backup"])
