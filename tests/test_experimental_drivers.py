"""Experimental drivers: protocol-shape tests against synthetic answers (no hardware confirmation yet)."""
import base64
import hashlib
import json
import re
import unittest
from urllib.parse import parse_qs

from tests.fakerouter import FakeSession
from tests.test_crypto import rsa_decrypt_pkcs1, small_rsa
from netdoc.crypto_compat import aes_cbc_decrypt, aes_cbc_encrypt
from netdoc.drivers.base import Fingerprint, LoginGuard, LoginRejected, NotSupported
from netdoc.drivers import asuswrt, fritzbox, mikrotik, openwrt, tplink, tplink_legacy, tplink_mr
from netdoc.web import Response


def fp_with(body, routes=None, headers=None, host="192.0.2.9"):
    fp = Fingerprint(host, f"http://{host}", Response(200, headers or {}, body.encode(), "/"))
    for path, val in (routes or {}).items():
        status, text = val if isinstance(val, tuple) else (200, val)
        fp._cache[path + json.dumps({}, sort_keys=True)] = Response(status, {}, text.encode(), path)
    return fp


def fresh(host):
    LoginGuard.unblock(host, "admin")
    LoginGuard.unblock(host, "root")
    LoginGuard.unblock(host, "")


class OpenWrtTest(unittest.TestCase):
    def setUp(self):
        fresh("192.0.2.10")
        self.d = openwrt.OpenWrt("http://192.0.2.10")
        self.pw_ok = True

        def ubus(m, path, data, h):
            req = json.loads(data)
            sid, obj, meth, args = req["params"]
            if obj == "session" and meth == "login":
                res = [0, {"ubus_rpc_session": "a" * 32}] if self.pw_ok else [6]
            elif obj == "system" and meth == "board":
                res = [0, {"model": "Demo AX1800", "release": {"description": "OpenWrt 23.05.3"}}]
            elif obj == "network.interface.wan":
                res = [0, {"up": True, "proto": "dhcp", "ipv4-address": [{"address": "198.51.100.7"}], "dns-server": ["192.0.2.53"]}]
            elif obj == "uci" and meth == "get":
                res = [0, {"values": {"channel": "11", "htmode": "HT40"}}]
            else:
                res = [0, {}]
            return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res})
        self.d.s = FakeSession(self.d.s, {("POST", "/ubus"): ubus})

    def test_detect(self):
        self.assertGreaterEqual(openwrt.OpenWrt.detect(fp_with('<a href="/cgi-bin/luci">LuCI</a>')), 50)
        self.assertEqual(openwrt.OpenWrt.detect(fp_with("<html>other</html>")), 0)

    def test_status_and_write(self):
        self.assertEqual(self.d.info()["firmware"], "OpenWrt 23.05.3")
        self.assertEqual(self.d.wan()["ip"], "198.51.100.7")
        self.assertEqual(self.d.current("wireless.radio0", {"channel": "6"}), {"channel": "11"})
        self.d.raw_set("wireless.radio0", {"channel": 6})
        calls = [json.loads(c[2])["params"][1:3] for c in self.d.s.calls]
        self.assertIn(["uci", "set"], calls)
        self.assertIn(["uci", "commit"], calls)

    def test_rejected(self):
        self.pw_ok = False
        with self.assertRaises(LoginRejected):
            self.d.login()
        fresh("192.0.2.10")


class MikroTikTest(unittest.TestCase):
    def test_flow(self):
        fresh("192.0.2.11")
        d = mikrotik.MikroTik("http://192.0.2.11")
        good = "Basic " + base64.b64encode(b"admin:test-pass").decode()

        def route(reply):
            def f(m, path, data, h):
                return (200, json.dumps(reply), {}) if h.get("Authorization") == good else (401, "", {})
            return f
        d.s = FakeSession(d.s, {
            ("GET", "/rest/system/resource"): route({"version": "7.15", "board-name": "Chateau LTE12", "cpu-load": "3"}),
            ("GET", "/rest/system/routerboard"): route({"model": "D53G-5HacD2HnD"}),
            ("GET", "/rest/interface/lte"): route([{"name": "lte1", "running": "true"}]),
            ("POST", "/rest/interface/lte/monitor"): route([{"access-technology": "LTE", "rsrp": "-97", "rsrq": "-11",
                                                           "sinr": "9", "primary-band": "B3@20Mhz", "ca-band": "B1@10Mhz",
                                                           "current-operator": "DemoTel"}]),
        })
        c = d.cellular()
        self.assertEqual((c["generation"], c["rsrp"], c["band"]), ("4G+", -97.0, "B3@20Mhz"))
        d2 = mikrotik.MikroTik("http://192.0.2.12")
        d2.s = FakeSession(d2.s, {("GET", "/rest/system/resource"): (401, "", {})})
        with self.assertRaises(LoginRejected):
            d2.login()
        fresh("192.0.2.12")


class FritzTest(unittest.TestCase):
    def test_digest_flow(self):
        fresh("192.0.2.13")
        d = fritzbox.FritzBox("http://192.0.2.13")
        d.user = "admin"
        chal = 'Digest realm="F!Box SOAP-Auth", nonce="N1", algorithm=MD5, qop="auth"'

        def soap(m, path, data, h):
            a = h.get("Authorization")
            if not a:
                return (401, "", {"WWW-Authenticate": chal})
            p = dict(re.findall(r'(\w+)="?([^",]*)"?', a.replace("Digest ", "")))
            ha1 = hashlib.md5(b"admin:F!Box SOAP-Auth:test-pass").hexdigest()
            ha2 = hashlib.md5(f"POST:{path}".encode()).hexdigest()
            want = hashlib.md5(f"{ha1}:N1:{p['nc']}:{p['cnonce']}:auth:{ha2}".encode()).hexdigest()
            if p["response"] != want:
                return (401, "", {"WWW-Authenticate": chal})
            return ('<s:Envelope><s:Body><u:GetInfoResponse><NewModelName>FRITZ!Box 7590</NewModelName>'
                    '<NewSoftwareVersion>154.07.57</NewSoftwareVersion><NewUpTime>3600</NewUpTime>'
                    '</u:GetInfoResponse></s:Body></s:Envelope>')
        d.tr = FakeSession(d.tr, {("POST", "/upnp/control/deviceinfo"): soap})
        self.assertEqual(d.info()["model"], "FRITZ!Box 7590")
        d.logout()
        import os
        os.environ["NETDOC_PASSWORD"] = "wrong"
        try:
            with self.assertRaises(LoginRejected):
                d.login()
        finally:
            os.environ["NETDOC_PASSWORD"] = "test-pass"
            fresh("192.0.2.13")


class AsusTest(unittest.TestCase):
    def test_login_and_wifi(self):
        fresh("192.0.2.14")
        d = asuswrt.AsusWrt("http://192.0.2.14")

        def login(m, path, data, h):
            auth = parse_qs(data.decode())["login_authorization"][0]
            ok = base64.b64decode(auth) == b"admin:test-pass"
            return json.dumps({"asus_token": "T"}) if ok else json.dumps({"error_status": "3"})

        def appget(m, path, data, h):
            hook = parse_qs(data.decode())["hook"][0]
            vals = {"wl0_ssid": "HomeNet", "wl0_chanspec": "6", "wl0_bw": "1", "wl1_ssid": "HomeNet-5G", "wl1_chanspec": "36/80",
                    "wl1_bw": "3", "productid": "RT-AX58U", "firmver": "3.0.0.4", "buildno": "388_24198"}
            keys = re.findall(r"nvram_get\((\w+)\)", hook)
            return json.dumps({k: vals.get(k, "") for k in keys})
        d.s = FakeSession(d.s, {("POST", "/login.cgi"): login, ("POST", "/appGet.cgi"): appget})
        w = d.wifi()
        self.assertEqual([x["width"] for x in w], ["20MHz", "80MHz"])
        self.assertEqual(d.info()["model"], "RT-AX58U")
        import os
        d2 = asuswrt.AsusWrt("http://192.0.2.15")
        d2.s = FakeSession(d2.s, dict(d.s.routes))
        os.environ["NETDOC_PASSWORD"] = "bad"
        try:
            with self.assertRaises(LoginRejected):
                d2.login()
        finally:
            os.environ["NETDOC_PASSWORD"] = "test-pass"
            fresh("192.0.2.15")


class FakeTPLink:
    """A router-side implementation of the signed-AES envelope, using a small RSA key."""

    def __init__(self, password="test-pass"):
        self.n, self.e, self.d = small_rsa(512, seed=11)
        self.password = password
        self.seq = 1000
        self.key = self.iv = None
        self.got_plain = []

    def keys(self, *a):
        return json.dumps({"success": True, "data": {"password": [format(self.n, "x"), "10001"]}})

    def auth(self, *a):
        return json.dumps({"success": True, "data": {"key": [format(self.n, "x"), "10001"], "seq": self.seq}})

    def _open(self, data):
        q = parse_qs(data.decode())
        sign = q["sign"][0]
        k = (self.n.bit_length() + 7) // 8
        s = b"".join(rsa_decrypt_pkcs1(self.n, self.d, sign[i:i + 2 * k]) for i in range(0, len(sign), 2 * k)).decode()
        sp = dict(x.split("=", 1) for x in s.split("&"))
        if "k" in sp:
            self.key, self.iv = sp["k"].encode(), sp["i"].encode()
        body = aes_cbc_decrypt(self.key, self.iv, base64.b64decode(q["data"][0])).decode()
        self.got_plain.append(body)
        return body, sp

    def _seal(self, obj):
        return json.dumps({"data": base64.b64encode(aes_cbc_encrypt(self.key, self.iv, json.dumps(obj).encode())).decode()})

    def login(self, m, path, data, h):
        body, sp = self._open(data)
        pw_hex = parse_qs(body)["password"][0]
        pw = rsa_decrypt_pkcs1(self.n, self.d, pw_hex).decode()
        if pw != self.password:
            return self._seal({"success": False, "errorcode": "login failed", "data": {"attemptsAllowed": 8}})
        return self._seal({"success": True, "data": {"stok": "STOK1"}})

    def status(self, m, path, data, h):
        self._open(data)
        return self._seal({"success": True, "data": {"wan_ipv4_ipaddr": "198.51.100.20", "wan_ipv4_conntype": "dhcp",
                                                     "wireless_2g_ssid": "HomeNet", "wireless_2g_enable": "on",
                                                     "wireless_2g_current_channel": "6",
                                                     "access_devices_wireless_host": [{"hostname": "phone", "ipaddr": "192.168.0.100",
                                                                                       "macaddr": "02-00-00-00-00-01"}]}})


class TPLinkTest(unittest.TestCase):
    def make(self, router, host="192.0.2.20"):
        fresh(host)
        d = tplink.TPLinkWeb(f"http://{host}")
        d.s = FakeSession(d.s, {
            ("POST", "/cgi-bin/luci/;stok=/login?form=keys"): router.keys,
            ("POST", "/cgi-bin/luci/;stok=/login?form=auth"): router.auth,
            ("POST", "/cgi-bin/luci/;stok=/login?form=login"): router.login,
            ("POST", "/cgi-bin/luci/;stok=STOK1/admin/status?form=all"): router.status,
        })
        return d

    def test_signed_aes_roundtrip(self):
        r = FakeTPLink()
        d = self.make(r)
        self.assertEqual(d.wan()["ip"], "198.51.100.20")
        self.assertEqual(d.wifi()[0]["channel"], "6")
        self.assertEqual(d.variant, "signed-aes")
        for c in d.s.calls:   # the password never travels in clear text
            self.assertNotIn(b"test-pass", c[2] or b"")

    def test_wrong_password_rejected_then_blocked(self):
        r = FakeTPLink(password="other")
        d = self.make(r, "192.0.2.21")
        with self.assertRaises(LoginRejected):
            d.login()
        d2 = tplink.TPLinkWeb("http://192.0.2.21")
        d2.s = FakeSession(d2.s, {})
        with self.assertRaises(LoginRejected):
            d2.login()
        self.assertEqual(d2.s.calls, [])
        fresh("192.0.2.21")

    def test_unknown_variant_sends_no_password(self):
        fresh("192.0.2.22")
        d = tplink.TPLinkWeb("http://192.0.2.22")
        d.s = FakeSession(d.s, {("POST", "/cgi-bin/luci/;stok=/login?form=keys"): '{"success":false}'})
        with self.assertRaises(NotSupported):
            d.login()
        self.assertFalse(any("form=login" in c[1] for c in d.s.calls))
        self.assertIsNone(LoginGuard.blocked("192.0.2.22", "admin"))


class TPLinkOtherTest(unittest.TestCase):
    def test_detect_discrimination(self):
        web = fp_with('<script src="/webpages/js/su/su.js"></script> TP-Link', {"/cgi/getParm": (404, "")})
        mr = fp_with('<title>Archer MR600</title> TP-LINK cgi_gdpr', {"/cgi/getParm": 'var ee="010001";\nvar nn="C0FF";\nvar seq="42";'})
        old = fp_with('<html>TP-LINK <script>window.location="/userRpm/LoginRpm.htm"</script></html>', {"/cgi/getParm": (404, "")})
        for fp, want in ((web, tplink.TPLinkWeb), (mr, tplink_mr.TPLinkMR), (old, tplink_legacy.TPLinkLegacy)):
            scores = {c: c.detect(fp) for c in (tplink.TPLinkWeb, tplink_mr.TPLinkMR, tplink_legacy.TPLinkLegacy)}
            self.assertEqual(max(scores, key=scores.get), want, scores)

    def test_mr_parsers(self):
        self.assertEqual(tplink_mr.parse_parm('var ee="010001";\nvar nn="AB";\nvar seq="7";'), {"ee": "010001", "nn": "AB", "seq": "7"})
        blocks, err = tplink_mr.parse_stack("[2,1,0,0,0,0]0\r\nrfInfoRsrp=-99\r\nrfInfoSnr=8\r\nrfInfoBand=3\r\n[error]0\r\n")
        self.assertEqual(err, "0")
        self.assertEqual(blocks[0]["rfInfoBand"], "3")
        self.assertIn("[LTE_NET_STATUS#", tplink_mr.stack_request(["LTE_NET_STATUS"]))

    def test_legacy_arrays(self):
        page = ('var statusPara = new Array(1, 1, 22, "3.16.9 Build 160620 Rel.71633n", "WR841N v11 00000000", 0,0 );'
                'var wanPara = new Array(4, "02-00-00-00-00-09", "198.51.100.30", 1, "255.255.255.0", 0, 0, "198.51.100.1", 1, 1, 0, "192.0.2.53 , 192.0.2.54", "", 0,0 );')
        self.assertEqual(tplink_legacy.js_array(page, "statusPara")[3], "3.16.9 Build 160620 Rel.71633n")
        d = tplink_legacy.TPLinkLegacy("http://192.0.2.23")
        d.logged_in = True
        d.page = lambda name: page
        self.assertEqual(d.info()["firmware"], "3.16.9 Build 160620 Rel.71633n")
        self.assertEqual(d.wan()["ip"], "198.51.100.30")
        self.assertEqual(d.wan()["dns"], ["192.0.2.53", "192.0.2.54"])


if __name__ == "__main__":
    unittest.main()
