"""Flow tests for the drivers verified on real hardware, against synthetic answers in the same shapes."""
import json
import unittest
from urllib.parse import parse_qs

from tests.fakerouter import FakeSession
from netdoc.drivers.base import LoginGuard, LoginRejected
from netdoc.drivers import huawei_ember, huawei_hilink, zte_goform, zte_zxhn

OK = '<?xml version="1.0" encoding="UTF-8"?><response>OK</response>'


def err(code):
    return f'<?xml version="1.0" encoding="UTF-8"?><error><code>{code}</code><message></message></error>'


class HiLinkCrypto(unittest.TestCase):
    def test_scram_proof_matches_router_js(self):
        # Vector produced by running the router web UI's own SCRAM function on these synthetic inputs.
        proof = huawei_hilink.scram_client_proof(
            "correct horse battery", "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0", 1000,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90Xy/Zq+Rt9w==")
        self.assertEqual(proof, "6ef452ddc18b669df331bf54aa2e309d349e0af5d3cf6010eaeb35d77c9232e4")

    def test_entities_decoded(self):
        self.assertEqual(huawei_hilink.fields("<servernonce>ab&#x2F;cd</servernonce>")["servernonce"], "ab/cd")

    def test_generation(self):
        g = huawei_hilink.generation
        self.assertEqual(g("1011"), "5G")
        self.assertEqual(g("101", "1"), "5G")
        self.assertEqual(g("101", "0", "B3+B1"), "4G+")
        self.assertEqual(g("101"), "4G")
        self.assertEqual(g("0"), "No service")


class HiLinkFlow(unittest.TestCase):
    def setUp(self):
        LoginGuard.unblock("192.0.2.1", "admin")
        self.d = huawei_hilink.HuaweiHiLink("http://192.0.2.1")
        self.auth_answer = '<response><serversignature>x</serversignature><rsan>y</rsan></response>'
        self.d.s = FakeSession(self.d.s, {
            ("GET", "/"): '<meta name="csrf_token" content="tok1"/>',
            ("GET", "/api/user/state-login"): "<response><State>-1</State><password_type>4</password_type></response>",
            ("POST", "/api/user/challenge_login"): "<response><salt>00ff</salt><iterations>100</iterations>"
                                                     "<servernonce>abc&#x2F;def</servernonce></response>",
            ("POST", "/api/user/authentication_login"): lambda *a: self.auth_answer,
            ("GET", "/api/monitoring/status"): "<response><ConnectionStatus>901</ConnectionStatus><SignalIcon>3</SignalIcon>"
                                                "<SignalIconNr>5</SignalIconNr><CurrentNetworkTypeEx>101</CurrentNetworkTypeEx>"
                                                "<EndcStatus>1</EndcStatus><maxsignal>5</maxsignal></response>",
            ("GET", "/api/net/current-plmn"): "<response><FullName>DemoTel</FullName></response>",
            ("GET", "/api/device/signal"): lambda *a: (
                "<response><rsrp>-101dBm</rsrp><rsrq>-12.0dB</rsrq><sinr>-1dB</sinr><band>3</band><nrrsrp>-95dBm</nrrsrp>"
                "<nrsinr>15dB</nrsinr></response>" if self.d.logged_in or any(
                    c[1] == "/api/user/authentication_login" for c in self.d.s.calls) else err("100003")),
            ("GET", "/api/monitoring/month_statistics"): "<response><CurrentMonthDownload>1000</CurrentMonthDownload>"
                                                           "<CurrentMonthUpload>10</CurrentMonthUpload></response>",
            ("POST", "/api/user/logout"): OK,
        })

    def test_login_and_cellular(self):
        c = self.d.cellular()
        self.assertEqual(c["generation"], "5G")
        self.assertEqual(c["bars"], 5)
        self.assertEqual(c["rsrp"], -101.0)
        self.assertEqual(c["nr"]["sinr"], 15.0)
        # the decoded nonce (with "/") must be what is sent back
        auth = [x for x in self.d.s.calls if x[1] == "/api/user/authentication_login"][0]
        self.assertIn(b"<finalnonce>abc/def</finalnonce>", auth[2])
        self.assertNotIn(b"test-pass", auth[2])

    def test_wrong_password_blocks_future_attempts(self):
        self.auth_answer = err("108006")
        with self.assertRaises(LoginRejected):
            self.d.login()
        n = len(self.d.s.calls)
        d2 = huawei_hilink.HuaweiHiLink("http://192.0.2.1")
        d2.s = FakeSession(d2.s, {})
        with self.assertRaises(LoginRejected):
            d2.login()
        self.assertEqual(d2.s.calls, [], "a blocked login must not send anything")
        self.assertTrue(LoginGuard.unblock("192.0.2.1", "admin"))
        self.assertGreater(n, 0)


class ZTE(unittest.TestCase):
    def setUp(self):
        LoginGuard.unblock("192.0.2.2", "admin")
        self.result = "0"
        self.d = zte_goform.ZTEGoform("http://192.0.2.2")

        def get(m, path, data, h):
            q = parse_qs(path.split("?", 1)[1])
            cmds = q["cmd"][0].split(",")
            vals = {"loginfo": "no", "psw_fail_num_str": "5", "login_lock_time": "-1", "LD": "ABCD", "RD": "EF",
                    "wa_inner_version": "BD_V1", "cr_version": "CR1", "network_type": "LTE", "signalbar": "4",
                    "ppp_status": "ppp_connected", "network_provider": "DemoTel", "wan_lte_ca": "ca_activated",
                    "lte_rsrp": "-95", "lte_snr": "7", "wan_active_band": "LTE BAND 3", "lte_ca_scell_band": "1"}
            if self.d.s.calls and any(c[1] == "/goform/goform_set_cmd_process" for c in self.d.s.calls) and self.result == "0":
                vals["loginfo"] = "ok"
            return json.dumps({c: vals.get(c, "") for c in cmds})
        self.d.s = FakeSession(self.d.s, {("GET", "/goform/goform_get_cmd_process*"): get,
                                          ("POST", "/goform/goform_set_cmd_process"): lambda *a: json.dumps({"result": self.result})})

    def test_hashes(self):
        self.assertEqual(zte_goform.login_hash("pw", "LD1"), zte_goform.sha_upper(zte_goform.sha_upper("pw") + "LD1"))
        self.assertEqual(len(zte_goform.ad_token("a", "b", "c")), 64)

    def test_login_and_signal(self):
        c = self.d.cellular()
        self.assertEqual(c["generation"], "4G+")
        self.assertEqual(c["band"], "LTE BAND 3 + CA 1")
        login = [x for x in self.d.s.calls if x[0] == "POST"][0]
        self.assertIn(zte_goform.login_hash("test-pass", "ABCD").encode(), login[2])

    def test_rejected(self):
        self.result = "3"
        with self.assertRaises(LoginRejected):
            self.d.login()
        self.assertIsNotNone(LoginGuard.blocked("192.0.2.2", "admin"))
        LoginGuard.unblock("192.0.2.2", "admin")


class ZXHN(unittest.TestCase):
    def test_body_and_check(self):
        body = zte_zxhn.encode_body([("OBJ_QOSQB_ID.Enable", 1), ("A", "x y")], "tok")
        self.assertEqual(body, "IF_ACTION=Apply&OBJ_QOSQB_ID.Enable=1&A=x%20y&_sessionTOKEN=tok")
        x = ("<Instance><ParaName>_InstID</ParaName><ParaValue>IGD</ParaValue><ParaName>Enable</ParaName>"
             "<ParaValue>0</ParaValue></Instance>")
        self.assertEqual(zte_zxhn.instances(x), [{"_InstID": "IGD", "Enable": "0"}])
        self.assertEqual(zte_zxhn.unescape_js("\\x41b"), "Ab")

    def test_login_success_and_unknown_answer(self):
        LoginGuard.unblock("192.0.2.3", "admin")
        d = zte_zxhn.ZTEZXHN("https://192.0.2.3")
        ans = {"v": '{"login_need_refresh": true}'}
        d.s = FakeSession(d.s, {("GET", "/"): "<html></html>",
                                ("GET", "/?_type=loginData&_tag=login_entry"): '{"sess_token":"s1","lockingTime":0}',
                                ("GET", "/?_type=loginData&_tag=login_token"): "<ajax_response_xml_root>salt</ajax_response_xml_root>",
                                ("POST", "/?_type=loginData&_tag=login_entry"): lambda *a: ans["v"]})
        d.login()
        d.logged_in = False
        ans["v"] = '{"loginErrMsg": "bad"}'
        with self.assertRaises(LoginRejected):
            d.login()
        LoginGuard.unblock("192.0.2.3", "admin")


class Ember(unittest.TestCase):
    def test_login(self):
        LoginGuard.unblock("192.0.2.4", "admin")
        d = huawei_ember.HuaweiEmber("https://192.0.2.4")
        ans = {"v": '/*{"errorCategory":"ok"}*/'}
        d.s = FakeSession(d.s, {("GET", "/"): '<meta name="csrf_param" content="p"/><meta name="csrf_token" content="t"/>',
                                ("POST", "/api/system/user_login"): lambda *a: ans["v"],
                                ("GET", "/api/ntwk/WlanBasic?showpass=false"):
                                    '/*[{"ID":"x","Channel":6,"BeaconType":"11i","IEEEiEncryptionMode":"AESEncryption","WifiEnable":true}]*/'})
        w = d.wifi()
        self.assertEqual(w[0]["security"], "WPA2-PSK")
        self.assertEqual(w[0]["encryption"], "AESEncryption")
        sent = json.loads([c for c in d.s.calls if c[0] == "POST"][0][2])
        self.assertEqual(sent["data"]["Password"], huawei_ember.login_password("admin", "test-pass", "p", "t"))
        d2 = huawei_ember.HuaweiEmber("https://192.0.2.4")
        d2.s = FakeSession(d2.s, dict(d.s.routes))
        ans["v"] = '/*{"errorCategory":"user_pass_err","count":1}*/'
        with self.assertRaises(LoginRejected):
            d2.login()
        LoginGuard.unblock("192.0.2.4", "admin")


if __name__ == "__main__":
    unittest.main()
