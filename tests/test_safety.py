"""Credential safety: router binding, one login attempt per run, guard persistence."""
import os
import unittest
from unittest import mock

from tests.fakerouter import FakeSession
from netdoc import keystore
from netdoc.drivers.base import LoginError, LoginGuard, NoPassword
from netdoc.drivers import huawei_hilink


class RouterBinding(unittest.TestCase):
    def setUp(self):
        self.env = os.environ.pop("NETDOC_PASSWORD")
        try:
            os.remove(keystore.BINDINGS)
        except OSError:
            pass

    def tearDown(self):
        os.environ["NETDOC_PASSWORD"] = self.env

    def test_password_not_used_on_other_router(self):
        keystore.bind("192.168.1.1", "admin", "aa:bb:cc:00:11:22")
        with mock.patch.object(keystore, "_keychain_get", return_value="home-secret"), \
                mock.patch.object(keystore, "gateway_mac", return_value="de:ad:be:ef:00:01"):
            with self.assertRaises(keystore.RouterMismatch):
                keystore.get_password("192.168.1.1", "admin")
        with mock.patch.object(keystore, "_keychain_get", return_value="home-secret"), \
                mock.patch.object(keystore, "gateway_mac", return_value="aa:bb:cc:00:11:22"):
            self.assertEqual(keystore.get_password("192.168.1.1", "admin"), "home-secret")

    def test_unbound_password_refused(self):
        with mock.patch.object(keystore, "_keychain_get", return_value="old-secret"):
            with self.assertRaises(keystore.RouterMismatch):
                keystore.get_password("192.168.9.1", "admin")

    def test_driver_turns_mismatch_into_no_password_and_sends_nothing(self):
        keystore.bind("192.0.2.40", "admin", "aa:bb:cc:00:11:22")
        d = huawei_hilink.HuaweiHiLink("http://192.0.2.40")
        d.s = FakeSession(d.s, {})
        with mock.patch.object(keystore, "_keychain_get", return_value="home-secret"), \
                mock.patch.object(keystore, "gateway_mac", return_value=None):
            with self.assertRaises(NoPassword):
                d.login()
        self.assertEqual(d.s.calls, [])


class OneAttemptPerRun(unittest.TestCase):
    def test_unexpected_failure_not_retried_in_same_run(self):
        LoginGuard.unblock("192.0.2.41", "admin")
        d = huawei_hilink.HuaweiHiLink("http://192.0.2.41")
        boom = {"n": 0}

        def challenge(*a):
            boom["n"] += 1
            return "<error><code>100004</code></error>"   # "system busy": transient, not a rejection
        d.s = FakeSession(d.s, {("GET", "/"): "", ("GET", "/api/webserver/SesTokInfo"): "<response><TokInfo>t</TokInfo></response>",
                                ("GET", "/api/user/state-login"): "<response><State>-1</State></response>",
                                ("POST", "/api/user/challenge_login"): challenge})
        for _ in range(3):
            with self.assertRaises(LoginError):
                d.login()
        self.assertEqual(boom["n"], 1)
        self.assertIsNone(LoginGuard.blocked("192.0.2.41", "admin"))   # transient: not persisted


if __name__ == "__main__":
    unittest.main()
