import unittest

from tests.fakerouter import FakeSession  # noqa: F401
from netdoc.mask import mask, mask_text, scrub_known


class Mask(unittest.TestCase):
    def test_secret_keys_hidden(self):
        d = mask({"WifiWpapsk": "hunter22", "Password": "x1", "imei": "356938035643809", "SerialNumber": "ABC",
                  "WifiAuthmode": "WPA2-PSK", "password_type": "4", "nested": [{"wpa_key": "k"}], "ssid": "Home"})
        self.assertEqual(d["WifiWpapsk"], "<hidden>")
        self.assertEqual(d["Password"], "<hidden>")
        self.assertEqual(d["imei"], "<hidden>")
        self.assertEqual(d["SerialNumber"], "<hidden>")
        self.assertEqual(d["nested"][0]["wpa_key"], "<hidden>")
        self.assertEqual(d["WifiAuthmode"], "WPA2-PSK")   # harmless, useful
        self.assertEqual(d["password_type"], "4")
        self.assertEqual(d["ssid"], "Home")               # identifiers kept by default

    def test_identifiers_mode(self):
        d = mask({"ssid": "Home", "mac": "02:00:00:aa:bb:cc", "note": "wan 8.8.8.8 lan 192.168.1.1"}, identifiers=True)
        self.assertEqual(d["ssid"], "<redacted>")
        self.assertEqual(d["mac"], "xx:xx:xx:xx:xx:xx")
        self.assertIn("<public-ip>", d["note"])
        self.assertIn("192.168.1.1", d["note"])

    def test_xml_and_known(self):
        x = mask_text("<response><Imei>356938035643809</Imei><WifiKey>abc</WifiKey><SignalIcon>4</SignalIcon></response>")
        self.assertNotIn("356938035643809", x)
        self.assertIn("<SignalIcon>4</SignalIcon>", x)
        self.assertEqual(scrub_known("pw is s3cr3t!", ["s3cr3t!"]), "pw is <hidden>")


if __name__ == "__main__":
    unittest.main()
