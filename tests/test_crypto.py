import random
import unittest

from tests.fakerouter import FakeSession  # noqa: F401  (sets sys.path)
from netdoc.crypto_compat import (aes_cbc_decrypt, aes_cbc_encrypt, aes_decrypt_block, aes_encrypt_block,
                                  rsa_encrypt_chunked, rsa_encrypt_pkcs1v15)


def _prime(bits, rnd):
    while True:
        n = rnd.getrandbits(bits) | (1 << (bits - 1)) | 1
        if all(pow(a, n - 1, n) == 1 for a in (2, 3, 5, 7, 11, 13, 17, 19, 23)):
            return n


def small_rsa(bits=512, seed=7):
    rnd = random.Random(seed)
    e = 65537
    while True:
        p, q = _prime(bits // 2, rnd), _prime(bits // 2, rnd)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            return p * q, e, pow(e, -1, phi)


def rsa_decrypt_pkcs1(n, d, hexs):
    k = (n.bit_length() + 7) // 8
    em = pow(int(hexs, 16), d, n).to_bytes(k, "big")
    assert em[:2] == b"\x00\x02", em[:2]
    return em[em.index(b"\x00", 2) + 1:]


class AES(unittest.TestCase):
    def test_fips197_appendix_c(self):
        p = bytes.fromhex("00112233445566778899aabbccddeeff")
        for key, ct in (("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
                        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
                        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089")):
            k = bytes.fromhex(key)
            self.assertEqual(aes_encrypt_block(k, p).hex(), ct)
            self.assertEqual(aes_decrypt_block(k, bytes.fromhex(ct)), p)

    def test_sp800_38a_cbc_aes128(self):
        k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                           "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
        ct = ("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
              "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
        self.assertEqual(aes_cbc_encrypt(k, iv, pt, pad=False).hex(), ct)
        self.assertEqual(aes_cbc_decrypt(k, iv, bytes.fromhex(ct), pad=False), pt)

    def test_cbc_pkcs7_roundtrip(self):
        k, iv = b"1234567890123456", b"6543210987654321"
        for n in (0, 1, 15, 16, 17, 100):
            data = bytes(range(n))
            self.assertEqual(aes_cbc_decrypt(k, iv, aes_cbc_encrypt(k, iv, data)), data)


class RSA(unittest.TestCase):
    def test_pkcs1_roundtrip_and_chunking(self):
        n, e, d = small_rsa()
        nh, eh = format(n, "x"), format(e, "x")
        self.assertEqual(rsa_decrypt_pkcs1(n, d, rsa_encrypt_pkcs1v15(nh, eh, b"secret")), b"secret")
        msg = b"k=1234567890123456&i=6543210987654321&h=" + b"a" * 32 + b"&s=123456789"
        out = rsa_encrypt_chunked(nh, eh, msg)
        k = (n.bit_length() + 7) // 8
        chunks = [out[i:i + 2 * k] for i in range(0, len(out), 2 * k)]
        self.assertEqual(b"".join(rsa_decrypt_pkcs1(n, d, c) for c in chunks), msg)


if __name__ == "__main__":
    unittest.main()
