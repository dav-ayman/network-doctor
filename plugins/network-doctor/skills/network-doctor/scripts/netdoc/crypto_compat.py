"""Pure-Python AES (FIPS-197) with CBC + PKCS#7, and textbook RSA encryption (PKCS#1 v1.5 or raw).

Only what router web UIs need (TP-Link encrypts logins with these). Not constant-time and not meant for
anything else; the stdlib has no AES and network-doctor avoids third-party dependencies.
"""
from __future__ import annotations

import os
from typing import List

# --- AES --------------------------------------------------------------------------------------
_SBOX: List[int] = []
_INV: List[int] = [0] * 256


def _init_sbox() -> None:
    # Build the S-box from the multiplicative inverse in GF(2^8) plus the affine transform (FIPS-197 5.1.1).
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)          # p *= 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09                                                     # q /= 3
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    _SBOX.extend(sbox)
    for i, v in enumerate(sbox):
        _INV[v] = i


def _rotl8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


_init_sbox()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _expand(key: bytes) -> List[List[int]]:
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _encrypt_block(rk: List[List[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[0])]
    nr = len(rk) - 1
    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        # ShiftRows (state is column-major: index = 4*col + row)
        s = [s[(4 * ((c + r) % 4)) + r] for c in range(4) for r in range(4)]
        if rnd != nr:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_xt(a[0]) ^ _xt(a[1]) ^ a[1] ^ a[2] ^ a[3],
                      a[0] ^ _xt(a[1]) ^ _xt(a[2]) ^ a[2] ^ a[3],
                      a[0] ^ a[1] ^ _xt(a[2]) ^ _xt(a[3]) ^ a[3],
                      _xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ _xt(a[3])]
            s = m
        s = [b ^ k for b, k in zip(s, rk[rnd])]
    return bytes(s)


def _decrypt_block(rk: List[List[int]], block: bytes) -> bytes:
    nr = len(rk) - 1
    s = [b ^ k for b, k in zip(block, rk[nr])]
    for rnd in range(nr - 1, -1, -1):
        s = [s[(4 * ((c - r) % 4)) + r] for c in range(4) for r in range(4)]   # InvShiftRows
        s = [_INV[b] for b in s]
        s = [b ^ k for b, k in zip(s, rk[rnd])]
        if rnd != 0:
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                      _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                      _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                      _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = m
    return bytes(s)


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    return _encrypt_block(_expand(key), block)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    return _decrypt_block(_expand(key), block)


def pkcs7_pad(data: bytes, n: int = 16) -> bytes:
    k = n - len(data) % n
    return data + bytes([k]) * k


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or data[-1] < 1 or data[-1] > 16 or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("bad PKCS#7 padding")
    return data[:-data[-1]]


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes, pad: bool = True) -> bytes:
    rk = _expand(key)
    data = pkcs7_pad(data) if pad else data
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        prev = _encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return out


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, pad: bool = True) -> bytes:
    rk = _expand(key)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(rk, blk), prev))
        prev = blk
    return pkcs7_unpad(out) if pad else out


# --- RSA --------------------------------------------------------------------------------------
def _key_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def rsa_encrypt_pkcs1v15(n_hex: str, e_hex: str, data: bytes) -> str:
    """RSAES-PKCS1-v1_5 (RFC 8017 7.2.1), result as lowercase hex padded to the key length."""
    n, e = int(n_hex, 16), int(e_hex, 16)
    k = _key_len(n)
    if len(data) > k - 11:
        raise ValueError("message too long for RSA key")
    ps = b""
    while len(ps) < k - 3 - len(data):
        ps += bytes(b for b in os.urandom(k) if b)
    em = b"\x00\x02" + ps[:k - 3 - len(data)] + b"\x00" + data
    return format(pow(int.from_bytes(em, "big"), e, n), "x").zfill(2 * k)


def rsa_encrypt_raw(n_hex: str, e_hex: str, data: bytes) -> str:
    """Textbook RSA on a zero-left-padded block (some router UIs do this). Hex, padded to key length."""
    n, e = int(n_hex, 16), int(e_hex, 16)
    k = _key_len(n)
    if len(data) > k:
        raise ValueError("message too long for RSA key")
    return format(pow(int.from_bytes(data.rjust(k, b"\x00"), "big"), e, n), "x").zfill(2 * k)


def rsa_encrypt_chunked(n_hex: str, e_hex: str, data: bytes, pkcs1: bool = True) -> str:
    """Encrypt data longer than one RSA block by concatenating per-chunk ciphertexts (TP-Link "sign")."""
    k = _key_len(int(n_hex, 16))
    step = k - 11 if pkcs1 else k
    enc = rsa_encrypt_pkcs1v15 if pkcs1 else rsa_encrypt_raw
    return "".join(enc(n_hex, e_hex, data[i:i + step]) for i in range(0, len(data), step))
