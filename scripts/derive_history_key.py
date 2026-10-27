#!/usr/bin/env python3
"""Derive a repo's session-history key pair from SESSION_HISTORY_KEY.

Mirrors seal.DeriveKeyPair in the engine: HKDF-SHA256 over the secret with
the repo id as salt and "claudinite conversation-logs key" as info gives an
X25519 private key. Reads the secret from the environment and the repo id
from argv; writes the public key file to argv[2] and the age identity to
argv[3]. The canary uses it so that the key is derived by something other
than the engine's own code.
"""
import hashlib
import hmac
import os
import subprocess
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def hkdf(secret: bytes, salt: bytes, info: bytes, n: int) -> bytes:
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def bech32(hrp: str, data: bytes) -> str:
    acc, bits, five = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append((acc << (5 - bits)) & 31)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    mod = polymod(expand + five + [0] * 6) ^ 1
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in five + checksum)


def main() -> None:
    repo_id, pub_path, identity_path = sys.argv[1:4]
    secret = os.environ["SESSION_HISTORY_KEY"].encode()
    if not secret:
        sys.exit("SESSION_HISTORY_KEY is empty")
    raw = hkdf(secret, repo_id.encode(), b"claudinite conversation-logs key", 32)
    pkcs8 = bytes.fromhex("302e020100300506032b656e04220420") + raw
    der = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=pkcs8, capture_output=True, check=True,
    ).stdout
    pub = der[-32:]
    with open(pub_path, "w") as f:
        f.write(f"# repo {repo_id}\n{bech32('age', pub)}\n")
    with open(identity_path, "w") as f:
        f.write(bech32("age-secret-key-", raw).upper() + "\n")


main()
