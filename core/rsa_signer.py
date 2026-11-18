"""
Zero-Dependency Asymmetric RSA Digital Signature Engine.
Uses Python's built-in math and hashlib to generate RSA keypairs, sign SHA-256 chain roots,
and verify digital signatures without external compiled C libraries.
"""

import math
import secrets
import hashlib
import json
import os
from typing import Tuple, Dict, Any


def is_probable_prime(n: int, k: int = 10) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 512) -> int:
    """Generates a random probable prime of specified bit-length."""
    while True:
        p = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(p):
            return p


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (g, x, y) such that a*x + b*y = g."""
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(e: int, phi: int) -> int:
    """Computes modular inverse of e modulo phi."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


class RSASigner:
    """
    Manages RSA public/private key generation, signature creation, and verification.
    """

    def __init__(self, key_dir: str = "evidence/keys"):
        self.key_dir = key_dir
        self.private_key_path = os.path.join(key_dir, "authority_private.json")
        self.public_key_path = os.path.join(key_dir, "authority_public.json")
        self.e = 65537
        self.n = 0
        self.d = 0

        os.makedirs(key_dir, exist_ok=True)
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """Loads existing keypair or generates a fresh one."""
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            with open(self.private_key_path, "r", encoding="utf-8") as f:
                priv = json.load(f)
                self.n = int(priv["n"], 16)
                self.d = int(priv["d"], 16)
                self.e = int(priv["e"], 16)
        else:
            self.generate_new_keypair(bits=512)

    def generate_new_keypair(self, bits: int = 512):
        """Generates a new RSA-1024 (2x512 bits) keypair."""
        p = generate_prime(bits)
        q = generate_prime(bits)
        while q == p:
            q = generate_prime(bits)

        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.e = 65537
        self.d = mod_inverse(self.e, phi)

        # Save private key
        with open(self.private_key_path, "w", encoding="utf-8") as f:
            json.dump({"n": hex(self.n), "d": hex(self.d), "e": hex(self.e)}, f, indent=2)

        # Save public key
        with open(self.public_key_path, "w", encoding="utf-8") as f:
            json.dump({"n": hex(self.n), "e": hex(self.e)}, f, indent=2)

    def sign(self, message: str) -> str:
        """
        Signs a message string:
        Computes SHA-256 integer digest, then calculates s = (m^d) mod n.
        """
        h_bytes = hashlib.sha256(message.encode("utf-8")).digest()
        m = int.from_bytes(h_bytes, byteorder="big")
        s = pow(m, self.d, self.n)
        return hex(s)

    def verify(self, message: str, signature_hex: str) -> bool:
        """
        Verifies signature using the public key:
        Computes m_recovered = (s^e) mod n and compares against SHA-256(message).
        """
        try:
            s = int(signature_hex, 16)
            m_recovered = pow(s, self.e, self.n)
            h_bytes = hashlib.sha256(message.encode("utf-8")).digest()
            m_expected = int.from_bytes(h_bytes, byteorder="big")
            return m_recovered == m_expected
        except Exception:
            return False
