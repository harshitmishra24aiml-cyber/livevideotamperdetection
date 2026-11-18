"""
Cryptographic Hash Chain Engine for Live Video Integrity
Implements SHA-256 Frame Hashing, Recursive Chain Hashing, and Session Signatures.
"""

import hashlib
import hmac
import os
import json
from typing import Optional, Tuple
import numpy as np


GENESIS_HASH = "GENESIS"


def sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 hexadecimal digest for raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_str(text: str) -> str:
    """Calculate SHA-256 hexadecimal digest for a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_frame_hash(frame: np.ndarray) -> str:
    """
    Computes a deterministic SHA-256 hash for a video frame (NumPy BGR array).
    Using frame.tobytes() on the contiguous raw buffer ensures bit-exact reproducibility.
    """
    if not isinstance(frame, np.ndarray):
        raise TypeError("Frame must be a numpy ndarray")
    if not frame.flags["C_CONTIGUOUS"]:
        frame = np.ascontiguousarray(frame)
    return sha256_bytes(frame.tobytes())


def create_chain_hash(previous_hash: str, index: int, frame_hash: str) -> str:
    """
    Computes the recursive hash chain node:
    C_i = SHA256( previous_hash || index || frame_hash )
    Concatenation scheme: f"{previous_hash}:{index}:{frame_hash}"
    """
    payload = f"{previous_hash}:{index}:{frame_hash}"
    return sha256_str(payload)


def verify_chain_link(previous_hash: str, index: int, frame_hash: str, expected_chain_hash: str) -> bool:
    """Verifies that a given chain hash corresponds to the inputs."""
    computed = create_chain_hash(previous_hash, index, frame_hash)
    return computed == expected_chain_hash


def compute_session_signature(final_chain_hash: str, total_frames: int, secret_key: bytes) -> str:
    """
    Computes an HMAC-SHA256 signature for the session root block.
    This anchors the hash chain and prevents an attacker with access to files
    from recomputing a completely new valid chain without the authority key.
    """
    message = f"SESSION_ROOT:{total_frames}:{final_chain_hash}".encode("utf-8")
    return hmac.new(secret_key, message, hashlib.sha256).hexdigest()


def verify_session_signature(final_chain_hash: str, total_frames: int, secret_key: bytes, signature: str) -> bool:
    """Verifies the authenticity of the session anchor signature."""
    expected = compute_session_signature(final_chain_hash, total_frames, secret_key)
    return hmac.compare_digest(expected, signature)
