"""
Video Integrity Verifier - SHA-256 Hash Chain Auditor
Verifies video frames losslessly against the cryptographic hash chain and identifies tampering.
"""

import os
import cv2
import json
import hashlib
import argparse
from core.hash_chain import GENESIS_HASH, sha256_bytes, create_chain_hash
from core.verifier_engine import VideoVerifier

FRAME_DIR = "evidence/frames"
LOG_FILE = "evidence/hash_log.jsonl"


def sha256(data: bytes) -> str:
    """Calculate SHA-256 hash."""
    return sha256_bytes(data)


def create_chain(previous_hash: str, index: int, frame_hash: str) -> str:
    """Calculate chain hash node."""
    return create_chain_hash(previous_hash, index, frame_hash)


def verify_video(verbose: bool = True):
    """
    Verifies every frame in the evidence directory against the audit log
    and validates cryptographic chain continuity.
    """
    if not os.path.exists(LOG_FILE):
        print(f"[!] Error: Audit log not found at '{LOG_FILE}'.")
        print("[*] Please run 'python main.py' first to capture a video session.")
        return False

    print("\n==================================================")
    print(" CRYPTOGRAPHIC VIDEO INTEGRITY VERIFICATION")
    print(f" Evidence Directory: {FRAME_DIR}")
    print(f" Audit Log:          {LOG_FILE}")
    print("==================================================\n")

    verifier = VideoVerifier(base_dir="evidence")
    result = verifier.verify()

    for item in result.frame_results:
        idx = item.index
        if item.status == "AUTHENTIC":
            if verbose:
                short_h = item.recorded_frame_hash[:10] + "..."
                print(f"[+] Frame {idx:04d}: AUTHENTIC  | Hash: {short_h}")
        elif item.status == "MISSING":
            print(f"[!] Frame {idx:04d}: ALERT: Missing frame file! ({item.filename})")
        elif item.status == "UNREADABLE":
            print(f"[!] Frame {idx:04d}: ALERT: Frame file unreadable/corrupted!")
        elif "TAMPERED" in item.status:
            print(f"[X] Frame {idx:04d}: TAMPERING DETECTED! ({item.status})")
            print(f"    Recorded Hash:     {item.recorded_frame_hash}")
            print(f"    Recalculated Hash: {item.recomputed_frame_hash}")
            if item.is_masked:
                print(f"    [!] MASKING DETECTED: {item.mask_type} | Bounding Box(es): {item.mask_coords}")
                print(f"        Detail: {item.mask_details}")
        elif item.status == "CHAIN_BROKEN":
            print(f"[X] Frame {idx:04d}: CHAIN CORRUPTED! Previous hash dependency broken.")
            print(f"    Expected Prev: {item.expected_previous_hash}")
            print(f"    Log Prev:      {item.recorded_previous_hash}")
        else:
            print(f"[X] Frame {idx:04d}: VIOLATION - {item.details}")
            if item.is_masked:
                print(f"    [!] MASKING DETECTED: {item.mask_type} | Bounding Box(es): {item.mask_coords}")

    print("\n========== VERIFICATION REPORT ==========")
    print(f"Frames checked:         {result.total_checked}")
    print(f"Authentic frames:       {result.authentic_count}")
    print(f"Integrity violations:   {result.tampered_count + result.missing_count + result.chain_broken_count}")
    print(f"Masked frames detected: {result.masked_count}")
    print(f"Integrity Accuracy:     {result.accuracy_percent}%")

    if result.first_violation_index is not None:
        print(f"First compromised frame: Frame #{result.first_violation_index}")

    if result.manifest_verified is not None:
        sig_status = "AUTHENTIC (Signature Verified)" if result.manifest_verified else "INVALID SIGNATURE!"
        print(f"Session Root Signature: {sig_status}")

    print("------------------------------------------")
    if result.is_valid:
        print(f"RESULT: No tampering detected. All frames authentic (Accuracy: {result.accuracy_percent}%).")
    else:
        print(f"RESULT: VIDEO INTEGRITY COMPROMISED! (Accuracy: {result.accuracy_percent}%)")
    print("==========================================\n")

    return result.is_valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify Live Video Integrity using SHA-256 Hash Chain")
    parser.add_argument("--quiet", action="store_true", help="Only show summary, omit authentic frame logs")
    args = parser.parse_args()

    verify_video(verbose=not args.quiet)
