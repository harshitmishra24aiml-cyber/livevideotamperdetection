"""
Forensic Verification Engine for Live Video Tamper Detection.
Performs cryptographic verification of frames, sequence continuity, and hash chain integrity.
"""

import os
import cv2
import json
import numpy as np
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
from .hash_chain import (
    GENESIS_HASH,
    compute_frame_hash,
    create_chain_hash,
    verify_session_signature,
)


@dataclass
class FrameStatus:
    index: int
    filename: str
    status: str  # "AUTHENTIC", "TAMPERED", "MISSING", "CHAIN_BROKEN", "DISORDERED"
    is_authentic: bool
    recorded_frame_hash: str
    recomputed_frame_hash: Optional[str]
    recorded_previous_hash: str
    expected_previous_hash: str
    recorded_chain_hash: str
    recomputed_chain_hash: Optional[str]
    details: str
    timestamp: float = 0.0


@dataclass
class VerificationResult:
    is_valid: bool
    total_checked: int
    authentic_count: int
    tampered_count: int
    missing_count: int
    chain_broken_count: int
    first_violation_index: Optional[int]
    manifest_verified: Optional[bool]
    frame_results: List[FrameStatus] = field(default_factory=list)
    summary_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_checked": self.total_checked,
            "authentic_count": self.authentic_count,
            "tampered_count": self.tampered_count,
            "missing_count": self.missing_count,
            "chain_broken_count": self.chain_broken_count,
            "first_violation_index": self.first_violation_index,
            "manifest_verified": self.manifest_verified,
            "summary_message": self.summary_message,
            "frames": [asdict(f) for f in self.frame_results],
        }


class VideoVerifier:
    """
    Cryptographic auditor verifying frames and the tamper-evident hash chain.
    """

    def __init__(
        self,
        base_dir: str = "evidence",
        frame_dir: Optional[str] = None,
        log_file: Optional[str] = None,
        secret_key: bytes = b"CRYPTO_AUDIT_SECRET_2026"
    ):
        self.base_dir = base_dir
        self.frame_dir = frame_dir or os.path.join(base_dir, "frames")
        self.log_file = log_file or os.path.join(base_dir, "hash_log.jsonl")
        self.secret_key = secret_key

    def verify(self) -> VerificationResult:
        """
        Executes a rigorous cryptographic audit of all recorded frames and the hash chain.
        """
        if not os.path.exists(self.log_file):
            return VerificationResult(
                is_valid=False,
                total_checked=0,
                authentic_count=0,
                tampered_count=0,
                missing_count=0,
                chain_broken_count=0,
                first_violation_index=None,
                manifest_verified=None,
                summary_message=f"Log file not found: {self.log_file}",
            )

        frame_results: List[FrameStatus] = []
        previous_hash = GENESIS_HASH
        expected_index = 1
        total_checked = 0
        authentic_count = 0
        tampered_count = 0
        missing_count = 0
        chain_broken_count = 0
        first_violation_index = None

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    tampered_count += 1
                    if first_violation_index is None:
                        first_violation_index = line_no
                    frame_results.append(
                        FrameStatus(
                            index=line_no,
                            filename="UNKNOWN",
                            status="LOG_CORRUPT",
                            is_authentic=False,
                            recorded_frame_hash="",
                            recomputed_frame_hash=None,
                            recorded_previous_hash="",
                            expected_previous_hash=previous_hash,
                            recorded_chain_hash="",
                            recomputed_chain_hash=None,
                            details=f"Malformed JSON on line {line_no}",
                        )
                    )
                    continue

                total_checked += 1
                idx = record.get("frame_number", total_checked)
                filename = record.get("filename", f"frame_{idx:06d}.png")
                filepath = os.path.join(self.frame_dir, filename)
                recorded_frame_hash = record.get("frame_hash", "")
                recorded_prev_hash = record.get("previous_hash", "")
                recorded_chain_hash = record.get("chain_hash", "")
                timestamp = record.get("timestamp", 0.0)

                # Check 1: Sequence index
                if idx != expected_index:
                    details = f"Sequence gap detected: expected #{expected_index}, found #{idx}"
                    status = "DISORDERED"
                    is_auth = False
                    tampered_count += 1
                    if first_violation_index is None:
                        first_violation_index = idx

                # Check 2: File existence
                if not os.path.exists(filepath):
                    missing_count += 1
                    if first_violation_index is None:
                        first_violation_index = idx
                    frame_results.append(
                        FrameStatus(
                            index=idx,
                            filename=filename,
                            status="MISSING",
                            is_authentic=False,
                            recorded_frame_hash=recorded_frame_hash,
                            recomputed_frame_hash=None,
                            recorded_previous_hash=recorded_prev_hash,
                            expected_previous_hash=previous_hash,
                            recorded_chain_hash=recorded_chain_hash,
                            recomputed_chain_hash=None,
                            details=f"Frame file {filename} does not exist on disk",
                            timestamp=timestamp,
                        )
                    )
                    # For chain continuity, update previous_hash from record
                    previous_hash = recorded_chain_hash
                    expected_index = idx + 1
                    continue

                # Check 3: Read frame
                frame = cv2.imread(filepath)
                if frame is None:
                    tampered_count += 1
                    if first_violation_index is None:
                        first_violation_index = idx
                    frame_results.append(
                        FrameStatus(
                            index=idx,
                            filename=filename,
                            status="UNREADABLE",
                            is_authentic=False,
                            recorded_frame_hash=recorded_frame_hash,
                            recomputed_frame_hash=None,
                            recorded_previous_hash=recorded_prev_hash,
                            expected_previous_hash=previous_hash,
                            recorded_chain_hash=recorded_chain_hash,
                            recomputed_chain_hash=None,
                            details=f"Frame file {filename} could not be decoded as image",
                            timestamp=timestamp,
                        )
                    )
                    previous_hash = recorded_chain_hash
                    expected_index = idx + 1
                    continue

                # Check 4: Frame Hash (Pixel-level integrity)
                recomputed_frame_hash = compute_frame_hash(frame)
                frame_hash_match = recomputed_frame_hash == recorded_frame_hash

                # Check 5: Previous hash continuity & Chain Hash recalculation
                prev_hash_match = recorded_prev_hash == previous_hash
                recomputed_chain_hash = create_chain_hash(
                    previous_hash, idx, recomputed_frame_hash
                )
                chain_hash_match = (
                    recomputed_chain_hash == recorded_chain_hash and prev_hash_match
                )

                if frame_hash_match and chain_hash_match:
                    status = "AUTHENTIC"
                    is_auth = True
                    authentic_count += 1
                    details = "Bit-exact pixel hash and chain link verified"
                elif not frame_hash_match and chain_hash_match:
                    status = "TAMPERED"
                    is_auth = False
                    tampered_count += 1
                    details = "Pixel data altered (frame hash mismatch)"
                    if first_violation_index is None:
                        first_violation_index = idx
                elif frame_hash_match and not chain_hash_match:
                    status = "CHAIN_BROKEN"
                    is_auth = False
                    chain_broken_count += 1
                    details = f"Chain link broken (expected prev {previous_hash[:8]}..., log has {recorded_prev_hash[:8]}...)"
                    if first_violation_index is None:
                        first_violation_index = idx
                else:
                    status = "TAMPERED"
                    is_auth = False
                    tampered_count += 1
                    details = "Both frame pixel hash and chain hash corrupted"
                    if first_violation_index is None:
                        first_violation_index = idx

                frame_results.append(
                    FrameStatus(
                        index=idx,
                        filename=filename,
                        status=status,
                        is_authentic=is_auth,
                        recorded_frame_hash=recorded_frame_hash,
                        recomputed_frame_hash=recomputed_frame_hash,
                        recorded_previous_hash=recorded_prev_hash,
                        expected_previous_hash=previous_hash,
                        recorded_chain_hash=recorded_chain_hash,
                        recomputed_chain_hash=recomputed_chain_hash,
                        details=details,
                        timestamp=timestamp,
                    )
                )

                # For forensic progression, advance the chain using the recorded chain hash
                # so subsequent frame checks can also be audited.
                previous_hash = recorded_chain_hash
                expected_index = idx + 1

        # Check 6: Session manifest digital signature
        manifest_path = os.path.join(self.base_dir, "session_manifest.json")
        manifest_verified = None
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as mf:
                    mdata = json.load(mf)
                sig = mdata.get("session_signature", "")
                final_hash = mdata.get("final_chain_hash", "")
                total_f = mdata.get("total_frames", 0)
                manifest_verified = verify_session_signature(
                    final_hash, total_f, self.secret_key, sig
                )
            except Exception:
                manifest_verified = False

        total_violations = tampered_count + missing_count + chain_broken_count
        is_valid = total_violations == 0 and total_checked > 0

        if is_valid:
            summary = "RESULT: No tampering detected. All frames and chain links are 100% authentic."
        else:
            summary = (
                f"RESULT: VIDEO INTEGRITY COMPROMISED! "
                f"Violations: {total_violations} (Tampered: {tampered_count}, "
                f"Missing: {missing_count}, Broken Chain: {chain_broken_count}). "
                f"First compromised frame: #{first_violation_index}."
            )

        return VerificationResult(
            is_valid=is_valid,
            total_checked=total_checked,
            authentic_count=authentic_count,
            tampered_count=tampered_count,
            missing_count=missing_count,
            chain_broken_count=chain_broken_count,
            first_violation_index=first_violation_index,
            manifest_verified=manifest_verified,
            frame_results=frame_results,
            summary_message=summary,
        )

    def generate_tamper_heatmap(
        self, frame_index: int
    ) -> Optional[Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """
        If a clean snapshot is available, generates a side-by-side visual diff
        and difference heatmap showing the exact pixels modified.
        Returns: (original_frame, tampered_frame, heatmap_rgb)
        """
        filename = f"frame_{frame_index:06d}.png"
        tampered_path = os.path.join(self.frame_dir, filename)
        snapshot_path = os.path.join(self.base_dir, ".snapshot_clean", "frames", filename)

        if not os.path.exists(tampered_path) or not os.path.exists(snapshot_path):
            return None

        orig = cv2.imread(snapshot_path)
        tamp = cv2.imread(tampered_path)

        if orig is None or tamp is None:
            return None

        # Compute absolute difference
        diff = cv2.absdiff(orig, tamp)
        diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)

        # Highlight difference with colormap (HEATMAP)
        # Scale differences to maximize visibility
        _, thresh = cv2.threshold(diff_gray, 5, 255, cv2.THRESH_BINARY)
        diff_norm = cv2.normalize(diff_gray, None, 0, 255, cv2.NORM_MINMAX)
        heatmap = cv2.applyColorMap(diff_norm, cv2.COLORMAP_JET)

        # Overlay bounding rectangles around tampered clusters
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        tamp_marked = tamp.copy()
        for c in contours:
            if cv2.contourArea(c) > 10:
                x, y, w, h = cv2.boundingRect(c)
                cv2.rectangle(tamp_marked, (x, y), (x + w, y + h), (0, 0, 255), 2)
                cv2.putText(tamp_marked, "TAMPER DETECTED", (x, max(15, y - 5)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1)

        return orig, tamp_marked, heatmap
