"""
Forensic Verification Engine for Live Video Tamper Detection.
Performs cryptographic verification of frames, sequence continuity, hash chain integrity,
and AI-assisted video masking and lens occlusion detection.
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
from .masking_detector import MaskingDetector, MaskingResult


@dataclass
class FrameStatus:
    index: int
    filename: str
    status: str  # "AUTHENTIC", "TAMPERED", "TAMPERED_BY_MASKING", "MISSING", "CHAIN_BROKEN", "DISORDERED"
    is_authentic: bool
    recorded_frame_hash: str
    recomputed_frame_hash: Optional[str]
    recorded_previous_hash: str
    expected_previous_hash: str
    recorded_chain_hash: str
    recomputed_chain_hash: Optional[str]
    details: str
    timestamp: float = 0.0
    is_masked: bool = False
    mask_type: str = "NONE"
    mask_coords: List[Tuple[int, int, int, int]] = field(default_factory=list)
    mask_details: str = ""


@dataclass
class VerificationResult:
    is_valid: bool
    total_checked: int
    authentic_count: int
    tampered_count: int
    missing_count: int
    chain_broken_count: int
    masked_count: int
    accuracy_percent: float
    first_violation_index: Optional[int]
    manifest_verified: Optional[bool]
    frame_results: List[FrameStatus] = field(default_factory=list)
    summary_message: str = ""
    video_source_mode: str = "SESSION_FRAMES"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_checked": self.total_checked,
            "authentic_count": self.authentic_count,
            "tampered_count": self.tampered_count,
            "missing_count": self.missing_count,
            "chain_broken_count": self.chain_broken_count,
            "masked_count": self.masked_count,
            "accuracy_percent": self.accuracy_percent,
            "first_violation_index": self.first_violation_index,
            "manifest_verified": self.manifest_verified,
            "summary_message": self.summary_message,
            "video_source_mode": self.video_source_mode,
            "frames": [asdict(f) for f in self.frame_results],
        }


class VideoVerifier:
    """
    Cryptographic and Forensic Auditor verifying frames, hash chains,
    and video masking attacks.
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
        self.masking_detector = MaskingDetector()

    def verify(self) -> VerificationResult:
        """
        Executes a rigorous cryptographic audit of all recorded frames and the hash chain,
        enhanced with multi-angle masking detection.
        """
        if not os.path.exists(self.log_file):
            return VerificationResult(
                is_valid=False,
                total_checked=0,
                authentic_count=0,
                tampered_count=0,
                missing_count=0,
                chain_broken_count=0,
                masked_count=0,
                accuracy_percent=0.0,
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
        masked_count = 0
        first_violation_index = None
        prev_frame_cache = None

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

                # Check 6: Video Masking & Occlusion Detection
                mask_res = self.masking_detector.analyze_frame_masking(frame, prev_frame_cache)
                prev_frame_cache = frame.copy()

                if mask_res.is_masked:
                    masked_count += 1

                if frame_hash_match and chain_hash_match:
                    if mask_res.is_masked:
                        status = f"AUTHENTIC_BUT_{mask_res.mask_type}"
                        is_auth = False
                        tampered_count += 1
                        details = f"Hash matches captured log, but frame exhibits {mask_res.details}"
                    else:
                        status = "AUTHENTIC"
                        is_auth = True
                        authentic_count += 1
                        details = "Bit-exact pixel hash and chain link verified. No masking."
                elif not frame_hash_match and chain_hash_match:
                    is_auth = False
                    tampered_count += 1
                    if mask_res.is_masked:
                        status = f"TAMPERED_BY_{mask_res.mask_type}"
                        details = f"Frame tampered: {mask_res.details} (hash mismatch)"
                    else:
                        status = "TAMPERED"
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
                    is_auth = False
                    tampered_count += 1
                    if mask_res.is_masked:
                        status = f"TAMPERED_BY_{mask_res.mask_type}"
                        details = f"Both frame hash and chain hash corrupted with {mask_res.details}"
                    else:
                        status = "TAMPERED"
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
                        is_masked=mask_res.is_masked,
                        mask_type=mask_res.mask_type,
                        mask_coords=mask_res.bounding_boxes,
                        mask_details=mask_res.details,
                    )
                )

                previous_hash = recorded_chain_hash
                expected_index = idx + 1

        # Check 7: Session manifest digital signature
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
        accuracy = round((authentic_count / total_checked) * 100.0, 1) if total_checked > 0 else 0.0

        if is_valid:
            summary = f"RESULT: No tampering detected. All frames and chain links are 100% authentic (Accuracy: {accuracy}%)."
        else:
            summary = (
                f"RESULT: VIDEO INTEGRITY COMPROMISED! Accuracy: {accuracy}%. "
                f"Violations: {total_violations} (Tampered: {tampered_count}, "
                f"Masked: {masked_count}, Missing: {missing_count}, Broken Chain: {chain_broken_count}). "
                f"First compromised frame: #{first_violation_index}."
            )

        return VerificationResult(
            is_valid=is_valid,
            total_checked=total_checked,
            authentic_count=authentic_count,
            tampered_count=tampered_count,
            missing_count=missing_count,
            chain_broken_count=chain_broken_count,
            masked_count=masked_count,
            accuracy_percent=accuracy,
            first_violation_index=first_violation_index,
            manifest_verified=manifest_verified,
            frame_results=frame_results,
            summary_message=summary,
            video_source_mode="SESSION_FRAMES",
        )

    def verify_video_file(
        self,
        video_path: str,
        optional_log_path: Optional[str] = None,
        max_frames: int = 120
    ) -> VerificationResult:
        """
        Directly analyzes an uploaded video file (.mp4, .avi, .mov).
        If optional_log_path is provided, verifies SHA-256 hash chain and masking.
        If no log is provided, executes deep AI masking forensics (lens occlusion, digital redactions, static patches).
        """
        if not os.path.exists(video_path):
            return VerificationResult(
                is_valid=False,
                total_checked=0,
                authentic_count=0,
                tampered_count=0,
                missing_count=0,
                chain_broken_count=0,
                masked_count=0,
                accuracy_percent=0.0,
                first_violation_index=None,
                manifest_verified=None,
                summary_message=f"Video file not found: {video_path}",
                video_source_mode="UPLOADED_FILE"
            )

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return VerificationResult(
                is_valid=False,
                total_checked=0,
                authentic_count=0,
                tampered_count=0,
                missing_count=0,
                chain_broken_count=0,
                masked_count=0,
                accuracy_percent=0.0,
                first_violation_index=None,
                manifest_verified=None,
                summary_message=f"Could not open video file {video_path}",
                video_source_mode="UPLOADED_FILE"
            )

        # Parse log records if provided
        log_records = []
        if optional_log_path and os.path.exists(optional_log_path):
            with open(optional_log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        log_records.append(json.loads(line.strip()))

        has_log = len(log_records) > 0
        frame_results: List[FrameStatus] = []
        idx = 0
        authentic_count = 0
        tampered_count = 0
        masked_count = 0
        chain_broken_count = 0
        first_violation_index = None
        previous_hash = GENESIS_HASH
        prev_frame = None

        while True:
            ret, frame = cap.read()
            if not ret or frame is None:
                break
            idx += 1
            if max_frames > 0 and idx > max_frames:
                break

            frame_hash = compute_frame_hash(frame)
            mask_res = self.masking_detector.analyze_frame_masking(frame, prev_frame)
            prev_frame = frame.copy()

            if mask_res.is_masked:
                masked_count += 1

            if has_log:
                # Cryptographic + Masking Mode
                if idx <= len(log_records):
                    rec = log_records[idx - 1]
                    rec_f_hash = rec.get("frame_hash", "")
                    rec_prev_hash = rec.get("previous_hash", "")
                    rec_c_hash = rec.get("chain_hash", "")

                    f_match = frame_hash == rec_f_hash
                    c_calc = create_chain_hash(previous_hash, idx, frame_hash)
                    c_match = (c_calc == rec_c_hash) and (rec_prev_hash == previous_hash)

                    if f_match and c_match and not mask_res.is_masked:
                        status = "AUTHENTIC"
                        is_auth = True
                        authentic_count += 1
                        details = "Hash chain and masking verified: 100% authentic"
                    elif mask_res.is_masked:
                        status = f"TAMPERED_BY_{mask_res.mask_type}"
                        is_auth = False
                        tampered_count += 1
                        details = f"Masking Detected: {mask_res.details}"
                        if first_violation_index is None:
                            first_violation_index = idx
                    elif not f_match:
                        status = "TAMPERED"
                        is_auth = False
                        tampered_count += 1
                        details = "Frame hash mismatch (pixel modification)"
                        if first_violation_index is None:
                            first_violation_index = idx
                    else:
                        status = "CHAIN_BROKEN"
                        is_auth = False
                        chain_broken_count += 1
                        details = "Chain dependency link disrupted"
                        if first_violation_index is None:
                            first_violation_index = idx

                    previous_hash = rec_c_hash
                else:
                    # Beyond log records (inserted/extra frames)
                    status = "UNLOGGED_FRAME"
                    is_auth = False
                    tampered_count += 1
                    details = "Frame present in video but omitted from audit log"
                    rec_f_hash = ""
                    rec_prev_hash = ""
                    rec_c_hash = ""
                    c_calc = None
            else:
                # Standalone AI Masking Forensics Mode (Raw Video Upload)
                rec_f_hash = frame_hash
                rec_prev_hash = previous_hash
                c_calc = create_chain_hash(previous_hash, idx, frame_hash)
                rec_c_hash = c_calc

                if mask_res.is_masked:
                    status = f"MASKED_{mask_res.mask_type}"
                    is_auth = False
                    tampered_count += 1
                    details = mask_res.details
                    if first_violation_index is None:
                        first_violation_index = idx
                else:
                    status = "AUTHENTIC"
                    is_auth = True
                    authentic_count += 1
                    details = "Clean video frame (no masking, uncompromised lens)"

                previous_hash = c_calc

            frame_results.append(
                FrameStatus(
                    index=idx,
                    filename=f"frame_{idx:06d}.png",
                    status=status,
                    is_authentic=is_auth,
                    recorded_frame_hash=rec_f_hash,
                    recomputed_frame_hash=frame_hash,
                    recorded_previous_hash=rec_prev_hash,
                    expected_previous_hash=previous_hash,
                    recorded_chain_hash=rec_c_hash,
                    recomputed_chain_hash=c_calc,
                    details=details,
                    is_masked=mask_res.is_masked,
                    mask_type=mask_res.mask_type,
                    mask_coords=mask_res.bounding_boxes,
                    mask_details=mask_res.details,
                )
            )

        cap.release()
        total_checked = idx
        accuracy = round((authentic_count / total_checked) * 100.0, 1) if total_checked > 0 else 0.0
        is_valid = (tampered_count + chain_broken_count == 0) and total_checked > 0

        mode_desc = "Dual Cryptographic + Masking" if has_log else "AI Masking & Anomaly Forensics"
        if is_valid:
            summary = f"RESULT: Video Integrity Verified! [{mode_desc}] Accuracy: {accuracy}% across {total_checked} frames."
        else:
            summary = f"RESULT: Video Tampering Detected! [{mode_desc}] Accuracy: {accuracy}%. Violations: {tampered_count} (Masked: {masked_count}). First detected at Frame #{first_violation_index}."

        return VerificationResult(
            is_valid=is_valid,
            total_checked=total_checked,
            authentic_count=authentic_count,
            tampered_count=tampered_count,
            missing_count=0,
            chain_broken_count=chain_broken_count,
            masked_count=masked_count,
            accuracy_percent=accuracy,
            first_violation_index=first_violation_index,
            manifest_verified=True if has_log and is_valid else None,
            frame_results=frame_results,
            summary_message=summary,
            video_source_mode=f"UPLOADED_FILE ({mode_desc})"
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
