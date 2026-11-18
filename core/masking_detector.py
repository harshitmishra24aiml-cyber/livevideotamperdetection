"""
Masking Detection Engine for Video Surveillance Forensics.
Detects:
1. Camera Lens Occlusion (Physical masking: covered lens, spray, tape, blackout, severe blinding)
2. Digital Occlusion Box Masking (Pasted solid/semi-solid black/gray/white redaction boxes)
3. Static Background Patch Cloning (Frozen inpainting masks covering movement)
Computes exact bounding boxes, mask coverage ratio, and confidence scores.
"""

import cv2
import numpy as np
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any


@dataclass
class MaskingResult:
    is_masked: bool
    mask_type: str  # "NONE", "LENS_OCCLUSION", "DIGITAL_BOX_MASK", "STATIC_PATCH_CLONE", "BLUR_MASK"
    confidence: float  # 0.0 to 1.0
    bounding_boxes: List[Tuple[int, int, int, int]] = field(default_factory=list)  # (x, y, w, h)
    mask_area_ratio: float = 0.0  # Fraction of frame covered by mask (0.0 to 1.0)
    details: str = "No masking detected"
    annotated_frame: Optional[np.ndarray] = None


class MaskingDetector:
    """
    Forensic Computer Vision engine specializing in video masking and occlusion detection.
    Works standalone on raw video or in conjunction with SHA-256 cryptographic hash chains.
    """

    def __init__(
        self,
        min_box_area_ratio: float = 0.015,  # At least 1.5% of frame area
        max_box_area_ratio: float = 0.80,   # Up to 80% of frame area
        min_rectangular_extent: float = 0.78, # Area / (bw * bh) ratio
        lens_occlusion_blur_thresh: float = 10.0
    ):
        self.min_box_area_ratio = min_box_area_ratio
        self.max_box_area_ratio = max_box_area_ratio
        self.min_rectangular_extent = min_rectangular_extent
        self.lens_occlusion_blur_thresh = lens_occlusion_blur_thresh

    def detect_lens_occlusion(self, frame: np.ndarray) -> Tuple[bool, float, str]:
        """
        Detects complete or near-complete camera lens occlusion:
        - Hand/cloth/tape placed over camera
        - Spray paint on lens
        - Complete darkness (blackout) or extreme overexposure (blinding flashlight)
        """
        h, w, _ = frame.shape
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        mean_val = float(np.mean(gray))
        std_val = float(np.std(gray))

        # Blackout occlusion (e.g. tape or hand blocking light)
        if mean_val < 15.0 and std_val < 12.0:
            return True, 0.98, "Lens Blackout / Covered Camera (Near-zero dynamic range)"

        # Whiteout / Blinding flash occlusion
        if mean_val > 240.0 and std_val < 15.0:
            return True, 0.95, "Lens Whiteout / Camera Blinding (Overexposure occlusion)"

        # Severe Defocus / Uniform Obstruction (Laplacian variance)
        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        if lap_var < self.lens_occlusion_blur_thresh and std_val < 15.0:
            return True, 0.90, f"Lens Occlusion / Extreme Obstruction (Laplacian variance: {lap_var:.2f})"

        return False, 0.0, "Lens clear"

    def detect_digital_box_masking(
        self, frame: np.ndarray
    ) -> Tuple[bool, List[Tuple[int, int, int, int]], float, float, str]:
        """
        Detects digital occlusion boxes (solid or near-solid rectangular redaction masks)
        pasted onto video frames to obscure people, vehicles, or timestamps.
        Uses local variance analysis and rectangular compactness.
        """
        h, w, _ = frame.shape
        total_pixels = h * w
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # 1. Compute local variance in 5x5 sliding window
        mean = cv2.blur(gray, (5, 5))
        sqr_mean = cv2.blur(gray**2, (5, 5))
        var = np.maximum(0, sqr_mean - mean**2)

        # Digital masks (blackout, solid gray, whiteout, red boxes) are spatially flat (var < 6.0)
        flat_mask = (var < 6.0).astype(np.uint8) * 255
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
        flat_mask = cv2.morphologyEx(flat_mask, cv2.MORPH_CLOSE, kernel)

        n_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(flat_mask)

        detected_boxes = []
        total_masked_area = 0

        for i in range(1, n_labels):
            area = stats[i, cv2.CC_STAT_AREA]
            area_ratio = area / total_pixels

            if area_ratio < self.min_box_area_ratio or area_ratio > self.max_box_area_ratio:
                continue

            bx = stats[i, cv2.CC_STAT_LEFT]
            by = stats[i, cv2.CC_STAT_TOP]
            bw = stats[i, cv2.CC_STAT_WIDTH]
            bh = stats[i, cv2.CC_STAT_HEIGHT]

            # Aspect ratio check (not extreme 1-pixel line)
            aspect = float(bw) / bh if bh > 0 else 0
            if aspect < 0.20 or aspect > 5.0:
                continue

            # Rectangular compactness check: A digital box fills > 78% of its bounding rect
            extent = float(area) / (bw * bh)
            if extent < self.min_rectangular_extent:
                continue

            # Ensure bounding box is not touching all 4 boundaries (which would be full-frame)
            if bw >= (w - 10) and bh >= (h - 10):
                continue

            detected_boxes.append((bx, by, bw, bh))
            total_masked_area += (bw * bh)

        if detected_boxes:
            mask_ratio = min(1.0, total_masked_area / total_pixels)
            confidence = min(0.99, 0.80 + (mask_ratio * 0.3))
            details = f"Detected {len(detected_boxes)} digital occlusion mask(s) covering {mask_ratio*100:.1f}% of frame"
            return True, detected_boxes, mask_ratio, confidence, details

        return False, [], 0.0, 0.0, "No digital box masks detected"

    def detect_static_patch_masking(
        self, prev_frame: np.ndarray, curr_frame: np.ndarray
    ) -> Tuple[bool, List[Tuple[int, int, int, int]], float, str]:
        """
        Detects static background cloning / inpainting:
        An attacker copies a static background block across frames to conceal movement.
        """
        if prev_frame is None or curr_frame is None:
            return False, [], 0.0, "Prior frame not available"

        diff = cv2.absdiff(prev_frame, curr_frame)
        diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
        h, w = diff_gray.shape

        global_diff_mean = float(np.mean(diff_gray))
        if global_diff_mean < 1.0:
            return False, [], 0.0, "Entire frame static"

        zero_diff_mask = (diff_gray == 0).astype(np.uint8) * 255
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9))
        clean_mask = cv2.morphologyEx(zero_diff_mask, cv2.MORPH_OPEN, kernel)

        contours, _ = cv2.findContours(clean_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        static_patches = []
        for cnt in contours:
            area = cv2.contourArea(cnt)
            if area > (h * w * 0.03):
                x, y, bw, bh = cv2.boundingRect(cnt)
                static_patches.append((x, y, bw, bh))

        if static_patches and global_diff_mean > 4.0:
            details = f"Detected {len(static_patches)} unnatural static clone patch(es) amidst scene movement"
            return True, static_patches, 0.85, details

        return False, [], 0.0, "No static patch cloning detected"

    def analyze_frame_masking(
        self,
        frame: np.ndarray,
        prev_frame: Optional[np.ndarray] = None
    ) -> MaskingResult:
        """
        Executes complete multi-angle masking analysis on an individual frame.
        """
        annotated = frame.copy()
        h, w, _ = frame.shape

        # 1. Lens Occlusion Check
        is_lens, lens_conf, lens_msg = self.detect_lens_occlusion(frame)
        if is_lens:
            cv2.rectangle(annotated, (10, 10), (w - 10, h - 10), (0, 0, 255), 4)
            cv2.putText(annotated, f"ALERT: {lens_msg.upper()}", (20, 50),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.65, (0, 0, 255), 2)
            return MaskingResult(
                is_masked=True,
                mask_type="LENS_OCCLUSION",
                confidence=lens_conf,
                bounding_boxes=[(0, 0, w, h)],
                mask_area_ratio=1.0,
                details=lens_msg,
                annotated_frame=annotated
            )

        # 2. Digital Occlusion Box Check
        is_box, boxes, box_ratio, box_conf, box_msg = self.detect_digital_box_masking(frame)
        if is_box:
            for (bx, by, bw, bh) in boxes:
                # Highlight detected mask in bright red with yellow border
                cv2.rectangle(annotated, (bx, by), (bx + bw, by + bh), (0, 0, 255), 3)
                cv2.rectangle(annotated, (bx, by), (bx + bw, by + bh), (0, 255, 255), 1)
                cv2.putText(annotated, f"DIGITAL MASK DETECTED ({bw}x{bh})",
                            (bx, max(20, by - 8)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)

            return MaskingResult(
                is_masked=True,
                mask_type="DIGITAL_BOX_MASK",
                confidence=box_conf,
                bounding_boxes=boxes,
                mask_area_ratio=box_ratio,
                details=box_msg,
                annotated_frame=annotated
            )

        # 3. Static Background Clone Patch Check
        if prev_frame is not None:
            is_patch, patches, patch_conf, patch_msg = self.detect_static_patch_masking(prev_frame, frame)
            if is_patch:
                for (px, py, pw, ph) in patches:
                    cv2.rectangle(annotated, (px, py), (px + pw, py + ph), (255, 0, 255), 3)
                    cv2.putText(annotated, "STATIC CLONE PATCH", (px, max(20, py - 8)),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 0, 255), 2)
                return MaskingResult(
                    is_masked=True,
                    mask_type="STATIC_PATCH_CLONE",
                    confidence=patch_conf,
                    bounding_boxes=patches,
                    mask_area_ratio=sum([pw * ph for _, _, pw, ph in patches]) / (h * w),
                    details=patch_msg,
                    annotated_frame=annotated
                )

        return MaskingResult(
            is_masked=False,
            mask_type="NONE",
            confidence=0.0,
            bounding_boxes=[],
            mask_area_ratio=0.0,
            details="No masking or lens occlusion detected. Frame visually uncompromised.",
            annotated_frame=annotated
        )
