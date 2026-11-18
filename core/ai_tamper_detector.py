"""
AI & Computer Vision Forensic Analysis Engine.
Provides multi-modal spatial and temporal anomaly detection:
1. Error Level Analysis (ELA) - Detects compression and quantization inconsistencies
2. Laplacian Gradient Discontinuity - Identifies spliced, blurred, or pasted regions
3. Dense Optical Flow Temporal Consistency - Detects abrupt motion jumps from dropped/swapped frames
4. Composite AI Forensic Anomaly Score (0.0 to 1.0)
"""

import cv2
import numpy as np
from typing import Dict, Any, Tuple, Optional, List


class AITamperDetector:
    """
    Computer Vision and statistical forensic analyzer that complements
    the SHA-256 cryptographic hash chain with visual artifact detection.
    """

    def __init__(self, ela_scale: int = 20, ela_quality: int = 90):
        self.ela_scale = ela_scale
        self.ela_quality = ela_quality

    def compute_ela(self, frame: np.ndarray) -> Tuple[np.ndarray, float]:
        """
        Error Level Analysis (ELA):
        Compresses frame in-memory to JPEG and measures the pixel-level difference.
        Altered, spliced, or digitally modified areas compress at different error rates
        than the surrounding unmodified camera sensor pixels.
        Returns: (ela_visual_map, mean_error_intensity)
        """
        if frame is None:
            raise ValueError("Frame cannot be None")

        # Encode frame to JPEG memory buffer at fixed quality
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), self.ela_quality]
        _, enc_img = cv2.imencode(".jpg", frame, encode_param)

        # Decode back to raw BGR
        resaved = cv2.imdecode(enc_img, cv2.IMREAD_COLOR)

        # Absolute difference between original and resaved
        diff = cv2.absdiff(frame, resaved)

        # Scale difference to enhance visibility
        ela_map = cv2.convertScaleAbs(diff, alpha=self.ela_scale, beta=0)

        # Compute mean ELA anomaly intensity
        mean_err = float(np.mean(diff))
        return ela_map, mean_err

    def detect_edge_discontinuities(self, frame: np.ndarray) -> Tuple[np.ndarray, float]:
        """
        Laplacian Gradient Discontinuity:
        Detects artificial high-frequency sharp borders or localized blur artifacts
        typical of pasted objects, digital stamps, or cloned regions.
        """
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        lap_abs = np.uint8(np.absolute(laplacian))

        # Localized variance of gradient
        local_mean = cv2.blur(lap_abs, (15, 15))
        local_sqr_mean = cv2.blur(lap_abs ** 2, (15, 15))
        local_var = local_sqr_mean - local_mean ** 2

        norm_var = cv2.normalize(local_var, None, 0, 255, cv2.NORM_MINMAX, dtype=cv2.CV_8U)
        edge_anomaly_score = float(np.std(laplacian))
        return norm_var, edge_anomaly_score

    def compute_optical_flow_delta(
        self, prev_frame: np.ndarray, curr_frame: np.ndarray
    ) -> Tuple[float, np.ndarray]:
        """
        Dense Optical Flow Temporal Consistency:
        Computes Gunnar Farneback optical flow between consecutive frames.
        Detects abrupt motion jumps caused by dropped frames, temporal splicing,
        or rearranged frame sequences.
        """
        prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
        curr_gray = cv2.cvtColor(curr_frame, cv2.COLOR_BGR2GRAY)

        flow = cv2.calcOpticalFlowFarneback(
            prev_gray, curr_gray, None,
            pyr_scale=0.5, levels=3, winsize=15,
            iterations=3, poly_n=5, poly_sigma=1.2, flags=0
        )

        # Calculate magnitude and angle of 2D flow vectors
        mag, ang = cv2.cartToPolar(flow[..., 0], flow[..., 1])
        mean_motion = float(np.mean(mag))

        # Render HSV visualization of optical flow
        hsv = np.zeros_like(prev_frame)
        hsv[..., 1] = 255
        hsv[..., 0] = ang * 180 / np.pi / 2
        hsv[..., 2] = cv2.normalize(mag, None, 0, 255, cv2.NORM_MINMAX)
        flow_rgb = cv2.cvtColor(hsv, cv2.COLOR_HSV2BGR)

        return mean_motion, flow_rgb

    def analyze_frame_anomaly(
        self,
        frame: np.ndarray,
        prev_frame: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Executes full multi-modal forensic inspection on an individual frame.
        Produces an overall AI Anomaly Score (0.0 to 1.0).
        """
        ela_map, ela_intensity = self.compute_ela(frame)
        edge_map, edge_score = self.detect_edge_discontinuities(frame)

        motion_delta = 0.0
        flow_vis = None
        if prev_frame is not None:
            motion_delta, flow_vis = self.compute_optical_flow_delta(prev_frame, frame)

        # High ELA error (> 6.0) or high edge spikiness indicates spatial editing
        ela_norm = min(1.0, max(0.0, (ela_intensity - 2.5) / 8.0))
        edge_norm = min(1.0, max(0.0, (edge_score - 10.0) / 40.0))

        # Composite score
        composite_score = float(0.6 * ela_norm + 0.4 * edge_norm)
        is_suspicious = composite_score > 0.45

        return {
            "is_suspicious": is_suspicious,
            "anomaly_score": round(composite_score, 4),
            "ela_intensity": round(ela_intensity, 3),
            "edge_anomaly_score": round(edge_score, 3),
            "optical_motion_delta": round(motion_delta, 3),
            "ela_map": ela_map,
            "edge_map": edge_map,
            "flow_vis": flow_vis
        }
