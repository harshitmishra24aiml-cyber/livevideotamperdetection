"""
Video Engine for Live Capture, Ingestion, and Synthetic CCTV Generation.
Supports physical webcams, pre-recorded video files, and animated synthetic feeds.
"""

import cv2
import time
import math
import numpy as np
from typing import Optional, Tuple, Generator


class SyntheticCCTVGenerator:
    """
    Generates realistic, animated CCTV surveillance frames.
    Useful for demonstration, headless testing, or when a physical webcam is unavailable.
    """

    def __init__(self, width: int = 640, height: int = 480, fps: int = 20):
        self.width = width
        self.height = height
        self.fps = fps
        self.frame_idx = 0
        self.start_time = time.time()

    def generate_frame(self) -> np.ndarray:
        """Renders the next frame with dynamic motion and timestamp."""
        self.frame_idx += 1
        t = self.frame_idx / self.fps

        # Dark surveillance-style background with slight gradient
        frame = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        # Background subtle room elements (hallway perspective)
        cv2.line(frame, (0, 0), (self.width // 2, self.height // 2), (35, 40, 45), 2)
        cv2.line(frame, (self.width, 0), (self.width // 2, self.height // 2), (35, 40, 45), 2)
        cv2.line(frame, (0, self.height), (self.width // 2, self.height // 2), (35, 40, 45), 2)
        cv2.line(frame, (self.width, self.height), (self.width // 2, self.height // 2), (35, 40, 45), 2)
        cv2.rectangle(frame, (self.width // 4, self.height // 4), (3 * self.width // 4, 3 * self.height // 4), (45, 50, 55), 2)

        # Draw a moving security object (e.g. simulated monitored target)
        cx = int(self.width / 2 + 180 * math.sin(t * 1.5))
        cy = int(self.height / 2 + 90 * math.cos(t * 1.8))
        radius = 24

        # Glow / target circle
        cv2.circle(frame, (cx, cy), radius + 8, (0, 140, 255), 1)
        cv2.circle(frame, (cx, cy), radius, (0, 200, 255), -1)
        # Target crosshair
        cv2.line(frame, (cx - 35, cy), (cx + 35, cy), (0, 255, 255), 1)
        cv2.line(frame, (cx, cy - 35), (cx, cy + 35), (0, 255, 255), 1)
        cv2.putText(frame, f"TARGET-01 [ACTIVE]", (cx + 12, cy - 12),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 255), 1)

        # Another secondary object moving in counter-orbit
        bx = int(self.width / 2 - 140 * math.cos(t * 0.9))
        by = int(self.height / 2 + 110 * math.sin(t * 1.1))
        cv2.rectangle(frame, (bx - 18, by - 18), (bx + 18, by + 18), (80, 220, 100), -1)
        cv2.putText(frame, "PKG-A", (bx - 14, by + 5), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 0), 1)

        # CCTV On-Screen Display (OSD) Header
        cv2.putText(frame, "CAM-01 [EVIDENCE VAULT NORTH]", (20, 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.65, (220, 220, 220), 2)
        cur_datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ms = int((time.time() % 1) * 1000)
        cv2.putText(frame, f"TIME: {cur_datetime}.{ms:03d} UTC", (20, 58),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.52, (0, 255, 0), 1)

        # Surveillance crosshair at screen center
        mid_x, mid_y = self.width // 2, self.height // 2
        cv2.drawMarker(frame, (mid_x, mid_y), (100, 100, 100), cv2.MARKER_CROSS, 20, 1)

        # Subtle noise to simulate camera sensor jitter
        noise = np.random.randint(0, 8, (self.height, self.width, 3), dtype=np.uint8)
        frame = cv2.add(frame, noise)

        return frame


class VideoStreamSource:
    """
    Unified video source supporting:
    1. 'webcam' (default index 0)
    2. 'file' (path to video file)
    3. 'synthetic' (synthetic CCTV generator)
    """

    def __init__(self, mode: str = "webcam", device_index: int = 0, file_path: Optional[str] = None):
        self.mode = mode.lower()
        self.device_index = device_index
        self.file_path = file_path
        self.cap: Optional[cv2.VideoCapture] = None
        self.synthetic_gen: Optional[SyntheticCCTVGenerator] = None
        self.is_opened = False

        self._initialize()

    def _initialize(self):
        if self.mode == "synthetic":
            self.synthetic_gen = SyntheticCCTVGenerator()
            self.is_opened = True
        elif self.mode == "file":
            if not self.file_path:
                raise ValueError("file_path must be provided when mode is 'file'")
            self.cap = cv2.VideoCapture(self.file_path)
            self.is_opened = self.cap.isOpened()
        else:
            # Webcam mode
            self.cap = cv2.VideoCapture(self.device_index)
            self.is_opened = self.cap.isOpened()

    def read(self) -> Tuple[bool, Optional[np.ndarray]]:
        """Reads the next frame from the configured stream."""
        if self.mode == "synthetic":
            frame = self.synthetic_gen.generate_frame()
            return True, frame

        if self.cap is not None and self.is_opened:
            ret, frame = self.cap.read()
            # If video file reached the end, loop or return False
            if not ret and self.mode == "file":
                self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                ret, frame = self.cap.read()
            return ret, frame

        return False, None

    def release(self):
        """Releases the camera or video capture handle."""
        if self.cap is not None:
            self.cap.release()
            self.is_opened = False


def add_cryptographic_hud(
    frame: np.ndarray,
    frame_index: int,
    frame_hash: str,
    chain_hash: str,
    status: str = "CHAIN SECURED",
    is_valid: bool = True
) -> np.ndarray:
    """
    Renders an informative cryptographic Heads-Up Display (HUD) overlay
    directly on a preview copy of the video frame.
    Does NOT mutate the original raw frame.
    """
    overlay = frame.copy()
    h, w, _ = overlay.shape

    # Semi-transparent dark banner at bottom
    banner_height = 80
    sub_img = overlay[h - banner_height:h, 0:w]
    dark_rect = np.zeros(sub_img.shape, dtype=np.uint8)
    res = cv2.addWeighted(sub_img, 0.3, dark_rect, 0.7, 1.0)
    overlay[h - banner_height:h, 0:w] = res

    # Status badge color
    status_color = (0, 255, 0) if is_valid else (0, 0, 255)

    # Top right security badge
    cv2.rectangle(overlay, (w - 220, 10), (w - 10, 42), (20, 20, 20), -1)
    cv2.rectangle(overlay, (w - 220, 10), (w - 10, 42), status_color, 1)
    cv2.circle(overlay, (w - 202, 26), 6, status_color, -1)
    cv2.putText(overlay, status, (w - 188, 31), cv2.FONT_HERSHEY_SIMPLEX, 0.48, (255, 255, 255), 1)

    # Top left Frame Counter
    cv2.rectangle(overlay, (10, 10), (190, 42), (20, 20, 20), -1)
    cv2.rectangle(overlay, (10, 10), (190, 42), (80, 80, 80), 1)
    cv2.putText(overlay, f"FRAME #{frame_index:06d}", (22, 32),
                cv2.FONT_HERSHEY_SIMPLEX, 0.58, (0, 255, 255), 2)

    # Bottom Banner Details: Frame Hash & Hash Chain
    short_frame = f"{frame_hash[:12]}...{frame_hash[-8:]}" if len(frame_hash) >= 20 else frame_hash
    short_chain = f"{chain_hash[:12]}...{chain_hash[-8:]}" if len(chain_hash) >= 20 else chain_hash

    cv2.putText(overlay, f"SHA-256 (Hi): {short_frame}", (15, h - 50),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
    cv2.putText(overlay, f"CHAIN (Ci):   {short_chain}", (15, h - 20),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 180), 1)
    cv2.putText(overlay, f"Ci = SHA256(Ci-1 || i || Hi)", (w - 260, h - 20),
                cv2.FONT_HERSHEY_SIMPLEX, 0.42, (150, 150, 150), 1)

    return overlay
