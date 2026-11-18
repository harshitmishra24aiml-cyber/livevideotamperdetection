"""
Real-Time Dual-Screen Video Integrity & Live Tamper Detection Monitor.
Displays side-by-side:
- Left: Live Ingestion Feed (Webcam / Synthetic CCTV)
- Right: Real-time Cryptographic Sentinel & Tamper Alarm Monitor

Interactive Controls:
- Press 'T': Inject live pixel tampering into stream
- Press 'R': Reset / re-anchor chain
- Press 'Q': Quit
"""

import cv2
import time
import argparse
import numpy as np

from core.hash_chain import GENESIS_HASH, sha256_bytes, create_chain_hash
from core.video_engine import VideoStreamSource


def run_live_monitor(source_mode: str = "synthetic", device_index: int = 0):
    print("\n========================================================")
    print(" LIVE DUAL-SCREEN CRYPTOGRAPHIC VIDEO INTEGRITY MONITOR")
    print("========================================================")
    print("Controls:")
    print("  [T] - Inject on-the-fly Tampering Attack (Simulate Tamper)")
    print("  [R] - Reset & Re-anchor Integrity Chain")
    print("  [Q] - Quit Monitoring")
    print("========================================================\n")

    stream = VideoStreamSource(mode=source_mode, device_index=device_index)
    if not stream.is_opened:
        if source_mode == "webcam":
            print("[!] Physical webcam unavailable. Falling back to Synthetic CCTV stream.")
            stream = VideoStreamSource(mode="synthetic")
        else:
            print("[!] Could not open video source.")
            return

    previous_chain = GENESIS_HASH
    frame_index = 0
    tamper_injected = False
    tamper_count = 0
    alert_flasher = 0
    first_tamper_frame = None

    window_name = "Live Crypto Sentinel - Dual-Screen Video Integrity Monitor"
    cv2.namedWindow(window_name, cv2.WINDOW_AUTOSIZE)

    try:
        while True:
            ret, frame = stream.read()
            if not ret or frame is None:
                break

            frame_index += 1
            h, w, _ = frame.shape

            # Ground truth authentic frame
            clean_frame = frame.copy()

            # If tamper is active, deliberately alter pixels in the transmitted frame
            monitored_frame = clean_frame.copy()
            if tamper_injected:
                # Maliciously draw an unauthorized modification
                tamper_box_x = int(w * 0.35)
                tamper_box_y = int(h * 0.35)
                box_w, box_h = int(w * 0.3), int(h * 0.3)
                cv2.rectangle(monitored_frame, (tamper_box_x, tamper_box_y),
                              (tamper_box_x + box_w, tamper_box_y + box_h), (0, 0, 255), -1)
                cv2.putText(monitored_frame, "TAMPER ATTACK", (tamper_box_x + 10, tamper_box_y + 40),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)

            # Compute expected hash from pristine source
            expected_hash = sha256_bytes(clean_frame.tobytes())
            expected_chain = create_chain_hash(previous_chain, frame_index, expected_hash)

            # Compute actual hash from monitored channel
            actual_hash = sha256_bytes(monitored_frame.tobytes())
            actual_chain = create_chain_hash(previous_chain, frame_index, actual_hash)

            # Verification check
            is_frame_authentic = (actual_hash == expected_hash)
            is_chain_authentic = (actual_chain == expected_chain)
            is_secure = is_frame_authentic and is_chain_authentic

            if not is_secure:
                tamper_count += 1
                if first_tamper_frame is None:
                    first_tamper_frame = frame_index
            else:
                previous_chain = expected_chain

            # ==========================================
            # RENDER PANE 1: LIVE INGESTION FEED
            # ==========================================
            pane1 = clean_frame.copy()
            # Top banner
            cv2.rectangle(pane1, (0, 0), (w, 40), (25, 25, 25), -1)
            cv2.putText(pane1, f"CAMERA INGESTION [SOURCE: {source_mode.upper()}]", (15, 26),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, (220, 220, 220), 2)
            cv2.circle(pane1, (w - 25, 20), 7, (0, 255, 0), -1)

            # Bottom metadata
            cv2.rectangle(pane1, (0, h - 50), (w, h), (20, 20, 20), -1)
            cv2.putText(pane1, f"Frame: #{frame_index:05d} | SHA256: {expected_hash[:12]}...", (15, h - 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (180, 180, 180), 1)
            cv2.putText(pane1, f"Chain Link (Ci): {expected_chain[:16]}...", (15, h - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 220, 255), 1)

            # ==========================================
            # RENDER PANE 2: INTEGRITY SENTINEL (MONITOR)
            # ==========================================
            pane2 = monitored_frame.copy()
            alert_flasher = (alert_flasher + 1) % 10

            if is_secure:
                status_color = (0, 220, 0)
                status_text = "INTEGRITY SECURED: 100% AUTHENTIC"
                border_color = (0, 180, 0)
            else:
                status_color = (0, 0, 255) if alert_flasher < 5 else (0, 0, 180)
                status_text = f"TAMPER ALERT! CHAIN BROKEN AT FRAME #{first_tamper_frame}"
                border_color = (0, 0, 255)

                # Draw red targeting contours around detected discrepancy
                diff = cv2.absdiff(clean_frame, monitored_frame)
                diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
                _, thresh = cv2.threshold(diff_gray, 5, 255, cv2.THRESH_BINARY)
                contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                for c in contours:
                    if cv2.contourArea(c) > 20:
                        x, y, bw, bh = cv2.boundingRect(c)
                        cv2.rectangle(pane2, (x, y), (x + bw, y + bh), (0, 0, 255), 3)

            # Pane 2 Top status bar
            cv2.rectangle(pane2, (0, 0), (w, 40), (20, 20, 20), -1)
            cv2.putText(pane2, status_text, (15, 26),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.52, status_color, 2)

            # Pane 2 Bottom Diagnostics
            cv2.rectangle(pane2, (0, h - 50), (w, h), (15, 15, 15), -1)
            if is_secure:
                cv2.putText(pane2, f"Cryptographic Verification: VALID LINK", (15, h - 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 0), 1)
                cv2.putText(pane2, f"Violations: {tamper_count} | Press 'T' to tamper", (15, h - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 200, 200), 1)
            else:
                cv2.putText(pane2, f"Pixel Hash Mismatch! H' != H", (15, h - 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1)
                cv2.putText(pane2, f"Violations: {tamper_count} | Press 'R' to reset", (15, h - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 255), 1)

            # Add border around Pane 2
            cv2.rectangle(pane2, (0, 0), (w - 1, h - 1), border_color, 3)

            # Combine Side-by-Side into Dual Screen
            dual_screen = np.hstack([pane1, pane2])
            cv2.imshow(window_name, dual_screen)

            key = cv2.waitKey(30) & 0xFF
            if key == ord('q') or key == 27:
                break
            elif key == ord('t') or key == ord('m'):
                tamper_injected = not tamper_injected
                print(f"[*] Tamper state toggled: {'ACTIVE (Tampering)' if tamper_injected else 'OFF (Clean)'}")
            elif key == ord('r'):
                tamper_injected = False
                tamper_count = 0
                first_tamper_frame = None
                previous_chain = actual_chain
                print("[*] Sentinel reset and re-anchored to current chain state.")

    finally:
        stream.release()
        cv2.destroyAllWindows()
        print("\n[+] Live monitor closed cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Dual-Screen Video Integrity Tamper Monitor")
    parser.add_argument("--webcam", type=int, default=0, help="Webcam device index (default: 0)")
    parser.add_argument("--synthetic", action="store_true", help="Force animated synthetic CCTV stream")
    args = parser.parse_args()

    mode = "synthetic" if args.synthetic else "webcam"
    run_live_monitor(source_mode=mode, device_index=args.webcam)
