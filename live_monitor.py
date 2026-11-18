"""
Real-Time Dual-Screen Video Integrity & Live Masking/Tamper Sentinel.
Displays side-by-side:
- Left: Live Ingestion Feed (Webcam / Synthetic CCTV)
- Right: Real-time Cryptographic Sentinel & Masking Tamper Alarm

Interactive Controls:
- Press 'M': Inject on-the-fly Digital Masking Attack (redaction box)
- Press 'T': Inject on-the-fly Pixel Tamper Stamp
- Press 'L': Inject on-the-fly Camera Lens Blackout
- Press 'R': Reset & re-anchor integrity chain
- Press 'Q': Quit
"""

import cv2
import time
import argparse
import numpy as np

from core.hash_chain import GENESIS_HASH, sha256_bytes, create_chain_hash
from core.video_engine import VideoStreamSource
from core.masking_detector import MaskingDetector


def run_live_monitor(source_mode: str = "synthetic", device_index: int = 0):
    print("\n========================================================")
    print(" LIVE DUAL-SCREEN VIDEO INTEGRITY & MASKING MONITOR")
    print("========================================================")
    print("Interactive Live Controls:")
    print("  [M] - Inject Digital Masking Attack (Redaction Box)")
    print("  [T] - Inject Pixel Alteration Tamper Stamp")
    print("  [L] - Inject Camera Lens Blackout / Occlusion")
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

    mask_detector = MaskingDetector()
    previous_chain = GENESIS_HASH
    frame_index = 0
    active_attack = "NONE"  # "NONE", "MASK_BOX", "TAMPER_STAMP", "LENS_BLACKOUT"
    tamper_count = 0
    alert_flasher = 0
    first_tamper_frame = None

    window_name = "Live Crypto Sentinel - Dual-Screen Video Integrity & Masking Monitor"
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

            # Apply live injected attack if active
            monitored_frame = clean_frame.copy()
            if active_attack == "MASK_BOX":
                # Solid black digital redaction box
                bx, by = int(w * 0.25), int(h * 0.25)
                bw, bh = int(w * 0.45), int(h * 0.45)
                cv2.rectangle(monitored_frame, (bx, by), (bx + bw, by + bh), (0, 0, 0), -1)
            elif active_attack == "TAMPER_STAMP":
                tamper_box_x = int(w * 0.35)
                tamper_box_y = int(h * 0.35)
                box_w, box_h = int(w * 0.3), int(h * 0.3)
                cv2.rectangle(monitored_frame, (tamper_box_x, tamper_box_y),
                              (tamper_box_x + box_w, tamper_box_y + box_h), (0, 0, 255), -1)
                cv2.putText(monitored_frame, "TAMPER ATTACK", (tamper_box_x + 10, tamper_box_y + 40),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            elif active_attack == "LENS_BLACKOUT":
                monitored_frame[:] = 2

            # Compute expected hash from pristine source
            expected_hash = sha256_bytes(clean_frame.tobytes())
            expected_chain = create_chain_hash(previous_chain, frame_index, expected_hash)

            # Compute actual hash from monitored channel
            actual_hash = sha256_bytes(monitored_frame.tobytes())
            actual_chain = create_chain_hash(previous_chain, frame_index, actual_hash)

            # Dual verification check: Hashing + Masking
            is_frame_authentic = (actual_hash == expected_hash)
            is_chain_authentic = (actual_chain == expected_chain)
            mask_res = mask_detector.analyze_frame_masking(monitored_frame)

            is_secure = is_frame_authentic and is_chain_authentic and not mask_res.is_masked

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
            cv2.rectangle(pane1, (0, 0), (w, 40), (25, 25, 25), -1)
            cv2.putText(pane1, f"CAMERA INGESTION [SOURCE: {source_mode.upper()}]", (15, 26),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, (220, 220, 220), 2)
            cv2.circle(pane1, (w - 25, 20), 7, (0, 255, 0), -1)

            cv2.rectangle(pane1, (0, h - 50), (w, h), (20, 20, 20), -1)
            cv2.putText(pane1, f"Frame: #{frame_index:05d} | SHA256: {expected_hash[:12]}...", (15, h - 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (180, 180, 180), 1)
            cv2.putText(pane1, f"Chain Link (Ci): {expected_chain[:16]}...", (15, h - 10),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 220, 255), 1)

            # ==========================================
            # RENDER PANE 2: INTEGRITY & MASK SENTINEL
            # ==========================================
            pane2 = monitored_frame.copy()
            alert_flasher = (alert_flasher + 1) % 10

            if is_secure:
                status_color = (0, 220, 0)
                status_text = "INTEGRITY SECURED: 100% AUTHENTIC"
                border_color = (0, 180, 0)
            else:
                status_color = (0, 0, 255) if alert_flasher < 5 else (0, 0, 180)
                if mask_res.is_masked:
                    status_text = f"ALERT: {mask_res.mask_type} DETECTED! (FRAME #{first_tamper_frame})"
                else:
                    status_text = f"TAMPER ALERT! CHAIN BROKEN AT FRAME #{first_tamper_frame}"
                border_color = (0, 0, 255)

                # Draw targeting boxes around detected masks
                if mask_res.bounding_boxes:
                    for (bx, by, bw, bh) in mask_res.bounding_boxes:
                        cv2.rectangle(pane2, (bx, by), (bx + bw, by + bh), (0, 0, 255), 3)
                        cv2.putText(pane2, f"MASK DETECTED ({bw}x{bh})", (bx, max(20, by - 8)),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 2)
                else:
                    diff = cv2.absdiff(clean_frame, monitored_frame)
                    diff_gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
                    _, thresh = cv2.threshold(diff_gray, 5, 255, cv2.THRESH_BINARY)
                    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    for c in contours:
                        if cv2.contourArea(c) > 20:
                            x, y, bw, bh = cv2.boundingRect(c)
                            cv2.rectangle(pane2, (x, y), (x + bw, y + bh), (0, 0, 255), 3)

            cv2.rectangle(pane2, (0, 0), (w, 40), (20, 20, 20), -1)
            cv2.putText(pane2, status_text, (15, 26),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.48, status_color, 2)

            cv2.rectangle(pane2, (0, h - 50), (w, h), (15, 15, 15), -1)
            if is_secure:
                cv2.putText(pane2, f"Cryptographic Verification: VALID LINK", (15, h - 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 0), 1)
                cv2.putText(pane2, f"Violations: {tamper_count} | Press 'M' (Mask), 'T' (Stamp)", (15, h - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (200, 200, 200), 1)
            else:
                diag_msg = f"Mask: {mask_res.mask_type}" if mask_res.is_masked else "Pixel Hash Mismatch!"
                cv2.putText(pane2, f"{diag_msg} | H' != H", (15, h - 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 1)
                cv2.putText(pane2, f"Violations: {tamper_count} | Press 'R' to reset", (15, h - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 255), 1)

            cv2.rectangle(pane2, (0, 0), (w - 1, h - 1), border_color, 3)

            dual_screen = np.hstack([pane1, pane2])
            cv2.imshow(window_name, dual_screen)

            key = cv2.waitKey(30) & 0xFF
            if key == ord('q') or key == 27:
                break
            elif key == ord('m'):
                active_attack = "NONE" if active_attack == "MASK_BOX" else "MASK_BOX"
                print(f"[*] Digital Masking Attack toggled: {active_attack}")
            elif key == ord('t'):
                active_attack = "NONE" if active_attack == "TAMPER_STAMP" else "TAMPER_STAMP"
                print(f"[*] Pixel Tamper Stamp toggled: {active_attack}")
            elif key == ord('l'):
                active_attack = "NONE" if active_attack == "LENS_BLACKOUT" else "LENS_BLACKOUT"
                print(f"[*] Lens Occlusion toggled: {active_attack}")
            elif key == ord('r'):
                active_attack = "NONE"
                tamper_count = 0
                first_tamper_frame = None
                previous_chain = actual_chain
                print("[*] Sentinel reset and re-anchored to current chain state.")

    finally:
        stream.release()
        cv2.destroyAllWindows()
        print("\n[+] Live monitor closed cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Dual-Screen Video Integrity & Masking Monitor")
    parser.add_argument("--webcam", type=int, default=0, help="Webcam device index (default: 0)")
    parser.add_argument("--synthetic", action="store_true", help="Force animated synthetic CCTV stream")
    args = parser.parse_args()

    mode = "synthetic" if args.synthetic else "webcam"
    run_live_monitor(source_mode=mode, device_index=args.webcam)
