"""
Live Video Tamper Detection System - Recording & Hash-Chain Generation
Captures video frames, computes SHA-256 digests, and generates a tamper-evident cryptographic hash chain.
"""

import os
import cv2
import json
import time
import argparse
from core.hash_chain import GENESIS_HASH, sha256_bytes, sha256_str, compute_frame_hash, create_chain_hash
from core.video_engine import VideoStreamSource, add_cryptographic_hud
from core.audit_logger import AuditLogger

FRAME_DIR = "evidence/frames"
LOG_FILE = "evidence/hash_log.jsonl"


def sha256(data: bytes) -> str:
    """Calculate SHA-256 hash from byte stream."""
    return sha256_bytes(data)


def create_chain(previous_hash: str, index: int, frame_hash: str) -> str:
    """Generate chained hash: Ci = SHA256(Ci-1 || index || Hi)"""
    return create_chain_hash(previous_hash, index, frame_hash)


def start_recording(
    source_mode: str = "webcam",
    device_index: int = 0,
    video_file: str = None,
    max_frames: int = 0,
    show_preview: bool = True
):
    """
    Starts live video recording and cryptographic hash-chain generation.
    """
    logger = AuditLogger()
    logger.open_session(reset=True)

    print(f"\n==================================================")
    print(f" LIVE VIDEO INTEGRITY RECORDER (SHA-256 HASH CHAIN)")
    print(f"==================================================")
    print(f"Source mode:     {source_mode.upper()}")
    print(f"Frame storage:   {FRAME_DIR}")
    print(f"Audit log:       {LOG_FILE}")
    print(f"Initial chain:   {GENESIS_HASH}")
    print(f"==================================================")

    # Initialize video source
    try:
        stream = VideoStreamSource(
            mode=source_mode,
            device_index=device_index,
            file_path=video_file
        )
    except Exception as e:
        print(f"[!] Error opening video source: {e}")
        return

    # Check if webcam opened; if not, suggest/fallback to synthetic
    if not stream.is_opened:
        if source_mode == "webcam":
            print("[!] Physical webcam could not be opened.")
            print("[*] Automatically falling back to Synthetic CCTV Surveillance Feed...")
            stream = VideoStreamSource(mode="synthetic")
        else:
            print("[!] Video stream could not be opened. Exiting.")
            return

    previous_hash = GENESIS_HASH
    index = 0
    print("\n[+] Recording started. Press 'Q' or Ctrl+C to stop.\n")

    try:
        while True:
            success, frame = stream.read()
            if not success or frame is None:
                print("\n[*] End of video stream reached.")
                break

            index += 1

            # Lossless raw frame bytes & SHA-256 digest (Hi)
            frame_bytes = frame.tobytes()
            frame_hash = sha256(frame_bytes)

            # Generate hash chain node (Ci)
            chain_hash = create_chain(previous_hash, index, frame_hash)

            # Store frame losslessly (PNG) and write audit log
            logger.log_frame(
                frame_index=index,
                frame_hash=frame_hash,
                chain_hash=chain_hash,
                frame=frame
            )

            previous_hash = chain_hash

            # Console ticker
            short_frame = f"{frame_hash[:8]}...{frame_hash[-6:]}"
            short_chain = f"{chain_hash[:8]}...{chain_hash[-6:]}"
            print(f"\r[Frame #{index:04d}] SHA-256: {short_frame} | Chain: {short_chain}", end="", flush=True)

            # Interactive preview with cryptographic HUD
            if show_preview:
                hud_frame = add_cryptographic_hud(
                    frame=frame,
                    frame_index=index,
                    frame_hash=frame_hash,
                    chain_hash=chain_hash,
                    status="CHAIN SECURED",
                    is_valid=True
                )
                cv2.imshow("Video Integrity Monitoring - Live SHA-256 Chain", hud_frame)
                key = cv2.waitKey(1) & 0xFF
                if key == ord("q") or key == 27:
                    print("\n[!] User interrupted recording (Q pressed).")
                    break

            if max_frames > 0 and index >= max_frames:
                print(f"\n[*] Target frame count ({max_frames}) reached.")
                break

    except KeyboardInterrupt:
        print("\n[!] Recording interrupted by user.")
    finally:
        stream.release()
        if show_preview:
            cv2.destroyAllWindows()
        manifest = logger.close_session()

    print("\n==================================================")
    print(" RECORDING COMPLETED SUCCESSFULLY")
    print(f" Total frames recorded: {index}")
    print(f" Final Chain Hash:      {manifest['final_chain_hash']}")
    print(f" Session Root Signature:{manifest['session_signature']}")
    print(f" All frames saved to:   {FRAME_DIR}")
    print(f" Audit log saved to:    {LOG_FILE}")
    print("==================================================\n")
    print("Next step: Run 'python verifier.py' to verify cryptographic integrity.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live Video Integrity Capture using SHA-256 Hash Chain")
    parser.add_argument("--webcam", type=int, default=0, help="Webcam device index (default: 0)")
    parser.add_argument("--synthetic", action="store_true", help="Use animated synthetic CCTV feed")
    parser.add_argument("--file", type=str, default=None, help="Path to input video file")
    parser.add_argument("--frames", type=int, default=0, help="Maximum number of frames to capture (0 = unlimited)")
    parser.add_argument("--no-preview", action="store_true", help="Disable OpenCV GUI preview window")

    args = parser.parse_args()

    mode = "webcam"
    if args.synthetic:
        mode = "synthetic"
    elif args.file:
        mode = "file"

    start_recording(
        source_mode=mode,
        device_index=args.webcam,
        video_file=args.file,
        max_frames=args.frames,
        show_preview=not args.no_preview
    )
