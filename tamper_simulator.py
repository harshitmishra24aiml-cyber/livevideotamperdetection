"""
Tamper Attack Simulator for Live Video Integrity System.
Simulates real-world cyber and forensic attacks:
1. Pixel Modification (Altering video frame pixels)
2. Frame Deletion (Deleting evidence frame)
3. Frame Reordering (Swapping frames in sequence)
4. Audit Log Forgery (Tampering with JSONL records)
5. Restore clean baseline
"""

import os
import cv2
import json
import shutil
import argparse
from core.audit_logger import AuditLogger

FRAME_DIR = "evidence/frames"
LOG_FILE = "evidence/hash_log.jsonl"
SNAPSHOT_DIR = "evidence/.snapshot_clean"


def modify_frame(frame_index: int = 2, attack_type: str = "watermark") -> bool:
    """
    Modifies the pixels of a specific frame to simulate tampering.
    """
    filename = f"frame_{frame_index:06d}.png"
    filepath = os.path.join(FRAME_DIR, filename)

    if not os.path.exists(filepath):
        print(f"[!] Frame {filename} not found at {filepath}")
        return False

    img = cv2.imread(filepath)
    if img is None:
        print(f"[!] Could not read {filepath}")
        return False

    h, w, _ = img.shape

    if attack_type == "watermark":
        # Draw prominent red tamper box and text
        cv2.rectangle(img, (w // 4, h // 4), (3 * w // 4, 3 * h // 4), (0, 0, 255), 4)
        cv2.putText(img, "UNAUTHORIZED TAMPER", (w // 4 + 10, h // 2),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
    elif attack_type == "single_pixel":
        # Modify just a single pixel (subtle steganographic attack)
        img[h // 2, w // 2] = (img[h // 2, w // 2] + 1) % 256
    elif attack_type == "blur":
        # Blur an object area
        roi = img[h // 4: 3 * h // 4, w // 4: 3 * w // 4]
        img[h // 4: 3 * h // 4, w // 4: 3 * w // 4] = cv2.GaussianBlur(roi, (25, 25), 0)
    elif attack_type == "mask_box":
        # Digital privacy / redaction mask: solid black occlusion box over central region
        bx, by = int(w * 0.25), int(h * 0.25)
        bw, bh = int(w * 0.45), int(h * 0.45)
        cv2.rectangle(img, (bx, by), (bx + bw, by + bh), (0, 0, 0), -1)
    elif attack_type == "mask_lens":
        # Physical camera lens occlusion: complete blackout / covered lens
        img[:] = 2  # Near total darkness
    elif attack_type == "mask_spray":
        # Spray paint / severe obstruction
        img[:] = cv2.GaussianBlur(img, (55, 55), 0) // 2

    # Save back to disk
    cv2.imwrite(filepath, img, [cv2.IMWRITE_PNG_COMPRESSION, 3])
    print(f"[+] ATTACK SUCCESSFUL: Frame #{frame_index:04d} ({filename}) modified with '{attack_type}'.")
    return True


def delete_frame(frame_index: int = 3) -> bool:
    """
    Deletes a specific frame file to simulate frame dropping / deletion attack.
    """
    filename = f"frame_{frame_index:06d}.png"
    filepath = os.path.join(FRAME_DIR, filename)

    if not os.path.exists(filepath):
        print(f"[!] Frame {filename} already does not exist.")
        return False

    os.remove(filepath)
    print(f"[+] ATTACK SUCCESSFUL: Frame #{frame_index:04d} ({filename}) deleted from storage.")
    return True


def swap_frames(frame_a: int = 2, frame_b: int = 3) -> bool:
    """
    Swaps the content of two frames to simulate a reordering / replay attack.
    """
    file_a = os.path.join(FRAME_DIR, f"frame_{frame_a:06d}.png")
    file_b = os.path.join(FRAME_DIR, f"frame_{frame_b:06d}.png")

    if not os.path.exists(file_a) or not os.path.exists(file_b):
        print("[!] One or both frame files do not exist.")
        return False

    tmp_file = os.path.join(FRAME_DIR, "frame_tmp_swap.png")
    shutil.move(file_a, tmp_file)
    shutil.move(file_b, file_a)
    shutil.move(tmp_file, file_b)
    print(f"[+] ATTACK SUCCESSFUL: Frame #{frame_a:04d} and Frame #{frame_b:04d} content swapped.")
    return True


def corrupt_log(line_number: int = 2) -> bool:
    """
    Simulates malicious log alteration by changing a recorded chain hash.
    """
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return False

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if line_number > len(lines) or line_number < 1:
        print(f"[!] Invalid line number: {line_number}")
        return False

    record = json.loads(lines[line_number - 1])
    # Corrupt chain hash by flipping characters
    orig = record["chain_hash"]
    record["chain_hash"] = "deadbeef" + orig[8:]
    lines[line_number - 1] = json.dumps(record) + "\n"

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"[+] ATTACK SUCCESSFUL: Log entry for line #{line_number} corrupted (hash forgery).")
    return True


def restore_clean() -> bool:
    """
    Restores the clean evidence snapshot.
    """
    logger = AuditLogger()
    restored = logger.restore_clean_snapshot()
    if restored:
        print("[+] SUCCESS: Pristine evidence snapshot restored. System is back in authentic state.")
    else:
        print("[!] No clean snapshot found. Please record a new session with 'python main.py'.")
    return restored


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tamper Attack Simulator for Video Integrity Testing")
    parser.add_argument("--attack", choices=["modify", "delete", "swap", "corrupt_log", "restore"],
                        required=True, help="Attack type to simulate")
    parser.add_argument("--frame", type=int, default=2, help="Target frame number (default: 2)")
    parser.add_argument("--frame-b", type=int, default=3, help="Second frame for swap attack (default: 3)")
    parser.add_argument("--type", choices=["watermark", "single_pixel", "blur", "mask_box", "mask_lens", "mask_spray"], default="watermark",
                        help="Modification style for 'modify' attack (includes digital masking & lens occlusion)")

    args = parser.parse_args()

    print("\n==================================================")
    print(" TAMPER ATTACK SIMULATOR")
    print("==================================================")

    if args.attack == "modify":
        modify_frame(args.frame, args.type)
    elif args.attack == "delete":
        delete_frame(args.frame)
    elif args.attack == "swap":
        swap_frames(args.frame, args.frame_b)
    elif args.attack == "corrupt_log":
        corrupt_log(args.frame)
    elif args.attack == "restore":
        restore_clean()

    print("==================================================")
    print("Run 'python verifier.py' now to observe verification detection.")
