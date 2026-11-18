"""
Audit Logger for Secure Frame and Hash-Chain Storage.
Handles lossless PNG frame saving, JSONL audit logging, and session snapshots.
"""

import os
import cv2
import json
import time
import shutil
import datetime
import numpy as np
from typing import Dict, Any, Optional
from .hash_chain import GENESIS_HASH, create_chain_hash, compute_session_signature


DEFAULT_BASE_DIR = "evidence"
DEFAULT_FRAME_DIR = os.path.join(DEFAULT_BASE_DIR, "frames")
DEFAULT_LOG_FILE = os.path.join(DEFAULT_BASE_DIR, "hash_log.jsonl")
DEFAULT_SNAPSHOT_DIR = os.path.join(DEFAULT_BASE_DIR, ".snapshot_clean")


class AuditLogger:
    """
    Manages lossless storage of video frames and append-only cryptographic audit logs.
    """

    def __init__(
        self,
        base_dir: str = DEFAULT_BASE_DIR,
        frame_dir: Optional[str] = None,
        log_file: Optional[str] = None,
        secret_key: bytes = b"CRYPTO_AUDIT_SECRET_2026"
    ):
        self.base_dir = base_dir
        self.frame_dir = frame_dir or os.path.join(base_dir, "frames")
        self.log_file = log_file or os.path.join(base_dir, "hash_log.jsonl")
        self.secret_key = secret_key

        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs(self.frame_dir, exist_ok=True)

        self.previous_hash = GENESIS_HASH
        self.frame_count = 0
        self._file_handle = None

    def open_session(self, reset: bool = True):
        """Prepares logger for a new recording session."""
        if reset:
            # Clean existing frames safely without removing the directory itself (avoids Windows lock)
            if os.path.exists(self.frame_dir):
                for fname in os.listdir(self.frame_dir):
                    fpath = os.path.join(self.frame_dir, fname)
                    try:
                        if os.path.isfile(fpath):
                            os.remove(fpath)
                    except Exception:
                        pass
            else:
                os.makedirs(self.frame_dir, exist_ok=True)

            if os.path.exists(self.log_file):
                try:
                    os.remove(self.log_file)
                except Exception:
                    pass

        self._file_handle = open(self.log_file, "a", encoding="utf-8")
        self.previous_hash = GENESIS_HASH
        self.frame_count = 0

    def log_frame(
        self,
        frame_index: int,
        frame_hash: str,
        chain_hash: str,
        frame: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Saves the frame losslessly and appends the cryptographic record.
        """
        filename = f"frame_{frame_index:06d}.png"
        filepath = os.path.join(self.frame_dir, filename)

        # Save frame losslessly (PNG) if provided
        if frame is not None:
            cv2.imwrite(filepath, frame, [cv2.IMWRITE_PNG_COMPRESSION, 3])

        record = {
            "frame_number": frame_index,
            "timestamp": time.time(),
            "iso_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "filename": filename,
            "frame_hash": frame_hash,
            "previous_hash": self.previous_hash,
            "chain_hash": chain_hash,
        }

        if self._file_handle is None or self._file_handle.closed:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        else:
            self._file_handle.write(json.dumps(record) + "\n")
            self._file_handle.flush()

        self.previous_hash = chain_hash
        self.frame_count = frame_index
        return record

    def close_session(self) -> Dict[str, Any]:
        """Closes session and writes cryptographic session manifest."""
        if self._file_handle and not self._file_handle.closed:
            self._file_handle.close()

        # Compute session root signature
        signature = compute_session_signature(
            self.previous_hash, self.frame_count, self.secret_key
        )

        manifest = {
            "closed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_frames": self.frame_count,
            "final_chain_hash": self.previous_hash,
            "genesis_hash": GENESIS_HASH,
            "session_signature": signature,
        }

        manifest_path = os.path.join(self.base_dir, "session_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Save snapshot for easy testing and restore
        self.save_clean_snapshot()

        return manifest

    def save_clean_snapshot(self):
        """Creates a pristine snapshot for the tamper attack simulator."""
        snapshot_dir = os.path.join(self.base_dir, ".snapshot_clean")
        os.makedirs(snapshot_dir, exist_ok=True)
        snapshot_frames = os.path.join(snapshot_dir, "frames")
        os.makedirs(snapshot_frames, exist_ok=True)

        # Copy frames
        if os.path.exists(self.frame_dir):
            for fname in os.listdir(self.frame_dir):
                src = os.path.join(self.frame_dir, fname)
                dst = os.path.join(snapshot_frames, fname)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

        # Copy log
        if os.path.exists(self.log_file):
            shutil.copy2(self.log_file, os.path.join(snapshot_dir, "hash_log.jsonl"))

        # Copy manifest if exists
        manifest_path = os.path.join(self.base_dir, "session_manifest.json")
        if os.path.exists(manifest_path):
            shutil.copy2(manifest_path, os.path.join(snapshot_dir, "session_manifest.json"))

    def restore_clean_snapshot(self) -> bool:
        """Restores the pristine snapshot after tampering simulation."""
        snapshot_dir = os.path.join(self.base_dir, ".snapshot_clean")
        if not os.path.exists(snapshot_dir):
            return False

        snapshot_frames = os.path.join(snapshot_dir, "frames")
        snapshot_log = os.path.join(snapshot_dir, "hash_log.jsonl")

        if os.path.exists(snapshot_frames):
            os.makedirs(self.frame_dir, exist_ok=True)
            # Remove any excess files
            clean_files = set(os.listdir(snapshot_frames))
            for cur_f in os.listdir(self.frame_dir):
                if cur_f not in clean_files:
                    try:
                        os.remove(os.path.join(self.frame_dir, cur_f))
                    except Exception:
                        pass
            # Copy snapshot frames over
            for fname in clean_files:
                src = os.path.join(snapshot_frames, fname)
                dst = os.path.join(self.frame_dir, fname)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

        if os.path.exists(snapshot_log):
            shutil.copy2(snapshot_log, self.log_file)

        manifest_snap = os.path.join(snapshot_dir, "session_manifest.json")
        if os.path.exists(manifest_snap):
            shutil.copy2(manifest_snap, os.path.join(self.base_dir, "session_manifest.json"))

        return True
