"""FastAPI bridge to the existing Live Video Tamper Detection forensic engine.

This API creates a trusted baseline when a video is first ingested, then allows
later uploads to be compared frame-by-frame against that baseline. A baseline
created after upload does NOT prove the video was authentic before ingestion.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

import cv2
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from core.audit_logger import AuditLogger
from core.hash_chain import compute_frame_hash
from core.verifier_engine import VideoVerifier

APP_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", str(APP_ROOT / "api" / "data" / "evidence"))).resolve()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
API_KEY = os.getenv("API_KEY", "")
HMAC_SECRET = os.getenv("FORENSIC_HMAC_SECRET", "")

app = FastAPI(
    title="Crypto Sentinel API",
    version="0.1.0",
    description="Video ingestion, SHA-256 frame chaining and forensic verification API.",
)


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not API_KEY:
        raise HTTPException(status_code=503, detail="API_KEY is not configured on the server.")
    if not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


def require_hmac_secret() -> bytes:
    if not HMAC_SECRET or len(HMAC_SECRET.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=503,
            detail="FORENSIC_HMAC_SECRET must be configured with at least 32 characters.",
        )
    return HMAC_SECRET.encode("utf-8")


def safe_job_dir(job_id: str) -> Path:
    if not job_id or any(ch not in "0123456789abcdef-" for ch in job_id.lower()):
        raise HTTPException(status_code=400, detail="Invalid job ID.")
    path = (EVIDENCE_ROOT / job_id).resolve()
    if EVIDENCE_ROOT not in path.parents:
        raise HTTPException(status_code=400, detail="Invalid evidence path.")
    if not path.is_dir():
        raise HTTPException(status_code=404, detail="Evidence job not found.")
    return path


async def save_upload(upload: UploadFile) -> tuple[Path, str, int]:
    suffix = Path(upload.filename or "video.mp4").suffix.lower()
    if suffix not in {".mp4", ".mov", ".avi", ".mkv", ".mpg", ".mpeg"}:
        raise HTTPException(status_code=415, detail="Supported formats: MP4, MOV, AVI, MKV, MPG, MPEG.")

    temp_dir = Path(tempfile.mkdtemp(prefix="crypto-sentinel-"))
    target = temp_dir / ("source" + suffix)
    size = 0
    digest = hashlib.sha256()
    try:
        with target.open("wb") as output:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"Video exceeds {MAX_UPLOAD_MB} MB limit.")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    finally:
        await upload.close()

    if size == 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    return target, digest.hexdigest(), size


def load_records(job_dir: Path) -> list[dict[str, Any]]:
    log_path = job_dir / "hash_log.jsonl"
    if not log_path.exists():
        raise HTTPException(status_code=404, detail="Hash-chain log is missing.")
    records: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as source:
        for line in source:
            if line.strip():
                records.append(json.loads(line))
    return records


def compare_video_to_baseline(video_path: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise HTTPException(status_code=422, detail="Could not decode this video. Try an H.264 MP4.")
    checked = 0
    mismatches: list[dict[str, Any]] = []
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            checked += 1
            if checked > len(records):
                mismatches.append({"frame": checked, "status": "UNEXPECTED_EXTRA_FRAME"})
                continue
            actual_hash = compute_frame_hash(frame)
            expected_hash = records[checked - 1].get("frame_hash", "")
            if not hmac.compare_digest(actual_hash, expected_hash):
                mismatches.append({"frame": checked, "status": "HASH_MISMATCH"})
    finally:
        cap.release()

    if checked < len(records):
        for index in range(checked + 1, len(records) + 1):
            mismatches.append({"frame": index, "status": "MISSING_FRAME"})

    total = max(len(records), checked)
    mismatch_count = len(mismatches)
    return {
        "is_match": mismatch_count == 0 and checked == len(records),
        "frames_checked": checked,
        "baseline_frames": len(records),
        "mismatch_count": mismatch_count,
        "integrity_percent": round(((total - mismatch_count) / total) * 100, 2) if total else 0.0,
        "mismatches": mismatches[:500],
        "note": "Comparison is against the baseline recorded at ingestion. It does not establish authenticity before that baseline was created.",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "crypto-sentinel-api", "version": "0.1.0"}


@app.post("/api/v1/videos/analyze", dependencies=[Depends(require_api_key)])
async def analyze_video(video: UploadFile = File(...)) -> JSONResponse:
    secret = require_hmac_secret()
    temp_path, file_sha256, file_size = await save_upload(video)
    job_id = str(uuid.uuid4())
    job_dir = EVIDENCE_ROOT / job_id
    job_dir.mkdir(parents=True, exist_ok=False)

    cap = cv2.VideoCapture(str(temp_path))
    if not cap.isOpened():
        shutil.rmtree(temp_path.parent, ignore_errors=True)
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=422, detail="Could not decode video. Try H.264 encoded MP4.")

    fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
    declared_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    logger = AuditLogger(base_dir=str(job_dir), secret_key=secret)
    logger.open_session(reset=True)
    processed = 0
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            processed += 1
            frame_hash = compute_frame_hash(frame)
            from core.hash_chain import create_chain_hash
            chain_hash = create_chain_hash(logger.previous_hash, processed, frame_hash)
            logger.log_frame(processed, frame_hash, chain_hash, frame=frame)
        manifest = logger.close_session()
    except Exception:
        try:
            logger.close_session()
        except Exception:
            pass
        shutil.rmtree(job_dir, ignore_errors=True)
        raise
    finally:
        cap.release()
        shutil.rmtree(temp_path.parent, ignore_errors=True)

    if processed == 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=422, detail="No video frames could be decoded.")

    metadata = {
        "job_id": job_id,
        "original_filename": video.filename,
        "file_size_bytes": file_size,
        "source_file_sha256": file_sha256,
        "fps": fps,
        "declared_frame_count": declared_frames,
        "processed_frame_count": processed,
        "baseline_created": True,
        "created_at_utc": manifest.get("closed_at"),
        "final_chain_hash": manifest.get("final_chain_hash"),
    }
    (job_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return JSONResponse({
        "job_id": job_id,
        "status": "BASELINE_CREATED",
        "metadata": metadata,
        "message": "A trusted frame-hash baseline and signed chain were created for subsequent comparisons.",
    })


@app.post("/api/v1/jobs/{job_id}/verify", dependencies=[Depends(require_api_key)])
async def verify_video(job_id: str, video: UploadFile = File(...)) -> dict[str, Any]:
    secret = require_hmac_secret()
    job_dir = safe_job_dir(job_id)
    temp_path, uploaded_sha256, _ = await save_upload(video)
    try:
        records = load_records(job_dir)
        comparison = compare_video_to_baseline(temp_path, records)
        verifier = VideoVerifier(base_dir=str(job_dir), secret_key=secret)
        chain_result = verifier.verify()
        return {
            "job_id": job_id,
            "uploaded_file_sha256": uploaded_sha256,
            "comparison": comparison,
            "baseline_chain": chain_result.to_dict(),
        }
    finally:
        shutil.rmtree(temp_path.parent, ignore_errors=True)


@app.get("/api/v1/jobs/{job_id}", dependencies=[Depends(require_api_key)])
def get_job(job_id: str) -> dict[str, Any]:
    job_dir = safe_job_dir(job_id)
    metadata_path = job_dir / "metadata.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=404, detail="Job metadata not found.")
    return json.loads(metadata_path.read_text(encoding="utf-8"))


@app.get("/api/v1/jobs/{job_id}/report", dependencies=[Depends(require_api_key)])
def get_report(job_id: str) -> dict[str, Any]:
    job_dir = safe_job_dir(job_id)
    metadata = json.loads((job_dir / "metadata.json").read_text(encoding="utf-8"))
    result = VideoVerifier(base_dir=str(job_dir), secret_key=require_hmac_secret()).verify()
    return {"metadata": metadata, "verification": result.to_dict()}
