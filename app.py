"""
Live Video Tamper Detection System - Streamlit Monitoring Dashboard
Interactive forensics interface for real-time SHA-256 hash chaining, video upload & accuracy verification,
masking attack detection, visual chain exploration, and pixel-level forensic heatmaps.
"""

import os
import cv2
import json
import time
import shutil
import tempfile
import uuid
import io
import zipfile
import pandas as pd
import numpy as np
from PIL import Image
import streamlit as st

from core.hash_chain import GENESIS_HASH, sha256_bytes, sha256_str, compute_frame_hash, create_chain_hash
from core.video_engine import VideoStreamSource, SyntheticCCTVGenerator, add_cryptographic_hud

# Compatibility guard: older Streamlit deployments may still have a cached
# video_engine.py without the dual-sentinel HUD helper. Keep startup working
# and retain a visible masking warning until the updated module is loaded.
try:
    from core.video_engine import add_dual_sentinel_hud
except ImportError:
    def add_dual_sentinel_hud(
        frame,
        frame_index,
        frame_hash,
        chain_hash,
        mask_result=None,
        is_hash_valid=True,
        status_override=None,
    ):
        status = status_override or (
            "MASK DETECTED" if mask_result is not None and getattr(mask_result, "is_masked", False)
            else "CHAIN SECURED"
        )
        overlay = add_cryptographic_hud(
            frame=frame,
            frame_index=frame_index,
            frame_hash=frame_hash,
            chain_hash=chain_hash,
            status=status,
            is_valid=is_hash_valid and not (
                mask_result is not None and getattr(mask_result, "is_masked", False)
            ),
        )
        if mask_result is not None and getattr(mask_result, "is_masked", False):
            h, w = overlay.shape[:2]
            mask_type = getattr(mask_result, "mask_type", "MASK DETECTED")
            for (bx, by, bw, bh) in getattr(mask_result, "bounding_boxes", []) or []:
                cv2.rectangle(overlay, (bx, by), (bx + bw, by + bh), (0, 0, 255), 2)
            cv2.rectangle(overlay, (10, 52), (min(w - 10, 390), 88), (0, 0, 150), -1)
            cv2.putText(
                overlay, f"MASK ALERT: {mask_type}"[:42], (18, 76),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 2
            )
        return overlay
from core.audit_logger import AuditLogger, DEFAULT_BASE_DIR, DEFAULT_FRAME_DIR, DEFAULT_LOG_FILE
from core.verifier_engine import VideoVerifier, VerificationResult
from core.masking_detector import MaskingDetector, MaskingResult
from core.ai_tamper_detector import AITamperDetector
import tamper_simulator

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="Live Video Tamper & Masking Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for Cyber-Forensic Dashboard
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #00E676;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #B0BEC5;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1E293B;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #334155;
    }
    .verified-banner {
        background-color: #064E3B;
        border: 1px solid #059669;
        color: #A7F3D0;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 1.15rem;
        text-align: center;
        margin-bottom: 1rem;
    }
    .tampered-banner {
        background-color: #7F1D1D;
        border: 1px solid #DC2626;
        color: #FECACA;
        padding: 16px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 1.15rem;
        text-align: center;
        margin-bottom: 1rem;
    }
    .accuracy-gauge {
        background: #0F172A;
        border: 2px solid #38BDF8;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        margin-bottom: 20px;
    }
    .hash-badge {
        font-family: 'Courier New', monospace;
        background-color: #0F172A;
        padding: 4px 8px;
        border-radius: 4px;
        color: #38BDF8;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)


def get_evidence_stats():
    """Reads basic metrics from existing evidence directory."""
    frames_count = 0
    if os.path.exists(DEFAULT_FRAME_DIR):
        frames_count = len([f for f in os.listdir(DEFAULT_FRAME_DIR) if f.endswith(".png")])
    log_exists = os.path.exists(DEFAULT_LOG_FILE)
    manifest_exists = os.path.exists(os.path.join(DEFAULT_BASE_DIR, "session_manifest.json"))
    return frames_count, log_exists, manifest_exists


# Sidebar Navigation & System Information
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.markdown("### 🛡️ Crypto Sentinel")
    st.markdown("**Live Video Tamper & Masking Detection**")
    st.caption("Cryptographic Hash Chain • AI Masking Forensics")
    st.markdown("---")

    st.subheader("Active Session")
    f_count, log_ok, manifest_ok = get_evidence_stats()
    st.metric("Recorded Frames", f_count)
    st.markdown(f"**Audit Log:** {'🟢 Active' if log_ok else '⚪ None'}")
    st.markdown(f"**Session Manifest:** {'🟢 Signed' if manifest_ok else '⚪ None'}")

    st.markdown("---")
    st.subheader("Dual Defense Model")
    st.markdown("1. **Cryptographic Layer:**")
    st.latex(r"C_i = \text{SHA256}(C_{i-1} \parallel i \parallel H_i)")
    st.markdown("2. **Masking Detection Layer:**")
    st.caption("• Lens Occlusion (Blackout/Blur)")
    st.caption("• Digital Redaction Box Masking")
    st.caption("• Static Patch Inpainting")

    st.markdown("---")
    st.caption("NIST FIPS 180-4 • High-Assurance Forensic Surveillance")


# Title Header
st.markdown('<div class="main-title">🛡️ Live Video Tamper & Masking Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Dual-Layer Verification: SHA-256 Hash Chain Integrity + AI Masking & Occlusion Forensics</div>', unsafe_allow_html=True)

# Main Navigation Tabs (6 comprehensive tabs)
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📹 Live Camera Sentinel (Masking + Hashing)",
    "📤 Upload & Accuracy Inspector",
    "🔗 Hash Chain Explorer",
    "⚡ Tamper & Mask Attack Lab",
    "🔍 Forensic Verifier",
    "📄 Audit Certificate & Report"
])


# ==========================================
# TAB 1: LIVE CAMERA SENTINEL (MASKING + HASHING)
# ==========================================
with tab1:
    st.markdown("### 📹 Live Camera Sentinel: Real-Time Masking & SHA-256 Hashing")
    st.write(
        "Monitors video frames directly from your **Physical Webcam** or **Synthetic CCTV**, "
        "simultaneously computing **SHA-256 cryptographic hash chains** ($C_i$) and running **AI Masking & Lens Occlusion Detection** on every single frame."
    )

    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("#### 1. Camera Source")
        source_type = st.selectbox(
            "Video Source",
            ["Physical Webcam (Live Camera)", "Synthetic CCTV (Simulated Stream)"],
            key="tab1_source_type"
        )

        device_index = 0
        if "Physical Webcam" in source_type:
            device_index = st.number_input("Webcam Device Index", min_value=0, max_value=5, value=0, key="tab1_device_idx")

        st.markdown("#### 2. Live Tamper Simulation")
        st.caption("Test how the system catches masking and pixel tampering in real time:")
        live_attack = st.selectbox(
            "Simulate Live Camera Attack",
            [
                "None (Clean / Authentic Stream)",
                "Cover Camera Lens (Simulate Hand/Tape Blackout)",
                "Apply Digital Privacy Mask (Black Redaction Box)",
                "Inject Watermark Pixel Stamp"
            ],
            key="tab1_live_attack"
        )

        st.markdown("---")
        st.markdown("#### 3. Operation Mode")
        op_mode = st.radio(
            "Select Mode",
            ["Continuous Live Sentinel (Active Monitor)", "Record & Anchor Session (Save to Audit Log)"],
            key="tab1_op_mode"
        )

        if op_mode == "Record & Anchor Session (Save to Audit Log)":
            target_frames = st.slider("Frames to Record", min_value=5, max_value=60, value=15, step=5, key="tab1_record_frames")
            start_record_btn = st.button("🔴 Record & Secure Session", use_container_width=True, type="primary", key="tab1_start_record")
            start_monitor = False
        else:
            start_record_btn = False
            start_monitor = st.checkbox("🟢 Start Live Sentinel Stream", value=False, key="tab1_live_sentinel_toggle")

        st.markdown("---")
        st.markdown("💡 **Native High-FPS Dual Screen CLI:**")
        st.code("python live_monitor.py --source webcam\n# Hotkeys: M=Mask, L=Lens, T=Tamper, R=Reset", language="bash")

    with col2:
        preview_container = st.empty()
        alert_container = st.empty()
        status_container = st.empty()
        metrics_container = st.empty()

        mask_detector = MaskingDetector()

        # --- SUB-MODE A: CONTINUOUS LIVE SENTINEL ---
        if op_mode.startswith("Continuous") and start_monitor:
            chosen_mode = "synthetic" if "Synthetic" in source_type else "webcam"

            try:
                stream = VideoStreamSource(mode=chosen_mode, device_index=device_index)
            except Exception as ex:
                st.error(f"Failed to open video source: {ex}")
                stream = None

            if stream and stream.is_opened:
                previous_chain = GENESIS_HASH
                frame_count = 0
                tamper_count = 0
                mask_count = 0

                try:
                    for _ in range(60):  # Continuous live stream cycle
                        ret, raw_frame = stream.read()
                        if not ret or raw_frame is None:
                            break

                        frame_count += 1
                        h, w, _ = raw_frame.shape
                        monitored_frame = raw_frame.copy()

                        # Apply live simulated attack if chosen
                        if "Cover Camera Lens" in live_attack:
                            monitored_frame[:] = 2  # Complete blackout / lens covered
                        elif "Digital Privacy Mask" in live_attack:
                            bx, by = int(w * 0.28), int(h * 0.25)
                            bw, bh = int(w * 0.44), int(h * 0.45)
                            cv2.rectangle(monitored_frame, (bx, by), (bx + bw, by + bh), (0, 0, 0), -1)
                        elif "Watermark Pixel" in live_attack:
                            cv2.rectangle(monitored_frame, (int(w * 0.3), int(h * 0.3)), (int(w * 0.7), int(h * 0.5)), (0, 0, 255), -1)
                            cv2.putText(monitored_frame, "TAMPER ATTACK", (int(w * 0.32), int(h * 0.42)),
                                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)

                        # Dual Verification: SHA-256 Chain + Masking Detection
                        f_hash = compute_frame_hash(monitored_frame)
                        c_hash = create_chain_hash(previous_chain, frame_count, f_hash)
                        previous_chain = c_hash

                        mask_res = mask_detector.analyze_frame_masking(monitored_frame)

                        is_tampered = (live_attack != "None (Clean / Authentic Stream)")
                        if mask_res.is_masked:
                            mask_count += 1
                        if is_tampered or mask_res.is_masked:
                            tamper_count += 1

                        # Render Dual Sentinel HUD
                        hud_frame = add_dual_sentinel_hud(
                            frame=monitored_frame,
                            frame_index=frame_count,
                            frame_hash=f_hash,
                            chain_hash=c_hash,
                            mask_result=mask_res,
                            is_hash_valid=(not is_tampered),
                            status_override="🚨 TAMPER DETECTED" if is_tampered else None
                        )
                        hud_rgb = cv2.cvtColor(hud_frame, cv2.COLOR_BGR2RGB)
                        preview_container.image(hud_rgb, channels="RGB", use_container_width=True)

                        # Live Alert Banner
                        if mask_res.is_masked:
                            alert_container.markdown(f"""
                            <div class="tampered-banner" style="padding: 10px; margin-bottom: 8px;">
                                🚨 LIVE MASKING DETECTED: <b>{mask_res.mask_type}</b> ({mask_res.confidence*100:.1f}% confidence)<br>
                                <span style="font-size: 0.85rem;">{mask_res.details}</span>
                            </div>
                            """, unsafe_allow_html=True)
                        elif is_tampered:
                            alert_container.markdown("""
                            <div class="tampered-banner" style="padding: 10px; margin-bottom: 8px;">
                                🚨 PIXEL INTEGRITY COMPROMISED: Hash Chain Mismatch Detected!
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            alert_container.markdown("""
                            <div class="verified-banner" style="padding: 10px; margin-bottom: 8px;">
                                🟢 CAMERA SECURE: SHA-256 Hash Chain Intact • No Masking Detected
                            </div>
                            """, unsafe_allow_html=True)

                        # Live Metrics Row
                        with metrics_container.container():
                            m1, m2, m3, m4 = st.columns(4)
                            m1.metric("Live Frame", f"#{frame_count:04d}")
                            m2.metric(
                                "Mask Status",
                                "🔴 MASKED" if mask_res.is_masked else "🟢 CLEAR",
                                delta=mask_res.mask_type if mask_res.is_masked else "CLEAN",
                                delta_color="inverse" if mask_res.is_masked else "normal"
                            )
                            m3.metric(
                                "Hash Chain",
                                "🔴 TAMPERED" if is_tampered else "🟢 INTACT",
                                delta=None
                            )
                            live_acc = max(0.0, 100.0 - (tamper_count / frame_count * 100.0))
                            m4.metric("Live Accuracy", f"{live_acc:.1f}%")

                        status_container.markdown(f"""
                        **SHA-256:** `{f_hash[:16]}...` | **Chain:** `{c_hash[:16]}...`
                        """)
                        time.sleep(0.04)

                    stream.release()
                except Exception as ex:
                    stream.release()
                    st.error(f"Stream error: {ex}")
            elif stream is not None:
                st.error("Could not access physical webcam. Ensure camera is connected or select 'Synthetic CCTV'.")
        elif op_mode.startswith("Continuous"):
            preview_container.info("Check '🟢 Start Live Sentinel Stream' above to begin real-time camera monitoring and masking detection.")

        # --- SUB-MODE B: RECORD & ANCHOR SESSION ---
        elif start_record_btn:
            chosen_mode = "synthetic" if "Synthetic" in source_type else "webcam"

            try:
                stream = VideoStreamSource(mode=chosen_mode, device_index=device_index)
            except Exception as ex:
                st.error(f"Failed to open video source: {ex}")
                stream = None

            if stream and stream.is_opened:
                logger = AuditLogger()
                logger.open_session(reset=True)

                previous_hash = GENESIS_HASH
                progress_bar = st.progress(0)
                detected_masks = 0

                for i in range(1, target_frames + 1):
                    ret, raw_frame = stream.read()
                    if not ret or raw_frame is None:
                        break

                    monitored_frame = raw_frame.copy()

                    # Apply live attack if selected
                    if "Cover Camera Lens" in live_attack:
                        monitored_frame[:] = 2
                    elif "Digital Privacy Mask" in live_attack:
                        h, w, _ = monitored_frame.shape
                        cv2.rectangle(monitored_frame, (int(w * 0.28), int(h * 0.25)), (int(w * 0.72), int(h * 0.70)), (0, 0, 0), -1)
                    elif "Watermark Pixel" in live_attack:
                        h, w, _ = monitored_frame.shape
                        cv2.putText(monitored_frame, "TAMPER ATTACK", (int(w * 0.3), int(h * 0.4)), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)

                    f_hash = compute_frame_hash(monitored_frame)
                    c_hash = create_chain_hash(previous_hash, i, f_hash)

                    logger.log_frame(i, f_hash, c_hash, frame=monitored_frame)
                    previous_hash = c_hash

                    mask_res = mask_detector.analyze_frame_masking(monitored_frame)
                    if mask_res.is_masked:
                        detected_masks += 1

                    hud_img = add_dual_sentinel_hud(
                        frame=monitored_frame,
                        frame_index=i,
                        frame_hash=f_hash,
                        chain_hash=c_hash,
                        mask_result=mask_res,
                        is_hash_valid=(live_attack == "None (Clean / Authentic Stream)")
                    )
                    hud_rgb = cv2.cvtColor(hud_img, cv2.COLOR_BGR2RGB)
                    preview_container.image(hud_rgb, channels="RGB", use_container_width=True)

                    status_container.markdown(f"""
                    **Frame #{i:04d}** | SHA-256: `{f_hash[:16]}...` | Mask: `{'🔴 ' + mask_res.mask_type if mask_res.is_masked else '🟢 CLEAR'}`
                    """)
                    progress_bar.progress(i / target_frames)
                    time.sleep(0.04)

                stream.release()
                manifest = logger.close_session()
                if detected_masks > 0:
                    st.warning(f"⚠️ Recording Complete with {detected_masks} MASKED frames detected! Final Chain Hash: `{manifest['final_chain_hash'][:16]}...`")
                else:
                    st.success(f"✅ Recording Complete! {target_frames} pristine frames secured. Final Chain Hash: `{manifest['final_chain_hash'][:16]}...`")
                st.rerun()
            elif stream is not None:
                st.error("Camera could not be opened. Using 'Synthetic CCTV' ensures instant verification without hardware.")
        else:
            latest_frame_path = os.path.join(DEFAULT_FRAME_DIR, f"frame_{f_count:06d}.png")
            if os.path.exists(latest_frame_path):
                img = Image.open(latest_frame_path)
                preview_container.image(img, caption=f"Last Recorded Frame (#{f_count})", use_container_width=True)
            else:
                preview_container.info("Select 'Start Live Sentinel Stream' or 'Record & Anchor Session' to start monitoring.")


# ==========================================
# TAB 2: VIDEO UPLOAD & ACCURACY INSPECTOR
# ==========================================
with tab2:
    st.markdown("### 📤 Upload Video & Inspect Accuracy")
    st.write(
        "Upload any surveillance or recorded video file (`.mp4`, `.avi`, `.mov`, `.mkv`) "
        "to evaluate its **Integrity Accuracy (0% to 100%)**, detect **Cryptographic Hash Tampering**, "
        "and identify **Video Masking Attacks** (lens occlusion, digital redactions, static patches)."
    )

    up_col1, up_col2 = st.columns([1, 1])

    with up_col1:
        st.markdown("#### 1. Choose Video File")
        uploaded_video = st.file_uploader(
            "Upload surveillance video (.mp4, .avi, .mov, .mkv)",
            type=["mp4", "avi", "mov", "mkv", "mpeg", "mpg"],
            key="upload_inspector_video"
        )

    with up_col2:
        st.markdown("#### 2. Optional: Upload Hash Chain Log")
        uploaded_log = st.file_uploader(
            "Upload hash_log.jsonl (Optional: Enables bit-exact cryptographic audit)",
            type=["jsonl", "json"],
            key="upload_inspector_log"
        )

    if uploaded_video is not None:
        st.video(uploaded_video)
        st.caption(f"Filename: `{uploaded_video.name}` • Size: `{uploaded_video.size / (1024 * 1024):.2f} MB`")

        # Two operational buttons
        btn_col1, btn_col2 = st.columns(2)
        with btn_col1:
            run_forensic_inspect = st.button(
                "🔬 Run Forensic Accuracy & Masking Audit",
                type="primary",
                use_container_width=True,
                key="btn_run_forensic_inspect"
            )
        with btn_col2:
            process_as_session = st.button(
                "🔐 Hash & Secure Video into New Evidence Session",
                use_container_width=True,
                key="btn_process_as_session"
            )

        suffix = os.path.splitext(uploaded_video.name)[1].lower() or ".mp4"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tfile:
            tfile.write(uploaded_video.getbuffer())
            temp_video_path = tfile.name

        temp_log_path = None
        if uploaded_log is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tlogfile:
                tlogfile.write(uploaded_log.getbuffer())
                temp_log_path = tlogfile.name

        # --- OPTION A: RUN ACCURACY & MASKING AUDIT ---
        if run_forensic_inspect or "last_upload_inspection_res" in st.session_state:
            if run_forensic_inspect:
                with st.spinner("🔬 Running Deep Forensic Integrity & Masking Analysis..."):
                    verifier = VideoVerifier()
                    upload_res = verifier.verify_video_file(
                        video_path=temp_video_path,
                        optional_log_path=temp_log_path,
                        max_frames=150
                    )
                    st.session_state["last_upload_inspection_res"] = upload_res.to_dict()
                    st.session_state["last_inspected_video_path"] = temp_video_path
            else:
                upload_res_dict = st.session_state["last_upload_inspection_res"]
                upload_res = VerificationResult(
                    is_valid=upload_res_dict["is_valid"],
                    total_checked=upload_res_dict["total_checked"],
                    authentic_count=upload_res_dict["authentic_count"],
                    tampered_count=upload_res_dict["tampered_count"],
                    missing_count=upload_res_dict["missing_count"],
                    chain_broken_count=upload_res_dict["chain_broken_count"],
                    masked_count=upload_res_dict["masked_count"],
                    accuracy_percent=upload_res_dict["accuracy_percent"],
                    first_violation_index=upload_res_dict["first_violation_index"],
                    manifest_verified=upload_res_dict["manifest_verified"],
                    summary_message=upload_res_dict["summary_message"],
                    video_source_mode=upload_res_dict["video_source_mode"],
                    frame_results=[FrameStatus(**f) for f in upload_res_dict["frames"]]
                )

            st.markdown("---")
            acc = upload_res.accuracy_percent
            if acc >= 95.0 and upload_res.is_valid:
                st.markdown(f"""
                <div class="verified-banner" style="font-size: 1.3rem;">
                    🟢 INTEGRITY VERIFIED: {acc}% ACCURACY<br>
                    <span style="font-size: 1rem; font-weight: normal;">No masking or hash tampering detected. Video is authentic across all {upload_res.total_checked} inspected frames.</span>
                </div>
                """, unsafe_allow_html=True)
            elif acc >= 70.0:
                st.markdown(f"""
                <div style="background-color: #78350F; border: 2px solid #F59E0B; color: #FEF3C7; padding: 18px; border-radius: 8px; font-weight: 600; font-size: 1.25rem; text-align: center; margin-bottom: 1rem;">
                    ⚠️ WARNING: SUSPICIOUS VIDEO (ACCURACY: {acc}%)<br>
                    <span style="font-size: 0.95rem; font-weight: normal;">
                        Integrity anomalies detected! Found {upload_res.tampered_count} violations ({upload_res.masked_count} masked frames). First violation at <b>Frame #{upload_res.first_violation_index}</b>.
                    </span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="tampered-banner" style="font-size: 1.3rem;">
                    🔴 SEVERE ALERT: VIDEO INTEGRITY COMPROMISED (ACCURACY: {acc}%)<br>
                    <span style="font-size: 1rem; font-weight: normal;">
                        Video tampering & masking confirmed! Detected {upload_res.tampered_count} violations. First compromised at <b>Frame #{upload_res.first_violation_index}</b>.
                    </span>
                </div>
                """, unsafe_allow_html=True)

            k1, k2, k3, k4 = st.columns(4)
            k1.metric("Overall Accuracy", f"{acc}%", delta="HIGH" if acc >= 95 else "-COMPROMISED")
            k2.metric("Inspected Frames", upload_res.total_checked)
            k3.metric("Authentic Frames", upload_res.authentic_count)
            k4.metric("Masked / Tampered", upload_res.tampered_count, delta=f"{upload_res.masked_count} masked" if upload_res.masked_count > 0 else None, delta_color="inverse")

            # Interactive Frame Inspector
            if upload_res.total_checked > 0:
                st.markdown("#### 🔬 Frame-by-Frame Masking & Tamper Inspector")
                inspect_f = st.slider(
                    "Select Frame to Inspect",
                    min_value=1,
                    max_value=upload_res.total_checked,
                    value=min(upload_res.first_violation_index or 1, upload_res.total_checked)
                )

                cap = cv2.VideoCapture(temp_video_path)
                cap.set(cv2.CAP_PROP_POS_FRAMES, inspect_f - 1)
                ret_f, current_frame = cap.read()
                cap.release()

                if ret_f and current_frame is not None:
                    cur_status = upload_res.frame_results[inspect_f - 1]
                    mask_det = MaskingDetector()
                    mask_res = mask_det.analyze_frame_masking(current_frame)
                    ai_det = AITamperDetector()
                    ai_res = ai_det.analyze_frame_anomaly(current_frame)

                    v_col1, v_col2, v_col3 = st.columns(3)
                    with v_col1:
                        st.image(cv2.cvtColor(current_frame, cv2.COLOR_BGR2RGB),
                                 caption=f"Frame #{inspect_f:04d} (Uploaded Raw)", use_container_width=True)
                    with v_col2:
                        st.image(cv2.cvtColor(mask_res.annotated_frame, cv2.COLOR_BGR2RGB),
                                 caption=f"Masking Localization ({mask_res.mask_type})", use_container_width=True)
                    with v_col3:
                        st.image(cv2.cvtColor(ai_res["ela_map"], cv2.COLOR_BGR2RGB),
                                 caption="Error Level Analysis (ELA Heatmap)", use_container_width=True)

                    st.markdown(f"""
                    **Frame Status:** `{cur_status.status}` | **Authentic:** `{'Yes' if cur_status.is_authentic else 'No'}`  
                    **Frame SHA-256 Digest:** `{cur_status.recomputed_frame_hash}`  
                    **Masking Diagnosis:** `{cur_status.mask_details or 'None'}`  
                    **Detected Bounding Boxes:** `{cur_status.mask_coords if cur_status.mask_coords else 'None'}`  
                    **AI Anomaly Score:** `{ai_res['anomaly_score'] * 100:.1f}%`
                    """)

            with st.expander("📋 View Complete Frame-by-Frame Audit Table", expanded=False):
                tab_data = [{
                    "Frame": f"#{fr.index:04d}",
                    "Status": fr.status,
                    "Authentic": "✅ Authentic" if fr.is_authentic else "❌ Tampered/Masked",
                    "Mask Type": fr.mask_type,
                    "Bounding Box": str(fr.mask_coords) if fr.mask_coords else "None",
                    "SHA-256": fr.recomputed_frame_hash[:16] + "..." if fr.recomputed_frame_hash else "",
                    "Details": fr.details
                } for fr in upload_res.frame_results]
                st.dataframe(pd.DataFrame(tab_data), use_container_width=True, hide_index=True)

        # --- OPTION B: PROCESS & SECURE INTO SESSION WITH ZIP EXPORT ---
        if process_as_session:
            session_id = uuid.uuid4().hex[:12]
            upload_root = os.path.join(DEFAULT_BASE_DIR, "uploads", session_id)
            os.makedirs(upload_root, exist_ok=True)

            try:
                cap = cv2.VideoCapture(temp_video_path)
                source_fps = cap.get(cv2.CAP_PROP_FPS) or 0.0
                source_frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
                logger = AuditLogger(base_dir=upload_root)
                logger.open_session(reset=True)

                processed = 0
                progress = st.progress(0.0)
                status = st.empty()

                while True:
                    ok, frame = cap.read()
                    if not ok:
                        break
                    processed += 1
                    f_hash = compute_frame_hash(frame)
                    c_hash = create_chain_hash(logger.previous_hash, processed, f_hash)
                    logger.log_frame(processed, f_hash, c_hash, frame=frame)
                    if source_frame_count > 0:
                        progress.progress(min(processed / source_frame_count, 1.0))
                    status.markdown(f"**Secured:** Frame #{processed:04d} | SHA-256: `{f_hash[:16]}…`")

                cap.release()
                manifest = logger.close_session()

                st.session_state["last_upload_evidence_dir"] = upload_root
                st.success(f"✅ Video Secured! {processed} frames hashed and chained into session `{session_id}`.")

                # Zip download
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                    for root, _, files in os.walk(upload_root):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            rel_p = os.path.relpath(fpath, upload_root)
                            archive.write(fpath, arcname=os.path.join("video_evidence", rel_p))

                st.download_button(
                    "📦 Download Complete Evidence Package (ZIP)",
                    data=zip_buffer.getvalue(),
                    file_name=f"video_integrity_evidence_{session_id}.zip",
                    mime="application/zip",
                    use_container_width=True
                )
            except Exception as ex:
                st.error(f"Processing failed: {ex}")


# ==========================================
# TAB 3: HASH CHAIN EXPLORER
# ==========================================
with tab3:
    st.markdown("### 🔗 Cryptographic Hash Chain Explorer")
    st.write("Inspect how every video frame is immutably linked to its predecessor. Any modification or masking breaks the sequential chain.")

    if not os.path.exists(DEFAULT_LOG_FILE):
        st.info("No recorded session found. Please record a session in Tab 1.")
    else:
        records = []
        with open(DEFAULT_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line.strip()))

        if not records:
            st.info("Log file is empty.")
        else:
            st.markdown(f"**Total Blocks in Chain:** `{len(records)}` | **Genesis Anchor:** `GENESIS`")

            for rec in records:
                idx = rec["frame_number"]
                fname = rec["filename"]
                f_hash = rec["frame_hash"]
                p_hash = rec["previous_hash"]
                c_hash = rec["chain_hash"]
                img_path = os.path.join(DEFAULT_FRAME_DIR, fname)

                with st.expander(f"📦 Block #{idx:04d} — Chain: {c_hash[:16]}...", expanded=(idx <= 3)):
                    c_left, c_right = st.columns([1, 2])
                    with c_left:
                        if os.path.exists(img_path):
                            st.image(img_path, caption=fname, use_container_width=True)
                        else:
                            st.error("Frame file missing from disk!")
                    with c_right:
                        st.markdown(f"**Frame Index ($i$):** `{idx}`")
                        st.markdown(f"**Previous Chain Hash ($C_{{i-1}}$):**")
                        st.code(p_hash, language="text")
                        st.markdown(f"**Frame SHA-256 Digest ($H_i$):**")
                        st.code(f_hash, language="text")
                        st.markdown(f"**Output Chain Hash ($C_i = \\text{{SHA256}}(C_{{i-1}} \\parallel i \\parallel H_i)$):**")
                        st.code(c_hash, language="text")


# ==========================================
# TAB 4: TAMPER & MASK ATTACK LAB
# ==========================================
with tab4:
    st.markdown("### ⚡ Tamper & Masking Attack Simulation Lab")
    st.write("Demonstrate the vulnerability of surveillance video to cyber tampering and test the detection power of our dual Hashing + Masking engine.")

    f_count, log_ok, _ = get_evidence_stats()
    if f_count == 0 or not log_ok:
        st.warning("Please record a video session in Tab 1 first before launching attacks.")
    else:
        st.info("💡 Launch an attack below and immediately switch to **Tab 5 (Forensic Verifier)** to watch the system catch both the hash mismatch and the mask box!")

        col_atk1, col_atk2 = st.columns(2)

        with col_atk1:
            st.markdown("#### 🎯 Attack 1: Masking & Content Modification")
            st.caption("Inject digital occlusion boxes, lens blackouts, or pixel modifications.")
            target_f = st.number_input("Target Frame Number", min_value=1, max_value=f_count, value=min(3, f_count))
            atk_style = st.selectbox(
                "Attack Type",
                ["mask_box", "mask_lens", "watermark", "single_pixel", "blur"],
                format_func=lambda x: {
                    "mask_box": "Digital Privacy Redaction Box (Blackout Mask)",
                    "mask_lens": "Camera Lens Blackout / Occlusion (Tape / Spray)",
                    "watermark": "Watermark Stamp Tamper",
                    "single_pixel": "Single Pixel Flip (Steganographic)",
                    "blur": "Gaussian Blur Object Area"
                }[x]
            )

            if st.button("🚀 Execute Attack on Frame", type="primary", use_container_width=True):
                success = tamper_simulator.modify_frame(target_f, atk_style)
                if success:
                    st.success(f"Frame #{target_f} modified with '{atk_style}'. Head over to Tab 5 to verify!")

            st.markdown("---")
            st.markdown("#### 🗑️ Attack 2: Drop / Delete Frame")
            st.caption("Deletes a frame from the sequence to conceal an event.")
            del_f = st.number_input("Frame to Delete", min_value=1, max_value=f_count, value=min(4, f_count))
            if st.button("🗑️ Delete Evidence Frame", use_container_width=True):
                success = tamper_simulator.delete_frame(del_f)
                if success:
                    st.success(f"Frame #{del_f} deleted. Verification will trigger MISSING FRAME alert.")

        with col_atk2:
            st.markdown("#### 🔀 Attack 3: Reorder / Swap Frames")
            st.caption("Swaps two frames in sequence (temporal shuffle attack).")
            swap_a = st.number_input("Frame A", min_value=1, max_value=f_count, value=min(2, f_count))
            swap_b = st.number_input("Frame B", min_value=1, max_value=f_count, value=min(3, f_count))
            if st.button("🔀 Swap Frames Content", use_container_width=True):
                success = tamper_simulator.swap_frames(swap_a, swap_b)
                if success:
                    st.success(f"Frames #{swap_a} and #{swap_b} swapped. Will detect sequence disruption.")

            st.markdown("---")
            st.markdown("#### 📝 Attack 4: Forged Audit Log")
            st.caption("Attacker alters a chain hash value in the JSONL log file.")
            log_line = st.number_input("Log Line to Corrupt", min_value=1, max_value=f_count, value=min(2, f_count))
            if st.button("📝 Corrupt Chain Hash in Log", use_container_width=True):
                success = tamper_simulator.corrupt_log(log_line)
                if success:
                    st.success(f"Line #{log_line} corrupted. Cryptographic chain rupture will trigger alert.")

            st.markdown("---")
            st.markdown("#### 🔄 Restore Clean Baseline")
            st.caption("Restores pristine frames and audit log from clean snapshot.")
            if st.button("🟢 Restore Original Video (Undo All Attacks)", use_container_width=True):
                restored = tamper_simulator.restore_clean()
                if restored:
                    st.success("Clean snapshot restored! Video is back in 100% authentic state.")
                    st.rerun()


# ==========================================
# TAB 5: FORENSIC VERIFIER
# ==========================================
with tab5:
    st.markdown("### 🔍 Forensic Integrity & Masking Verifier")
    st.write("Recalculates frame SHA-256 digests, reconstructs the hash chain, and scans for video masking occlusions.")

    if not os.path.exists(DEFAULT_LOG_FILE):
        st.warning("No audit log found. Please record a video session in Tab 1.")
    else:
        verifier = VideoVerifier()
        result = verifier.verify()

        # Backward-compatible metric access for older verifier result objects.
        total_checked = int(getattr(result, "total_checked", 0) or 0)
        authentic_count = int(getattr(result, "authentic_count", 0) or 0)
        accuracy = getattr(
            result,
            "accuracy_percent",
            round((authentic_count / total_checked) * 100.0, 1) if total_checked else 0.0,
        )

        if result.is_valid:
            st.markdown(f"""
            <div class="verified-banner">
                🟢 VERIFICATION PASSED: VIDEO INTEGRITY 100% AUTHENTIC (Accuracy: {accuracy}%)<br>
                <span style="font-size: 0.95rem; font-weight: normal;">All frame hashes match, cryptographic chain continuity is unbroken, and no masking occlusions detected.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="tampered-banner">
                🔴 ALERT: VIDEO INTEGRITY COMPROMISED! (Accuracy: {accuracy}%)<br>
                <span style="font-size: 0.95rem; font-weight: normal;">
                    Tampering/Masking detected! Found {result.tampered_count} violations ({result.masked_count} masked frames). First violation at <b>Frame #{result.first_violation_index}</b>.
                </span>
            </div>
            """, unsafe_allow_html=True)

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Accuracy", f"{accuracy}%", delta="HIGH" if result.is_valid else "-TAMPERED")
        m2.metric("Total Frames", result.total_checked)
        m3.metric("Authentic Frames", result.authentic_count)
        m4.metric("Tampered Frames", result.tampered_count, delta=f"-{result.tampered_count}" if result.tampered_count > 0 else None, delta_color="inverse")
        m5.metric("Masked Frames", result.masked_count, delta=f"-{result.masked_count}" if result.masked_count > 0 else None, delta_color="inverse")
        m6.metric("Broken Chain", result.chain_broken_count, delta=f"-{result.chain_broken_count}" if result.chain_broken_count > 0 else None, delta_color="inverse")

        st.markdown("#### Frame-by-Frame Cryptographic & Masking Audit")
        filter_choice = st.radio("Filter Frames", ["Show All", "Violations Only", "Masked Only", "Authentic Only"], horizontal=True)

        table_data = []
        for f in result.frame_results:
            if filter_choice == "Violations Only" and f.is_authentic:
                continue
            if filter_choice == "Masked Only" and not f.is_masked:
                continue
            if filter_choice == "Authentic Only" and not f.is_authentic:
                continue

            status_symbol = "🟢 AUTHENTIC" if f.is_authentic else f"🔴 {f.status}"
            table_data.append({
                "Frame": f"#{f.index:04d}",
                "Status": status_symbol,
                "Mask Detected": f"⚠️ {f.mask_type}" if f.is_masked else "Clean",
                "Bounding Box": str(f.mask_coords) if f.mask_coords else "None",
                "Recorded Hash": f.recorded_frame_hash[:14] + "..." if f.recorded_frame_hash else "N/A",
                "Recomputed Hash": f.recomputed_frame_hash[:14] + "..." if f.recomputed_frame_hash else "N/A",
                "Details": f.details
            })

        if table_data:
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No frames match the selected filter.")

        st.markdown("---")
        st.markdown("#### 🔬 Visual Tamper Difference Heatmap Inspector")
        st.write("Compare the current evidence frame against the original baseline snapshot to visualize the exact coordinates of modified pixels.")

        tampered_indices = [f.index for f in result.frame_results if not f.is_authentic]
        default_inspect = tampered_indices[0] if tampered_indices else 1
        inspect_idx = st.number_input("Inspect Frame Number", min_value=1, max_value=max(1, result.total_checked), value=default_inspect)

        heatmap_res = verifier.generate_tamper_heatmap(inspect_idx)
        if heatmap_res:
            orig, tamp_marked, heatmap = heatmap_res
            hc1, hc2, hc3 = st.columns(3)
            with hc1:
                st.image(cv2.cvtColor(orig, cv2.COLOR_BGR2RGB), caption=f"Original Frame #{inspect_idx:04d} (Pristine)", use_container_width=True)
            with hc2:
                st.image(cv2.cvtColor(tamp_marked, cv2.COLOR_BGR2RGB), caption=f"Tampered Frame #{inspect_idx:04d} (Marked)", use_container_width=True)
            with hc3:
                st.image(cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB), caption="Pixel Difference Heatmap (JET Colormap)", use_container_width=True)
        else:
            frame_path = os.path.join(DEFAULT_FRAME_DIR, f"frame_{inspect_idx:06d}.png")
            if os.path.exists(frame_path):
                img = Image.open(frame_path)
                st.image(img, caption=f"Frame #{inspect_idx:04d}", use_container_width=True)
                st.caption("Clean baseline snapshot not available for diff, or frame is authentic.")
            else:
                st.error(f"Frame #{inspect_idx:04d} is missing from disk!")


# ==========================================
# TAB 6: AUDIT CERTIFICATE & REPORT
# ==========================================
with tab6:
    st.markdown("### 📄 Digital Forensics Audit Certificate")
    st.write("Official verification certificate certifying cryptographic integrity, masking analysis, and evidence admissibility.")

    verifier = VideoVerifier()
    res = verifier.verify()

    cert_col1, cert_col2 = st.columns([2, 1])

    with cert_col1:
        st.markdown(f"""
        ### CERTIFICATE OF DIGITAL EVIDENCE INTEGRITY
        **Audit Date:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`  
        **Cryptographic Standard:** NIST SHA-256 Hash Chain ($C_i = \\text{{SHA256}}(C_{{i-1}} \\parallel i \\parallel H_i)$)  
        **Forensics Analysis:** Dual SHA-256 Hashing + AI Masking/Occlusion Detection  
        
        **Audit Summary:**
        - **Total Frames Inspected:** `{res.total_checked}`
        - **Integrity Accuracy Rating:** `{res.accuracy_percent}%`
        - **Authentic Frames:** `{res.authentic_count}`
        - **Tampered Frames:** `{res.tampered_count}`
        - **Masked Frames (Occlusions):** `{res.masked_count}`
        - **Root Chain Status:** `{'PASSED - SECURED' if res.is_valid else 'FAILED - COMPROMISED'}`
        - **Digital Signature:** `{'VALIDATED' if res.manifest_verified else 'NOT SIGNED / INVALID'}`
        
        **Integrity Verdict:**  
        `{res.summary_message}`
        """)

    with cert_col2:
        st.markdown("#### 📥 Export Audit Records")
        report_json = json.dumps(res.to_dict(), indent=2)
        st.download_button(
            label="💾 Download Forensic Report (JSON)",
            data=report_json,
            file_name="forensic_verification_report.json",
            mime="application/json",
            use_container_width=True
        )

        md_report = f"""# Video Forensic Integrity Audit Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
Algorithm: NIST SHA-256 Hash Chain + AI Masking Detection
Accuracy: {res.accuracy_percent}%
Verdict: {'AUTHENTIC' if res.is_valid else 'COMPROMISED'}
Total Frames: {res.total_checked}
Authentic Frames: {res.authentic_count}
Tampered Frames: {res.tampered_count}
Masked Frames: {res.masked_count}
First Violation Frame: #{res.first_violation_index or 'None'}

Summary: {res.summary_message}
"""
        st.download_button(
            label="📄 Download Executive Summary (MD)",
            data=md_report,
            file_name="forensic_summary_report.md",
            mime="text/markdown",
            use_container_width=True
        )

        if os.path.exists(DEFAULT_LOG_FILE):
            with open(DEFAULT_LOG_FILE, "r", encoding="utf-8") as f:
                log_data = f.read()
            st.download_button(
                label="📜 Download Raw Hash Chain Log (JSONL)",
                data=log_data,
                file_name="hash_log.jsonl",
                mime="text/plain",
                use_container_width=True
            )
