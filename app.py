"""
Live Video Tamper Detection System - Streamlit Monitoring Dashboard
Interactive forensics interface for real-time SHA-256 hash chaining, attack simulation,
visual chain exploration, and pixel-level tamper detection heatmaps.
"""

import os
import cv2
import json
import time
import shutil
import pandas as pd
import numpy as np
from PIL import Image
import streamlit as st

from core.hash_chain import GENESIS_HASH, sha256_bytes, sha256_str, compute_frame_hash, create_chain_hash
from core.video_engine import VideoStreamSource, SyntheticCCTVGenerator, add_cryptographic_hud
from core.audit_logger import AuditLogger, DEFAULT_BASE_DIR, DEFAULT_FRAME_DIR, DEFAULT_LOG_FILE
from core.verifier_engine import VideoVerifier, VerificationResult
import tamper_simulator

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="Live Video Tamper Detection System",
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
    st.markdown("**Live Video Tamper Detection System**")
    st.caption("Cryptographic Hash Chain • SHA-256")
    st.markdown("---")

    st.subheader("System Status")
    f_count, log_ok, manifest_ok = get_evidence_stats()
    st.metric("Recorded Frames", f_count)
    st.markdown(f"**Audit Log:** {'🟢 Active' if log_ok else '⚪ None'}")
    st.markdown(f"**Session Manifest:** {'🟢 Signed' if manifest_ok else '⚪ None'}")

    st.markdown("---")
    st.subheader("Algorithm Spec")
    st.latex(r"H_i = \text{SHA256}(F_i)")
    st.latex(r"C_0 = \text{GENESIS}")
    st.latex(r"C_i = \text{SHA256}(C_{i-1} \parallel i \parallel H_i)")

    st.markdown("---")
    st.caption("Developed for High-Assurance Video Surveillance Integrity")


# Title Header
st.markdown('<div class="main-title">🛡️ Live Video Tamper Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Real-Time Cryptographic Hash Chain Verification & Pixel-Level Forensic Analysis</div>', unsafe_allow_html=True)

# Main Navigation Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📹 Video Capture Studio",
    "🔗 Hash Chain Explorer",
    "⚡ Tamper Attack Lab",
    "🔍 Forensic Verifier",
    "📄 Audit Certificate & Report"
])


# ==========================================
# TAB 1: VIDEO CAPTURE STUDIO
# ==========================================
with tab1:
    st.markdown("### 📹 Video Recording & Hash Chain Generation")
    st.write("Capture frames from a camera stream, compute SHA-256 frame digests, and link each frame into an immutable cryptographic hash chain.")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("#### Stream Configuration")
        source_type = st.selectbox(
            "Video Source",
            ["Synthetic CCTV (Recommended for Demo)", "Physical Webcam", "Upload Video File"]
        )

        device_index = 0
        video_path = None

        if source_type == "Physical Webcam":
            device_index = st.number_input("Webcam Device Index", min_value=0, max_value=5, value=0)
        elif source_type == "Upload Video File":
            uploaded_file = st.file_uploader("Upload video file (MP4, AVI)", type=["mp4", "avi", "mov"])
            if uploaded_file is not None:
                video_path = os.path.join(DEFAULT_BASE_DIR, "uploaded_source.mp4")
                with open(video_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

        target_frames = st.slider("Number of Frames to Record", min_value=5, max_value=60, value=15, step=5)

        st.markdown("---")
        start_record_btn = st.button("🔴 Start Live Recording Session", use_container_width=True, type="primary")

    with col2:
        preview_container = st.empty()
        status_container = st.empty()

        if start_record_btn:
            mode_map = {
                "Synthetic CCTV (Recommended for Demo)": "synthetic",
                "Physical Webcam": "webcam",
                "Upload Video File": "file"
            }
            chosen_mode = mode_map[source_type]

            try:
                stream = VideoStreamSource(
                    mode=chosen_mode,
                    device_index=device_index,
                    file_path=video_path
                )
            except Exception as ex:
                st.error(f"Failed to open video source: {ex}")
                stream = None

            if stream and stream.is_opened:
                logger = AuditLogger()
                logger.open_session(reset=True)

                previous_hash = GENESIS_HASH
                progress_bar = st.progress(0)

                for i in range(1, target_frames + 1):
                    ret, frame = stream.read()
                    if not ret or frame is None:
                        st.warning("Video stream ended early.")
                        break

                    f_hash = compute_frame_hash(frame)
                    c_hash = create_chain_hash(previous_hash, i, f_hash)

                    logger.log_frame(i, f_hash, c_hash, frame=frame)
                    previous_hash = c_hash

                    # Render preview with cryptographic HUD
                    hud_img = add_cryptographic_hud(
                        frame=frame,
                        frame_index=i,
                        frame_hash=f_hash,
                        chain_hash=c_hash,
                        status="CHAIN SECURED",
                        is_valid=True
                    )
                    # Convert BGR to RGB for Streamlit
                    hud_rgb = cv2.cvtColor(hud_img, cv2.COLOR_BGR2RGB)
                    preview_container.image(hud_rgb, channels="RGB", use_container_width=True)

                    status_container.markdown(f"""
                    **Frame #{i:04d}** | SHA-256: `{f_hash[:16]}...` | Chain: `{c_hash[:16]}...`
                    """)
                    progress_bar.progress(i / target_frames)
                    time.sleep(0.04)

                stream.release()
                manifest = logger.close_session()
                st.success(f"✅ Recording Session Complete! Captured {target_frames} frames. Final Chain: `{manifest['final_chain_hash'][:16]}...`")
                st.rerun()
            elif stream is not None:
                st.error("Camera could not be opened. Try 'Synthetic CCTV' mode for full instant demonstration.")
        else:
            # Show latest saved frame or placeholder
            latest_frame_path = os.path.join(DEFAULT_FRAME_DIR, f"frame_{f_count:06d}.png")
            if os.path.exists(latest_frame_path):
                img = Image.open(latest_frame_path)
                preview_container.image(img, caption=f"Last Recorded Frame (#{f_count})", use_container_width=True)
            else:
                preview_container.info("Click 'Start Live Recording Session' to capture video frames and build the SHA-256 hash chain.")


# ==========================================
# TAB 2: HASH CHAIN EXPLORER
# ==========================================
with tab2:
    st.markdown("### 🔗 Cryptographic Hash Chain Explorer")
    st.write("Inspect how every video frame is immutably linked to its predecessor. Any modification to an earlier frame invalidates all subsequent chain hashes.")

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

            # Timeline view
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
# TAB 3: TAMPER ATTACK LAB
# ==========================================
with tab3:
    st.markdown("### ⚡ Tamper Attack Simulation Lab")
    st.write("Demonstrate the vulnerability of unhashed video and the detection power of SHA-256 hash chains by simulating real-world attacks.")

    f_count, log_ok, _ = get_evidence_stats()
    if f_count == 0 or not log_ok:
        st.warning("Please record a video session in Tab 1 first before launching attacks.")
    else:
        st.info("💡 You can launch an attack below and immediately switch to **Tab 4 (Forensic Verifier)** to watch the system catch the tampering!")

        col_atk1, col_atk2 = st.columns(2)

        with col_atk1:
            st.markdown("#### 🎯 Attack 1: Modify Frame Content")
            st.caption("Edits pixel data in a video frame (e.g. tampering evidence, altering faces/objects).")
            target_f = st.number_input("Target Frame Number", min_value=1, max_value=f_count, value=min(3, f_count))
            atk_style = st.selectbox("Modification Type", ["watermark", "single_pixel", "blur"],
                                     format_func=lambda x: {
                                         "watermark": "Prominent Red Box & Stamp (Obvious Tamper)",
                                         "single_pixel": "Single Pixel Modification (Steganographic / Invisible)",
                                         "blur": "Gaussian Blur Object Area (Evidence Redaction)"
                                     }[x])

            if st.button("🚀 Execute Frame Modification Attack", type="primary", use_container_width=True):
                success = tamper_simulator.modify_frame(target_f, atk_style)
                if success:
                    st.success(f"Frame #{target_f} successfully tampered with '{atk_style}'. Head over to Tab 4 to run verification!")

            st.markdown("---")
            st.markdown("#### 🗑️ Attack 2: Drop / Delete Frame")
            st.caption("Deletes a frame from the storage to hide specific moments.")
            del_f = st.number_input("Frame to Delete", min_value=1, max_value=f_count, value=min(4, f_count))
            if st.button("🗑️ Delete Evidence Frame", use_container_width=True):
                success = tamper_simulator.delete_frame(del_f)
                if success:
                    st.success(f"Frame #{del_f} deleted. Verification will trigger MISSING FRAME alert.")

        with col_atk2:
            st.markdown("#### 🔀 Attack 3: Reorder / Swap Frames")
            st.caption("Swaps the positions of two frames in sequence (temporal shuffle attack).")
            swap_a = st.number_input("Frame A", min_value=1, max_value=f_count, value=min(2, f_count))
            swap_b = st.number_input("Frame B", min_value=1, max_value=f_count, value=min(3, f_count))
            if st.button("🔀 Swap Frames Content", use_container_width=True):
                success = tamper_simulator.swap_frames(swap_a, swap_b)
                if success:
                    st.success(f"Frames #{swap_a} and #{swap_b} swapped. Verification will detect hash/sequence disruption.")

            st.markdown("---")
            st.markdown("#### 📝 Attack 4: Forged Audit Log")
            st.caption("Attacker directly alters a chain hash value in the JSONL log file.")
            log_line = st.number_input("Log Line to Corrupt", min_value=1, max_value=f_count, value=min(2, f_count))
            if st.button("📝 Corrupt Chain Hash in Log", use_container_width=True):
                success = tamper_simulator.corrupt_log(log_line)
                if success:
                    st.success(f"Line #{log_line} corrupted. Cryptographic chain rupture will trigger alert.")

            st.markdown("---")
            st.markdown("#### 🔄 Restore Clean Baseline")
            st.caption("Restores the authentic recorded video and pristine audit log from snapshot.")
            if st.button("🟢 Restore Original Video (Undo All Attacks)", use_container_width=True):
                restored = tamper_simulator.restore_clean()
                if restored:
                    st.success("Clean snapshot restored! Video is back in 100% authentic state.")
                    st.rerun()


# ==========================================
# TAB 4: FORENSIC VERIFIER
# ==========================================
with tab4:
    st.markdown("### 🔍 Forensic Integrity Verifier & Heatmap Inspector")
    st.write("Recalculates frame SHA-256 hashes and reconstructs the hash chain from ground truth. Detects pixel edits, missing frames, and log tampering.")

    if not os.path.exists(DEFAULT_LOG_FILE):
        st.warning("No audit log found. Please record a video session in Tab 1.")
    else:
        verifier = VideoVerifier()
        result = verifier.verify()

        # Big Visual Verdict Banner
        if result.is_valid:
            st.markdown("""
            <div class="verified-banner">
                🟢 VERIFICATION PASSED: VIDEO INTEGRITY 100% AUTHENTIC<br>
                <span style="font-size: 0.95rem; font-weight: normal;">All frame hashes match and cryptographic chain continuity is unbroken.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="tampered-banner">
                🔴 ALERT: VIDEO INTEGRITY COMPROMISED!<br>
                <span style="font-size: 0.95rem; font-weight: normal;">
                    Tampering detected! First violation found at <b>Frame #{result.first_violation_index}</b>.
                </span>
            </div>
            """, unsafe_allow_html=True)

        # KPI Metrics
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Frames", result.total_checked)
        m2.metric("Authentic Frames", result.authentic_count, delta=None if result.is_valid else "OK")
        m3.metric("Tampered Frames", result.tampered_count, delta=f"-{result.tampered_count}" if result.tampered_count > 0 else None, delta_color="inverse")
        m4.metric("Missing Frames", result.missing_count, delta=f"-{result.missing_count}" if result.missing_count > 0 else None, delta_color="inverse")
        m5.metric("Broken Chain Links", result.chain_broken_count, delta=f"-{result.chain_broken_count}" if result.chain_broken_count > 0 else None, delta_color="inverse")

        # Frame Audit Table
        st.markdown("#### Frame-by-Frame Cryptographic Audit Log")
        filter_choice = st.radio("Filter Frames", ["Show All", "Violations Only", "Authentic Only"], horizontal=True)

        table_data = []
        for f in result.frame_results:
            if filter_choice == "Violations Only" and f.is_authentic:
                continue
            if filter_choice == "Authentic Only" and not f.is_authentic:
                continue

            status_symbol = "🟢 AUTHENTIC" if f.is_authentic else f"🔴 {f.status}"
            table_data.append({
                "Frame": f"#{f.index:04d}",
                "Status": status_symbol,
                "Filename": f.filename,
                "Recorded Hash": f.recorded_frame_hash[:16] + "..." if f.recorded_frame_hash else "N/A",
                "Recomputed Hash": f.recomputed_frame_hash[:16] + "..." if f.recomputed_frame_hash else "N/A",
                "Chain Status": "Valid Link" if (f.recomputed_chain_hash == f.recorded_chain_hash and f.recorded_previous_hash == f.expected_previous_hash) else "Broken Link",
                "Details": f.details
            })

        if table_data:
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No frames match the selected filter.")

        # Pixel Heatmap Difference Inspector
        st.markdown("---")
        st.markdown("#### 🔬 Pixel Tamper Heatmap Inspector")
        st.write("Compare the current evidence frame against the original baseline snapshot to visualize the exact coordinates and intensity of the tampering.")

        # Find frames that failed
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
                st.image(cv2.cvtColor(tamp_marked, cv2.COLOR_BGR2RGB), caption=f"Tampered Frame #{inspect_idx:04d} (Detected Region)", use_container_width=True)
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
# TAB 5: AUDIT CERTIFICATE & REPORT
# ==========================================
with tab5:
    st.markdown("### 📄 Digital Forensics Audit Certificate")
    st.write("Official report on video integrity, cryptographic proofs, and admissibility analysis.")

    verifier = VideoVerifier()
    res = verifier.verify()

    cert_col1, cert_col2 = st.columns([2, 1])

    with cert_col1:
        st.markdown(f"""
        ### CERTIFICATE OF DIGITAL EVIDENCE INTEGRITY
        **Audit Date:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`  
        **Cryptographic Standard:** SHA-256 Hash Chain ($C_i = \\text{{SHA256}}(C_{{i-1}} \\parallel i \\parallel H_i)$)  
        **Storage Architecture:** Lossless PNG Frames + Append-Only JSONL Log  
        
        **Audit Summary:**
        - **Total Frames Inspected:** `{res.total_checked}`
        - **Authentic Frames:** `{res.authentic_count}`
        - **Tampered Frames:** `{res.tampered_count}`
        - **Missing Frames:** `{res.missing_count}`
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

        # Markdown report download
        md_report = f"""# Video Forensic Integrity Audit Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
Algorithm: SHA-256 Hash Chain
Result: {'AUTHENTIC' if res.is_valid else 'TAMPERED / COMPROMISED'}
Total Frames: {res.total_checked}
Authentic Frames: {res.authentic_count}
Tampered Frames: {res.tampered_count}
Missing Frames: {res.missing_count}
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
