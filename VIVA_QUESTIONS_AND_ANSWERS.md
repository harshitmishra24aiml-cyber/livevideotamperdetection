# 🎓 College Project Viva / Defense: Questions & Answers Guide

### Project: Real-Time Video Integrity Verification Using SHA-256 Cryptographic Hash Chains

---

### Q1: What is the core problem this project solves?
**Answer:**
Digital video files can be easily manipulated (editing faces, removing frames, or altering timestamps) using basic video editing tools or AI deepfake generators without leaving obvious visual clues. Traditional file-level checksums (like hashing an entire MP4 file) only tell you if the whole file changed, but cannot detect *where* the change happened, cannot protect live streaming feeds, and cannot differentiate between a dropped network packet and deliberate evidence tampering. 
Our project solves this by computing a SHA-256 hash for **every individual frame** and linking these hashes recursively into an **immutable cryptographic hash chain** ($C_i = \text{SHA256}(C_{i-1} \mathbin{\Vert} i \mathbin{\Vert} H_i)$). This provides frame-level granularity, detects missing/reordered frames, and pinpoints the exact millisecond tampering occurred.

---

### Q2: Why did you choose SHA-256 over MD5, SHA-1, or SHA-3?
**Answer:**
1. **MD5 and SHA-1 are cryptographically broken**: Practical collision attacks exist (e.g. Google's SHAttered attack on SHA-1 in 2017, and MD5 collisions generated in seconds). An attacker could forge an alternate video frame with the exact same hash.
2. **SHA-256 is the global gold standard**: Part of the NIST Secure Hash Standard (FIPS 180-4), offering 128-bit collision resistance and 256-bit preimage resistance. No practical collision has ever been found.
3. **Hardware Acceleration**: Most modern x86 and ARM CPUs have dedicated SHA-NI hardware instructions, allowing SHA-256 to hash raw frames in less than 1 millisecond, ensuring zero frame drops even on 60 FPS streams.
4. **SHA-3**: While SHA-3 is also secure, SHA-256 has vastly superior hardware instruction support in consumer CCTV systems and edge devices.

---

### Q3: Why do we need a "Hash Chain" instead of just hashing each frame independently?
**Answer:**
If you only store independent hashes ($H_1, H_2, H_3, \dots$):
1. **Frame Deletion Vulnerability**: An attacker can delete Frame 2 and remove $H_2$ from the log. The remaining frames $H_1, H_3$ will still match!
2. **Frame Reordering / Replay Vulnerability**: An attacker can swap the positions of Frame 2 and Frame 3. Since individual hashes don't encode temporal dependency, they would appear valid.
3. **Frame Insertion**: An attacker could inject duplicated frames.

By using a **hash chain**:
$$C_i = \text{SHA256}(C_{i-1} \mathbin{\Vert} i \mathbin{\Vert} H_i)$$
Each block $C_i$ mathematically incorporates the **entire history** of all preceding frames ($C_0 \dots C_{i-1}$) and the **sequence index ($i$)**. If Frame 2 is deleted or modified, $C_2$ changes, which immediately causes $C_3, C_4, \dots, C_N$ to fail verification.

---

### Q4: Why are frames stored losslessly as PNG instead of compressed MP4 or JPEG?
**Answer:**
Cryptographic hash functions are deterministic down to the individual bit. Standard video codecs (H.264, HEVC, JPEG) use **lossy compression** based on Discrete Cosine Transform (DCT) and motion vectors. When a lossy frame is saved and re-read from disk, subtle quantization noise alters pixel values by $\pm 1$ or $\pm 2$ LSBs. 
Because of the **avalanche effect** in SHA-256, changing even 1 bit in a pixel changes 50% of the output hash! Lossy compression would cause constant false-positive alarms. Saving frames losslessly (PNG or uncompressed raw frames) ensures bit-exact pixel reproducibility.

---

### Q5: What prevents an attacker from modifying a frame AND recomputing the entire hash chain from scratch?
**Answer:**
This is known as the **Chain Re-synthesis Attack**. We defend against this using two industry-standard techniques:
1. **Asymmetric RSA / HMAC Session Root Signature**:
   At the end of a recording session (or periodically every $K$ seconds), the terminal chain hash $C_N$ is cryptographically signed using an authority private key:
   $$S = \text{Sign}_{K_{\text{private}}}(C_N)$$
   An attacker who alters the frames can recompute a valid-looking hash chain, but they cannot forge the digital signature without the private key.
2. **External Remote Anchoring**:
   In a production deployment, the current chain hash $C_i$ is periodically transmitted over TLS to a remote immutable log server or a decentralized blockchain ledger (e.g. Ethereum smart contract).

---

### Q6: What is the computational time and space complexity?
**Answer:**
- **Time Complexity for Recording:** $O(N)$ for $N$ frames. Each frame takes $\approx 0.8\text{ ms}$ for SHA-256 and $\approx 0.02\text{ ms}$ for chain calculation. Total processing time per frame is $< 1\text{ ms}$, effortlessly sustaining 30 FPS ($33.3\text{ ms}$ budget) and 60 FPS ($16.6\text{ ms}$ budget).
- **Time Complexity for Verification:** $O(N)$. 100 frames are verified in under 0.25 seconds.
- **Space Complexity for Audit Log:** $O(N)$ with tiny storage footprint: each JSONL log record is $\approx 220\text{ bytes}$. A 1-hour 30 FPS video generates $\approx 23\text{ MB}$ of cryptographic audit data.

---

### Q7: How does your system visually locate where tampering occurred?
**Answer:**
Our system implements a **Pixel Difference Heatmap Inspector** (`generate_tamper_heatmap`):
1. It computes the absolute pixel difference between the pristine snapshot and the tampered evidence frame:
   $$D(x, y) = |F_{\text{clean}}(x, y) - F_{\text{tampered}}(x, y)|$$
2. It applies a binary threshold and contour detection to extract the bounding box coordinates $(x, y, w, h)$ of the altered area.
3. It normalizes $D(x, y)$ and applies an OpenCV `COLORMAP_JET` heatmap. This renders a visual heatmap showing red-hot zones where pixels were modified, blur-edited, or watermarked.

---

### Q8: What real-world applications benefit from this system?
**Answer:**
1. **Courtroom Digital Forensics**: Providing verifiable chain of custody for CCTV evidence in criminal trials.
2. **Police Body-Worn Cameras**: Ensuring footage cannot be selectively deleted or cut by unauthorized personnel.
3. **Financial Vault Surveillance**: High-security monitoring where missing seconds could conceal a heist.
4. **Autonomous Vehicles**: Securing dashcam and black-box video recordings against post-accident alteration.
5. **Anti-Deepfake Journalistic Verification**: Certifying that news agency video streams were recorded directly from a verified camera lens.

---

### Q9: How can this system be integrated with Blockchain?
**Answer:**
In our architecture, the hash chain produces a compact 32-byte digest $C_N$ that represents the cryptographic root of the entire video. Rather than storing gigabytes of heavy video files on a slow, expensive blockchain, we only need to write the 32-byte hash $C_N$ into a smart contract transaction once per session (or once per minute). Anyone in the world can then verify the local video files against the public blockchain transaction without trusting any single server.
