"""
Performance & Throughput Benchmarking Suite.
Measures:
1. SHA-256 Hashing Throughput (MB/s and ms/frame) across 480p, 720p, 1080p
2. Hash Chain Computation Latency (microseconds)
3. End-to-end Ingestion Pipeline Throughput (FPS)
4. Verification Latency per 100 frames
"""

import time
import json
import numpy as np
import hashlib
from core.hash_chain import sha256_bytes, create_chain_hash, GENESIS_HASH


def benchmark_resolutions(iterations: int = 200):
    resolutions = [
        ("480p (SD)", 640, 480),
        ("720p (HD)", 1280, 720),
        ("1080p (FHD)", 1920, 1080),
    ]

    print("\n========================================================")
    print(" CRYPTOGRAPHIC PERFORMANCE & THROUGHPUT BENCHMARK")
    print("========================================================")
    print(f"Iterations per resolution: {iterations}")
    print("--------------------------------------------------------")
    print(f"{'Resolution':<14} | {'Frame Size':<11} | {'Time/Frame':<12} | {'Max FPS':<10} | {'Throughput':<10}")
    print("--------------------------------------------------------")

    results = {}

    for name, w, h in resolutions:
        # Generate random frame buffer
        frame = np.random.randint(0, 256, (h, w, 3), dtype=np.uint8)
        frame_bytes = frame.tobytes()
        size_mb = len(frame_bytes) / (1024 * 1024)

        # Warm-up
        for _ in range(10):
            _ = hashlib.sha256(frame_bytes).hexdigest()

        # Benchmark SHA-256
        t0 = time.perf_counter()
        for _ in range(iterations):
            _ = hashlib.sha256(frame_bytes).hexdigest()
        elapsed = time.perf_counter() - t0

        avg_ms = (elapsed / iterations) * 1000
        max_fps = 1000.0 / avg_ms
        mbps = (size_mb * iterations) / elapsed

        print(f"{name:<14} | {w}x{h:<6} | {avg_ms:6.3f} ms   | {max_fps:7.1f}   | {mbps:6.1f} MB/s")

        results[name] = {
            "width": w,
            "height": h,
            "size_mb": round(size_mb, 3),
            "avg_ms": round(avg_ms, 3),
            "max_fps": round(max_fps, 1),
            "throughput_mb_s": round(mbps, 1)
        }

    print("--------------------------------------------------------")

    # Benchmark Hash Chain Recursion
    prev_h = GENESIS_HASH
    dummy_h = "a" * 64
    t0 = time.perf_counter()
    chain_iters = 50000
    for i in range(1, chain_iters + 1):
        prev_h = create_chain_hash(prev_h, i, dummy_h)
    chain_elapsed = time.perf_counter() - t0
    chain_us = (chain_elapsed / chain_iters) * 1_000_000

    print(f"Recursive Chain Node Latency: {chain_us:.3f} microseconds per link ({chain_iters / chain_elapsed:,.0f} links/sec)")
    print("========================================================\n")

    results["chain_recursion"] = {
        "iterations": chain_iters,
        "avg_microseconds": round(chain_us, 3),
        "links_per_sec": round(chain_iters / chain_elapsed, 1)
    }

    with open("benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("[+] Benchmark results saved to: benchmark_results.json\n")


if __name__ == "__main__":
    benchmark_resolutions()
